package io.jenkins.plugins.awarely;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Proc;
import hudson.model.*;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.ListBoxModel;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;
import java.util.concurrent.TimeUnit;
import jenkins.branch.MultiBranchProject;
import jenkins.model.Jenkins;
import jenkins.scm.api.mixin.ChangeRequestSCMHead;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.FileCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/** Freestyle build step and Pipeline awarelyScan step, using the same verified CLI as interactive users. */
public final class AwarelyScanBuilder extends Builder implements SimpleBuildStep {
    private final String collector;
    private String mode = "local",
            path = ".",
            applicationLabel = "application",
            credentialsId = "",
            severityThreshold = "REPORT_ONLY";
    private boolean failOnIncomplete = true, allPackages;

    @DataBoundConstructor
    public AwarelyScanBuilder(String collector) {
        this.collector = ScanPolicy.choice(collector, ScanPolicy.COLLECTORS, "collector");
    }

    public String getCollector() {
        return collector;
    }

    public String getMode() {
        return mode;
    }

    public String getPath() {
        return path;
    }

    public String getApplicationLabel() {
        return applicationLabel;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    public String getSeverityThreshold() {
        return severityThreshold;
    }

    public boolean isFailOnIncomplete() {
        return failOnIncomplete;
    }

    public boolean isAllPackages() {
        return allPackages;
    }

    @DataBoundSetter
    public void setMode(String v) {
        mode = ScanPolicy.choice(v, ScanPolicy.MODES, "action");
    }

    @DataBoundSetter
    public void setPath(String v) {
        path = ScanPolicy.relativePath(v);
    }

    @DataBoundSetter
    public void setApplicationLabel(String v) {
        applicationLabel = ScanPolicy.label(v);
    }

    @DataBoundSetter
    public void setCredentialsId(String v) {
        if (v == null || v.length() > 256 || v.codePoints().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("Invalid credential ID");
        credentialsId = v;
    }

    @DataBoundSetter
    public void setSeverityThreshold(String v) {
        severityThreshold = ScanPolicy.choice(v, ScanPolicy.GATES, "severity threshold");
    }

    @DataBoundSetter
    public void setFailOnIncomplete(boolean v) {
        failOnIncomplete = v;
    }

    @DataBoundSetter
    public void setAllPackages(boolean v) {
        allPackages = v;
    }

    @Override
    public void perform(
            Run<?, ?> run, FilePath workspace, EnvVars environment, Launcher launcher, TaskListener listener)
            throws IOException, InterruptedException {
        validate();
        Computer computer = workspace.toComputer();
        if (computer == null || computer.getNode() == null || computer.getNode() instanceof Jenkins)
            throw new AbortException("Awarely must run on a dedicated Linux agent, never on the Jenkins controller");
        Node node = computer.getNode();
        AwarelyConfiguration config = AwarelyConfiguration.get();
        boolean privileged = !mode.equals("local") || collector.equals("linux");
        if (privileged) {
            if (isChangeRequest(run.getParent()))
                throw new AbortException(
                        "Pull-request builds may collect application SBOMs locally, but cannot use credentials or inventory the agent host");
            if (!config.permitsAgent(node.getNodeName()))
                throw new AbortException("This agent is not approved for Monitor operations or host inventory");
            if (!mode.equals("local") && !config.permitsRemote(run.getParent()))
                throw new AbortException("An administrator must approve this exact job for Monitor operations");
            if (mode.equals("sync") && !config.permitsSync(run.getParent()))
                throw new AbortException(
                        "An administrator must separately approve this exact job for inventory synchronization");
            if (collector.equals("linux") && !config.permitsHost(run.getParent()))
                throw new AbortException("An administrator must approve this exact job for agent host inventory");
        }
        FilePath nodeRoot = node.getRootPath();
        if (nodeRoot == null) throw new AbortException("Agent is disconnected");
        Properties pins = PinnedTools.manifest();
        listener.getLogger()
                .println("Awarely Scan: " + collector + " / " + mode + "; CLI " + pins.getProperty("version")
                        + " (fixed by plugin release).");
        AgentFiles.Session session = workspace.act(new AgentFiles.Prepare(nodeRoot.getRemote(), path, collector));
        FilePath work = new FilePath(workspace.getChannel(), session.work);
        String artifactPrefix = "awarely/" + UUID.randomUUID();
        try {
            String binary = work.act(new PinnedTools.Prepare(pins, session.home, config.isAllowToolDownloads()));
            FilePath inventory = work.child("inventory.cdx.json");
            int code;
            if (collector.equals("existing")) {
                new FilePath(workspace.getChannel(), session.input)
                        .act(new AgentFiles.CopyInventory(inventory.getRemote()));
                code = 0;
            } else {
                listener.getLogger()
                        .println(
                                "Collecting selected inputs locally. Project builds and dependency installation remain separate pipeline steps.");
                code = execute(
                        launcher,
                        work,
                        session.home,
                        binary,
                        collectionArguments(session.input, inventory.getRemote(), config.isAllowToolDownloads()),
                        null,
                        listener);
                if (code != 0 && code != 3) throw new AbortException(collectionError(code));
            }
            byte[] inventoryBytes = inventory.act(new AgentFiles.Read());
            ScanResult result =
                    ScanResult.local(applicationLabel, collector, "local", artifactPrefix, inventoryBytes, code == 3);
            Map<String, String> artifacts = new LinkedHashMap<>();
            artifacts.put(artifactPrefix + "/inventory.cdx.json", "inventory.cdx.json");
            // Preserve the collected inventory even when authentication or assessment subsequently fails.
            run.pickArtifactManager()
                    .archive(work, launcher, new jenkins.util.BuildListenerAdapter(listener), artifacts);
            publishResult(run, result);
            artifacts.clear();
            if (!mode.equals("local")) {
                if (mode.equals("sync") && (result.isIncomplete() || result.getComponents() == 0))
                    throw new AbortException(
                            "Synchronization requires a complete, non-empty selected-input inventory. Use local export or check instead");
                listener.getLogger()
                        .println(
                                mode.equals("check")
                                        ? "Checking the selected inventory. Saved inventory and alerts remain unchanged."
                                        : "Synchronizing only the credential's configured source.");
                try (MonitorCredential credential = MonitorCredential.load(run, credentialsId)) {
                    List<String> args = new ArrayList<>(List.of(
                            mode,
                            "--input",
                            inventory.getRemote(),
                            "--credentials",
                            "-",
                            "--output",
                            work.child(mode + "-result.json").getRemote()));
                    if (mode.equals("sync")) {
                        // New invocations have new keys. The CLI retains a fixed revision/key for every transport
                        // retry.
                        args.addAll(List.of("--idempotency-key", "jenkins-" + UUID.randomUUID()));
                        try (SyncState.Lease lease = SyncState.acquire(credential.sourceKey, run)) {
                            code = execute(launcher, work, session.home, binary, args, credential.input(), listener);
                        }
                    } else code = execute(launcher, work, session.home, binary, args, credential.input(), listener);
                }
                if (code != 0) throw new AbortException(remoteError(code));
                byte[] report = work.child(mode + "-result.json").act(new AgentFiles.Read());
                if (mode.equals("check"))
                    result = ScanResult.check(applicationLabel, collector, artifactPrefix, report, severityThreshold);
                else {
                    validateReceipt(report, result.getComponents());
                    result = ScanResult.local(
                            applicationLabel, collector, "sync", artifactPrefix, inventoryBytes, false);
                }
                artifacts.put(artifactPrefix + "/" + mode + "-result.json", mode + "-result.json");
            }
            // Exact allowlist only: never a credential, cache file or raw producer output.
            if (!artifacts.isEmpty())
                run.pickArtifactManager()
                        .archive(work, launcher, new jenkins.util.BuildListenerAdapter(listener), artifacts);
            publishResult(run, result);
            if (mode.equals("check"))
                listener.getLogger()
                        .printf(
                                "Awarely completed: %d components; %d matched CVEs; %d unevaluated. See Awarely Scan and the JSON artifacts.%n",
                                result.getComponents(), result.getMatchedCves(), result.getUnevaluated());
            else
                listener.getLogger()
                        .printf(
                                "Awarely completed: %d components; %s. No vulnerability assessment was performed.%n",
                                result.getComponents(),
                                mode.equals("sync") ? "source synchronized" : "local inventory archived");
            if (result.isGateExceeded() || (failOnIncomplete && result.isIncomplete())) {
                run.setResult(Result.UNSTABLE);
                listener.getLogger()
                        .println(
                                result.isGateExceeded()
                                        ? "Build marked UNSTABLE: version-confirmed matches reached the configured severity threshold."
                                        : "Build marked UNSTABLE: inventory or vulnerability assessment is incomplete.");
            }
        } finally {
            try {
                work.deleteRecursive();
            } catch (IOException e) {
                listener.getLogger()
                        .println(
                                "Private scanner files could not be removed. Clean or recycle the isolated agent before reuse.");
                run.setResult(Result.FAILURE);
            }
        }
    }

    private static void publishResult(Run<?, ?> run, ScanResult result) throws IOException {
        synchronized (run) {
            AwarelyBuildAction action = run.getAction(AwarelyBuildAction.class);
            if (action == null) {
                action = new AwarelyBuildAction();
                run.addAction(action);
            }
            action.add(result);
            run.save();
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    static boolean isChangeRequest(Job<?, ?> job) {
        if (job.getParent() instanceof MultiBranchProject project)
            return project.getProjectFactory().getBranch(job).getHead() instanceof ChangeRequestSCMHead;
        return false;
    }

    private void validate() throws AbortException {
        try {
            ScanPolicy.choice(collector, ScanPolicy.COLLECTORS, "collector");
            ScanPolicy.choice(mode, ScanPolicy.MODES, "action");
            ScanPolicy.relativePath(path);
            ScanPolicy.label(applicationLabel);
            ScanPolicy.choice(severityThreshold, ScanPolicy.GATES, "threshold");
        } catch (IllegalArgumentException e) {
            throw new AbortException(e.getMessage());
        }
        if (!mode.equals("local") && (credentialsId == null || credentialsId.isBlank()))
            throw new AbortException("Select a Jenkins Secret file containing your Monitor credential JSON");
        if (allPackages && !collector.equals("linux"))
            throw new AbortException("All packages applies only to Linux host inventory");
        if (!severityThreshold.equals("REPORT_ONLY") && !mode.equals("check"))
            throw new AbortException("A severity threshold requires the check action");
    }

    List<String> collectionArguments(String input, String output, boolean download) {
        List<String> args = new ArrayList<>();
        switch (collector) {
            case "linux" -> {
                args.add("host");
                if (allPackages) args.add("--all-packages");
            }
            case "npm", "python" -> args.addAll(List.of("app", "--ecosystem", collector, "--path", input));
            case "import" -> args.addAll(List.of("import", "--input", input));
            case "npm-syft", "python-syft", "java", "other" -> {
                args.addAll(List.of("syft", "--ecosystem", collector.replace("-syft", ""), "--path", input));
                if (download) args.add("--allow-download");
            }
            default -> throw new IllegalArgumentException("Unsupported collector");
        }
        args.addAll(List.of("--name", applicationLabel, "--output", output, "--timeout", "300"));
        return args;
    }

    static int execute(
            Launcher launcher,
            FilePath work,
            String home,
            String binary,
            List<String> args,
            InputStream credentials,
            TaskListener listener)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(List.of(
                "/usr/bin/env",
                "-i",
                "HOME=" + home,
                "LANG=C.UTF-8",
                "PATH=/usr/bin:/bin",
                "AWARELY_RUN_COOKIE=" + UUID.randomUUID(),
                binary));
        command.addAll(args);
        // The fixed executable handles structured input. No shell interprets paths or labels. Child output can contain
        // untrusted data and is not logged.
        try (SafeDiagnostics diagnostics = new SafeDiagnostics()) {
            Launcher.ProcStarter starter = launcher.launch()
                    // Launcher expands dollar macros even without a shell. Escape them once so paths/labels remain
                    // literal.
                    .cmds(command.stream()
                            .map(value -> value.replace("$", "$$"))
                            .toList())
                    .quiet(true)
                    .pwd(work)
                    .stdout(OutputStream.nullOutputStream())
                    .stderr(diagnostics);
            if (credentials != null) starter.stdin(credentials);
            Proc process = starter.start();
            int status;
            try {
                status = process.joinWithTimeout(360, TimeUnit.SECONDS, listener);
            } catch (IOException | InterruptedException e) {
                try {
                    process.kill();
                } catch (IOException | InterruptedException cleanup) {
                    e.addSuppressed(cleanup);
                }
                throw e;
            }
            if (status != 0 && diagnostics.message() != null)
                listener.getLogger().println(diagnostics.message());
            return status;
        }
    }

    private static String collectionError(int code) {
        return switch (code) {
            case 2 ->
                "Collection failed: review the selected directory, supported manifest/artifact types and verified-tool availability. Nothing was uploaded.";
            case 4 -> "Collection could not publish a private output. Check agent disk space and permissions.";
            case 5 -> "Collection was interrupted or exceeded its deadline. Nothing was uploaded.";
            default -> "Collection failed. No inventory was uploaded; review agent health and supported inputs.";
        };
    }

    private static String remoteError(int code) {
        return switch (code) {
            case 2 ->
                "Credential or inventory validation failed. Check credential scope/format and use a valid Awarely inventory.";
            case 4 ->
                "API operation could not save its receipt. A sync may have committed; inspect the source before retrying.";
            case 5 ->
                "API operation was interrupted or timed out. A sync may have committed; inspect the source before retrying.";
            default ->
                "Monitor operation failed. Check credential validity/scope, source revision, quotas, catalog availability and HTTPS connectivity. No successful assessment is reported.";
        };
    }

    private static void validateReceipt(byte[] bytes, int components) throws IOException {
        var n = BoundedJson.read(bytes);
        if (n.path("schemaVersion").asInt() != 1
                || !"committed".equals(n.path("status").asText())
                || BoundedJson.count(n, "sourceComponentCount", 5000) != components)
            throw new IOException("Invalid sync receipt");
    }

    @Extension
    @Symbol("awarelyScan")
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> type) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Awarely Scan: inventory, check or synchronize";
        }

        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Item item) {
            if (item == null || !item.hasPermission(Item.CONFIGURE)) return new ListBoxModel();
            return new StandardListBoxModel()
                    .includeEmptyValue()
                    .includeAs(hudson.security.ACL.SYSTEM2, item, FileCredentials.class);
        }
    }
}
