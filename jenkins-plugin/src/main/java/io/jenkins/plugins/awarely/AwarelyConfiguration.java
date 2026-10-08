package io.jenkins.plugins.awarely;

import hudson.Extension;
import hudson.model.Job;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest2;

/** Authority is configured by administrators, never by an untrusted Jenkinsfile. */
@Extension
public final class AwarelyConfiguration extends GlobalConfiguration {
    private boolean allowToolDownloads;
    private String remoteJobs = "";
    private String hostScanJobs = "";
    private String syncJobs = "";
    private String trustedAgents = "";
    private String apiOrigins = "";

    public AwarelyConfiguration() {
        load();
    }

    public static AwarelyConfiguration get() {
        return GlobalConfiguration.all().get(AwarelyConfiguration.class);
    }

    public boolean isAllowToolDownloads() {
        return allowToolDownloads;
    }

    public String getRemoteJobs() {
        return remoteJobs;
    }

    public String getSyncJobs() {
        return syncJobs;
    }

    @DataBoundSetter
    public void setSyncJobs(String value) {
        syncJobs = names(value);
    }

    public String getHostScanJobs() {
        return hostScanJobs;
    }

    public String getTrustedAgents() {
        return trustedAgents;
    }

    public String getApiOrigins() {
        return apiOrigins;
    }

    @DataBoundSetter
    public void setApiOrigins(String value) {
        apiOrigins = names(value);
    }

    @DataBoundSetter
    public void setAllowToolDownloads(boolean value) {
        allowToolDownloads = value;
    }

    @DataBoundSetter
    public void setRemoteJobs(String value) {
        remoteJobs = names(value);
    }

    @DataBoundSetter
    public void setHostScanJobs(String value) {
        hostScanJobs = names(value);
    }

    @DataBoundSetter
    public void setTrustedAgents(String value) {
        trustedAgents = names(value);
    }

    @Override
    public boolean configure(StaplerRequest2 req, JSONObject json) throws FormException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        req.bindJSON(this, json);
        save();
        return true;
    }

    boolean permitsRemote(Job<?, ?> job) {
        return entries(remoteJobs).contains(job.getFullName());
    }

    boolean permitsSync(Job<?, ?> job) {
        return entries(syncJobs).contains(job.getFullName());
    }

    boolean permitsHost(Job<?, ?> job) {
        return entries(hostScanJobs).contains(job.getFullName());
    }

    boolean permitsOrigin(String origin) {
        return entries(apiOrigins).contains(origin);
    }

    boolean permitsAgent(String node) {
        return entries(trustedAgents).contains(node);
    }

    private static String names(String value) {
        if (value == null) return "";
        if (value.length() > 32000 || value.indexOf('\0') >= 0)
            throw new IllegalArgumentException("Allowlist is too large or invalid");
        return value;
    }

    private static Set<String> entries(String value) {
        if (value == null) return Set.of();
        return Arrays.stream(value.split("\\R"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }
}
