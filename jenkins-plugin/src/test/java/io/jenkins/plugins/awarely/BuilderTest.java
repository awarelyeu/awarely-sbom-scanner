package io.jenkins.plugins.awarely;

import static org.junit.jupiter.api.Assertions.*;

import hudson.model.FreeStyleProject;
import hudson.model.Result;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class BuilderTest {
    @Test
    void configurationRoundtripAndControllerRefusal(JenkinsRule j) throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        AwarelyScanBuilder step = new AwarelyScanBuilder("java");
        step.setMode("local");
        step.setPath("target/my app");
        step.setApplicationLabel("Demo Java");
        p.getBuildersList().add(step);
        j.configRoundtrip(p);
        AwarelyScanBuilder restored = p.getBuildersList().get(AwarelyScanBuilder.class);
        j.assertEqualDataBoundBeans(step, restored);
        var build = j.assertBuildStatus(Result.FAILURE, p.scheduleBuild2(0));
        j.assertLogContains("never on the Jenkins controller", build);
    }

    @Test
    void globalConfigurationRendersAndRoundtrips(JenkinsRule j) throws Exception {
        var config = AwarelyConfiguration.get();
        config.setRemoteJobs("folder/check");
        config.setSyncJobs("folder/deploy");
        config.setTrustedAgents("trusted-linux");
        config.setApiOrigins("https://api.example.invalid");
        config.save();
        var page = j.createWebClient().goTo("configure");
        assertTrue(page.asNormalizedText().contains("Allowed Monitor API origins"));
        j.submit(page.getFormByName("config"));
        assertEquals("folder/check", config.getRemoteJobs());
        assertEquals("folder/deploy", config.getSyncJobs());
        assertEquals("https://api.example.invalid", config.getApiOrigins());
    }

    @Test
    void pathsAndLabelsRemainArguments(JenkinsRule j) {
        AwarelyScanBuilder step = new AwarelyScanBuilder("npm");
        step.setApplicationLabel("demo; echo secret");
        List<String> args = step.collectionArguments("/workspace/a;touch owned", "/private/inventory.json", false);
        assertEquals(
                List.of(
                        "app",
                        "--ecosystem",
                        "npm",
                        "--path",
                        "/workspace/a;touch owned",
                        "--name",
                        "demo; echo secret",
                        "--output",
                        "/private/inventory.json",
                        "--timeout",
                        "300"),
                args);
        AwarelyScanBuilder syft = new AwarelyScanBuilder("java");
        assertFalse(
                syft.collectionArguments("/workspace", "/private/out", false).contains("--allow-download"));
        assertTrue(syft.collectionArguments("/workspace", "/private/out", true).contains("--allow-download"));
    }

    @Test
    void persistedSyncOrderingAndSingleWriter(JenkinsRule j) throws Exception {
        var a = j.createFreeStyleProject("a");
        var b = j.createFreeStyleProject("b");
        var old = j.buildAndAssertSuccess(a);
        var latest = j.buildAndAssertSuccess(a);
        var other = j.buildAndAssertSuccess(b);
        try (var lease = SyncState.acquire("synthetic-source", latest)) {
            assertNotNull(lease);
        }
        assertThrows(java.io.IOException.class, () -> SyncState.acquire("synthetic-source", old));
        assertThrows(java.io.IOException.class, () -> SyncState.acquire("synthetic-source", other));
        try (var lease = SyncState.acquire("another-source", other)) {
            assertNotNull(lease);
        }
    }

    @Test
    void reportEscapesUntrustedPackageText(JenkinsRule j) throws Exception {
        var run = j.buildAndAssertSuccess(j.createFreeStyleProject());
        String json = ScanResultTest.report("version", "HIGH", "complete", "[]")
                .replace("\"demo\"", "\"<img id='injected' src='x' onerror='alert(1)'>\"");
        var result = ScanResult.check(
                "<script id='label-injected'>alert(1)</script>",
                "npm",
                "awarely/test",
                json.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "HIGH");
        var action = new AwarelyBuildAction();
        run.addAction(action);
        action.add(result);
        run.save();
        var page = j.createWebClient().goTo(run.getUrl() + "awarely-scan/");
        assertTrue(
                page.getByXPath("//*[@id='injected' or @id='label-injected']").isEmpty());
        assertTrue(page.asNormalizedText().contains("<img id='injected'"));
    }
}
