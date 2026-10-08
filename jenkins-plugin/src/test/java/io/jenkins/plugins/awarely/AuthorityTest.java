package io.jenkins.plugins.awarely;

import static org.junit.jupiter.api.Assertions.*;

import hudson.model.Item;
import hudson.model.User;
import hudson.security.ACL;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.access.AccessDeniedException;

@WithJenkins
class AuthorityTest {
    @Test
    void reportSettingsAndCredentialEnumerationRespectPermissions(JenkinsRule j) throws Exception {
        var project = j.createFreeStyleProject("private-app");
        var run = j.buildAndAssertSuccess(project);
        var action = new AwarelyBuildAction();
        run.addAction(action);
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.READ)
                .everywhere()
                .to("viewer")
                .grant(Item.READ)
                .onItems(project)
                .to("reader")
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin"));
        var descriptor = j.jenkins.getDescriptorByType(AwarelyScanBuilder.DescriptorImpl.class);
        try (var ignored = ACL.as(User.getById("viewer", true))) {
            assertThrows(AccessDeniedException.class, action::getTarget);
            assertThrows(
                    AccessDeniedException.class,
                    () -> AwarelyConfiguration.get()
                            .configure((org.kohsuke.stapler.StaplerRequest2) null, new net.sf.json.JSONObject()));
            assertTrue(descriptor.doFillCredentialsIdItems(project).isEmpty());
        }
        try (var ignored = ACL.as(User.getById("reader", true))) {
            assertSame(action, action.getTarget());
            assertTrue(descriptor.doFillCredentialsIdItems(project).isEmpty());
        }
    }

    @Test
    void allowlistsAreExactAndWritePermissionIsSeparate(JenkinsRule j) throws Exception {
        var allowed = j.createFreeStyleProject("approved");
        var other = j.createFreeStyleProject("approved-extra");
        var cfg = AwarelyConfiguration.get();
        assertFalse(cfg.permitsRemote(allowed));
        cfg.setRemoteJobs("approved");
        cfg.setApiOrigins("https://monitor.example.invalid");
        cfg.setTrustedAgents("agent");
        assertTrue(cfg.permitsRemote(allowed));
        assertFalse(cfg.permitsRemote(other));
        assertFalse(cfg.permitsSync(allowed));
        assertFalse(cfg.permitsHost(allowed));
        assertFalse(cfg.permitsAgent("agent-other"));
        assertFalse(cfg.permitsOrigin("https://monitor.example.invalid.attacker.invalid"));
    }
}
