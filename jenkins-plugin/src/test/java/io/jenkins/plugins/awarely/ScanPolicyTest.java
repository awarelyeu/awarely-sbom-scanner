package io.jenkins.plugins.awarely;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class ScanPolicyTest {
    @Test
    void rejectsEscapingPaths() {
        for (String path :
                new String[] {"", "/etc", "../app", "app/../../etc", "app//nested", "app\\other", "app\nsecret"}) {
            assertThrows(IllegalArgumentException.class, () -> ScanPolicy.relativePath(path), path);
        }
        assertEquals(".", ScanPolicy.relativePath("."));
        assertEquals("services/shipping app", ScanPolicy.relativePath("services/shipping app"));
    }

    @Test
    void labelsCannotInjectLogControlSequences() {
        assertThrows(IllegalArgumentException.class, () -> ScanPolicy.label("name\u001b[2J"));
        assertThrows(IllegalArgumentException.class, () -> ScanPolicy.label("é".repeat(61)));
        assertEquals("Shipping", ScanPolicy.label("Shipping"));
    }

    @Test
    void unknownPoliciesAreRejected() {
        assertThrows(
                IllegalArgumentException.class, () -> ScanPolicy.choice("execute", ScanPolicy.COLLECTORS, "collector"));
        assertThrows(IllegalArgumentException.class, () -> ScanPolicy.choice("UPLOAD", ScanPolicy.MODES, "mode"));
        assertEquals(0, ScanPolicy.severity("UNKNOWN"));
    }
}
