package io.jenkins.plugins.awarely;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class SafeDiagnosticsTest {
    @Test
    void emitsOnlyFixedMessagesAndDiscardsLongOrInjectedOutput() throws Exception {
        try (var out = new SafeDiagnostics()) {
            out.write("token=secret\n\u001b[31mRemote operation failed: API returned HTTP 429 (RATE_LIMITED)\n"
                    .getBytes(StandardCharsets.UTF_8));
            assertNull(out.message());
            out.write(("x".repeat(100000) + "Remote operation failed: API returned HTTP 429 (RATE_LIMITED)\n")
                    .getBytes(StandardCharsets.UTF_8));
            assertNull(out.message());
            out.write(
                    "Remote operation failed: API returned HTTP 429 (RATE_LIMITED)\n".getBytes(StandardCharsets.UTF_8));
            assertTrue(out.message().startsWith("Monitor rate limit reached."));
            assertFalse(out.message().contains("secret"));
        }
    }
}
