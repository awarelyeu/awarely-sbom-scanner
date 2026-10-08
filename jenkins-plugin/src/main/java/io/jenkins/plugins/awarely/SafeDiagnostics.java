package io.jenkins.plugins.awarely;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/** Recognizes fixed CLI failure lines without retaining or exposing arbitrary child output. */
final class SafeDiagnostics extends OutputStream {
    private static final Map<String, String> MESSAGES = Map.of(
            "Remote operation failed: API returned HTTP 429 (RATE_LIMITED)",
            "Monitor rate limit reached. Stagger checks for this account and retry later; no successful assessment is reported.",
            "Remote operation failed: API returned HTTP 409 (INVENTORY_CONFLICT)",
            "The source changed during synchronization. Review its current inventory before starting a new build.",
            "Remote operation failed: API returned HTTP 409 (IDEMPOTENCY_CONFLICT)",
            "Monitor rejected a conflicting synchronization request. Inspect the source before retrying.",
            "Remote operation failed: API returned HTTP 503 (DISTRIBUTION_CATALOG_INVALID)",
            "The distribution catalog is temporarily unavailable or invalid. Retry the check later; no successful assessment is reported.");
    private final byte[] line = new byte[512];
    private int length;
    private boolean overflow;
    private String message;

    @Override
    public synchronized void write(int b) {
        if (b == '\n') {
            if (!overflow) {
                String known = MESSAGES.get(new String(line, 0, length, StandardCharsets.UTF_8));
                if (known != null) message = known;
            }
            Arrays.fill(line, (byte) 0);
            length = 0;
            overflow = false;
        } else if (length < line.length) line[length++] = (byte) b;
        else overflow = true;
    }

    synchronized String message() {
        return message;
    }

    @Override
    public synchronized void close() {
        Arrays.fill(line, (byte) 0);
        length = 0;
    }
}
