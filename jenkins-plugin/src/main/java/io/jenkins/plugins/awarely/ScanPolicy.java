package io.jenkins.plugins.awarely;

import java.util.Set;

/** Validated job options. Values never become shell fragments. */
final class ScanPolicy {
    static final Set<String> COLLECTORS =
            Set.of("linux", "npm", "npm-syft", "python", "python-syft", "java", "other", "import", "existing");
    static final Set<String> MODES = Set.of("local", "check", "sync");
    static final Set<String> GATES = Set.of("REPORT_ONLY", "CRITICAL", "HIGH", "MEDIUM", "LOW");

    private ScanPolicy() {}

    static String choice(String value, Set<String> values, String field) {
        if (value == null || !values.contains(value)) throw new IllegalArgumentException("Unsupported " + field);
        return value;
    }

    static String relativePath(String input) {
        if (input == null
                || input.isBlank()
                || input.length() > 2048
                || input.startsWith("/")
                || input.contains("\\")) {
            throw new IllegalArgumentException("Use a path relative to the build workspace");
        }
        for (String part : input.split("/", -1)) {
            if (part.equals("..") || part.isEmpty())
                throw new IllegalArgumentException("Parent traversal and empty path segments are not allowed");
        }
        if (input.codePoints().anyMatch(c -> Character.isISOControl(c) || Character.getType(c) == Character.FORMAT)) {
            throw new IllegalArgumentException("Path contains unsupported characters");
        }
        return input;
    }

    static String label(String value) {
        if (value == null
                || value.isBlank()
                || value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 120
                || value.codePoints()
                        .anyMatch(c -> Character.isISOControl(c) || Character.getType(c) == Character.FORMAT)) {
            throw new IllegalArgumentException(
                    "Application label must be 1–120 UTF-8 bytes without control characters");
        }
        return value;
    }

    static int severity(String severity) {
        return switch (severity) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }
}
