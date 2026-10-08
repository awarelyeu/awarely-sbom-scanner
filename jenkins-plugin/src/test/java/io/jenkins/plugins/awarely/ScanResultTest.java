package io.jenkins.plugins.awarely;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ScanResultTest {
    static String report(String precision, String severity, String coverage, String unevaluated) {
        return """
        {"schemaVersion":1,"status":"complete",
         "coverage":{"inventoryCoverage":"%s","componentsSubmitted":1,"from":"2025-01-01T00:00:00Z","to":"2026-01-01T00:00:00Z","unevaluated":%s},
         "components":[{"ecosystem":"npm","name":"demo","version":"1.0.0"}],
         "matches":[{"cveId":"CVE-2026-12345","severity":"%s","components":[{"componentIndex":0,"precision":"%s"}]}],
         "summary":{"matchedCves":1,"componentMatches":1}}
        """.formatted(coverage, unevaluated, severity, precision);
    }

    private ScanResult parse(String report, String gate) throws IOException {
        return ScanResult.check("demo", "npm", "awarely/test", report.getBytes(StandardCharsets.UTF_8), gate);
    }

    @Test
    void gateRequiresVersionPrecisionAndConfiguredSeverity() throws Exception {
        assertTrue(parse(report("version", "HIGH", "complete", "[]"), "HIGH").isGateExceeded());
        assertFalse(
                parse(report("product", "CRITICAL", "complete", "[]"), "LOW").isGateExceeded());
        assertFalse(parse(report("version", "MEDIUM", "complete", "[]"), "HIGH").isGateExceeded());
        assertFalse(parse(report("version", "CRITICAL", "complete", "[]"), "REPORT_ONLY")
                .isGateExceeded());
    }

    @Test
    void incompleteAssessmentRemainsDistinctFromFindings() throws Exception {
        var partial = parse(report("version", "LOW", "partial", "[]"), "HIGH");
        assertTrue(partial.isIncomplete());
        assertFalse(partial.isGateExceeded());
        var unsupported = parse(
                report("version", "LOW", "complete", "[{\"componentIndex\":0,\"reason\":\"ECOSYSTEM_NOT_EVALUATED\"}]"),
                "HIGH");
        assertEquals(1, unsupported.getUnevaluated());
        assertTrue(unsupported.isIncomplete());
    }

    @Test
    void rejectAmbiguousAndInconsistentReports() {
        String valid = report("version", "HIGH", "complete", "[]");
        for (String bad : new String[] {
            valid.replace("\"componentIndex\":0", "\"componentIndex\":1"),
            valid.replace("\"componentMatches\":1", "\"componentMatches\":0"),
            valid.replace("\"status\":\"complete\"", "\"status\":\"complete\",\"status\":\"failed\""),
            valid.replace("version\"}", "guessed\"}"),
            valid + "{}",
            valid.replace("CVE-2026-12345", "javascript:alert(1)")
        }) assertThrows(IOException.class, () -> parse(bad, "HIGH"));
    }

    @Test
    void parserBoundsAndMissingCoverageFailClosed() throws Exception {
        assertThrows(IOException.class, () -> BoundedJson.read(new byte[BoundedJson.LIMIT + 1]));
        assertThrows(
                IOException.class,
                () -> BoundedJson.read(
                        ("{\"n\":" + "[".repeat(40) + "0" + "]".repeat(40) + "}").getBytes(StandardCharsets.UTF_8)));
        byte[] sbom = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[]}"
                .getBytes(StandardCharsets.UTF_8);
        assertTrue(ScanResult.local("demo", "existing", "local", "awarely/test", sbom, false)
                .isIncomplete());
    }
}
