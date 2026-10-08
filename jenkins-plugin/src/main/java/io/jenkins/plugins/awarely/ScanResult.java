package io.jenkins.plugins.awarely;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Persisted, bounded display projection. No descriptions, HTML or remote URLs are rendered. */
public final class ScanResult implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String label, collector, mode, artifactPath, coverage, period;
    private final int components, matchedCves, versionMatches, unevaluated;
    private final boolean gateExceeded;
    private final List<Finding> findings;

    private ScanResult(
            String label,
            String collector,
            String mode,
            String artifactPath,
            String coverage,
            String period,
            int components,
            int matchedCves,
            int versionMatches,
            int unevaluated,
            boolean gateExceeded,
            List<Finding> findings) {
        this.label = label;
        this.collector = collector;
        this.mode = mode;
        this.artifactPath = artifactPath;
        this.coverage = coverage;
        this.period = period;
        this.components = components;
        this.matchedCves = matchedCves;
        this.versionMatches = versionMatches;
        this.unevaluated = unevaluated;
        this.gateExceeded = gateExceeded;
        this.findings = List.copyOf(findings);
    }

    static ScanResult local(String label, String collector, String mode, String artifacts, byte[] sbom, boolean partial)
            throws IOException {
        JsonNode n = BoundedJson.read(sbom);
        if (!"CycloneDX".equals(n.path("bomFormat").asText())
                || !"1.6".equals(n.path("specVersion").asText())
                || !n.path("components").isArray()
                || n.path("components").size() > 5000) throw new IOException("Invalid normalized inventory");
        boolean complete = false;
        for (JsonNode p : n.path("metadata").path("properties")) {
            if ("awarely:coverage".equals(p.path("name").asText())) {
                if (complete
                        || !"complete-for-selected-inputs"
                                .equals(p.path("value").asText())) {
                    partial = true;
                } else complete = true;
            }
        }
        partial = partial || !complete;
        return new ScanResult(
                label,
                collector,
                mode,
                artifacts,
                partial ? "partial" : "complete",
                "Not assessed",
                n.path("components").size(),
                0,
                0,
                0,
                false,
                List.of());
    }

    static ScanResult check(String label, String collector, String artifacts, byte[] data, String gate)
            throws IOException {
        JsonNode n = BoundedJson.read(data),
                cov = n.path("coverage"),
                comps = n.path("components"),
                matches = n.path("matches");
        if (n.path("schemaVersion").asInt() != 1
                || !"complete".equals(n.path("status").asText())
                || !comps.isArray()
                || comps.size() > 5000
                || !matches.isArray()
                || matches.size() > 100000
                || !cov.path("unevaluated").isArray()) throw new IOException("Invalid check report");
        String coverage = BoundedJson.text(cov, "inventoryCoverage", 16);
        if (!Set.of("complete", "partial").contains(coverage)
                || BoundedJson.count(cov, "componentsSubmitted", 5000) != comps.size())
            throw new IOException("Inconsistent check coverage");
        String from = BoundedJson.text(cov, "from", 64), to = BoundedJson.text(cov, "to", 64);
        try {
            if (!java.time.Instant.parse(from).isBefore(java.time.Instant.parse(to)))
                throw new IllegalArgumentException();
        } catch (RuntimeException e) {
            throw new IOException("Invalid assessment period");
        }
        Set<Integer> unevaluated = new HashSet<>();
        for (JsonNode u : cov.path("unevaluated")) {
            int index = BoundedJson.count(u, "componentIndex", comps.size() - 1);
            BoundedJson.text(u, "reason", 128);
            unevaluated.add(index);
        }
        int versionMatches = 0, totalMatches = 0;
        boolean exceeded = false;
        List<Finding> preview = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (JsonNode match : matches) {
            String id = BoundedJson.text(match, "cveId", 40), severity = BoundedJson.text(match, "severity", 16);
            if (!id.matches("CVE-[0-9]{4}-[0-9]{4,}|GHSA-[A-Za-z0-9-]{14}")
                    || !ids.add(id)
                    || !Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")
                            .contains(severity)
                    || !match.path("components").isArray()
                    || match.path("components").isEmpty()) throw new IOException("Invalid finding");
            Set<Integer> indices = new HashSet<>();
            for (JsonNode hit : match.path("components")) {
                int index = BoundedJson.count(hit, "componentIndex", comps.size() - 1);
                String precision = BoundedJson.text(hit, "precision", 16);
                if (!indices.add(index) || !Set.of("version", "product").contains(precision))
                    throw new IOException("Invalid finding reference");
                totalMatches++;
                if ("version".equals(precision)) {
                    versionMatches++;
                    if (!"REPORT_ONLY".equals(gate) && ScanPolicy.severity(severity) >= ScanPolicy.severity(gate))
                        exceeded = true;
                }
                JsonNode c = comps.get(index);
                String name = BoundedJson.text(c, "name", 1024),
                        version = BoundedJson.text(c, "version", 256),
                        eco = BoundedJson.text(c, "ecosystem", 32);
                if (preview.size() < 100) preview.add(new Finding(id, severity, eco, name, version, precision));
            }
        }
        if (BoundedJson.count(n.path("summary"), "matchedCves", 100000) != matches.size()
                || BoundedJson.count(n.path("summary"), "componentMatches", 1000000) != totalMatches)
            throw new IOException("Inconsistent finding totals");
        return new ScanResult(
                label,
                collector,
                "check",
                artifacts,
                coverage,
                from + " → " + to,
                comps.size(),
                matches.size(),
                versionMatches,
                unevaluated.size(),
                exceeded,
                preview);
    }

    public String getLabel() {
        return label;
    }

    public String getCollector() {
        return collector;
    }

    public String getMode() {
        return mode;
    }

    public String getArtifactPath() {
        return artifactPath;
    }

    public String getCoverage() {
        return coverage;
    }

    public String getPeriod() {
        return period;
    }

    public int getComponents() {
        return components;
    }

    public int getMatchedCves() {
        return matchedCves;
    }

    public int getVersionMatches() {
        return versionMatches;
    }

    public int getUnevaluated() {
        return unevaluated;
    }

    public boolean isGateExceeded() {
        return gateExceeded;
    }

    public boolean isIncomplete() {
        return "partial".equals(coverage) || unevaluated > 0;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public static final class Finding implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String id, severity, ecosystem, name, version, precision;

        Finding(String id, String severity, String ecosystem, String name, String version, String precision) {
            this.id = id;
            this.severity = severity;
            this.ecosystem = ecosystem;
            this.name = name;
            this.version = version;
            this.precision = precision;
        }

        public String getId() {
            return id;
        }

        public String getSeverity() {
            return severity;
        }

        public String getEcosystem() {
            return ecosystem;
        }

        public String getName() {
            return name;
        }

        public String getVersion() {
            return version;
        }

        public String getPrecision() {
            return precision;
        }
    }
}
