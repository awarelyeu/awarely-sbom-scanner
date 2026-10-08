package io.jenkins.plugins.awarely;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.fasterxml.jackson.databind.JsonNode;
import hudson.AbortException;
import hudson.model.Run;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.jenkinsci.plugins.plaincredentials.FileCredentials;

/** A short-lived stdin binding. Never stored in the workspace, process arguments or environment. */
final class MonitorCredential implements AutoCloseable {
    private final byte[] data;
    final String sourceKey;

    private MonitorCredential(byte[] data, String sourceKey) {
        this.data = data;
        this.sourceKey = sourceKey;
    }

    static MonitorCredential load(Run<?, ?> run, String id) throws IOException {
        FileCredentials credential = CredentialsProvider.findCredentialById(id, FileCredentials.class, run, List.of());
        if (credential == null)
            throw new AbortException(
                    "Select an accessible Jenkins Secret file credential containing the Monitor credential JSON");
        byte[] data;
        try (InputStream in = credential.getContent()) {
            data = in.readNBytes(8193);
        }
        try {
            if (data.length > 8192) throw new AbortException("Credential exceeds size limit");
            JsonNode n = BoundedJson.read(data);
            String origin = BoundedJson.text(n, "apiUrl", 2048), token = BoundedJson.text(n, "token", 128);
            String app = BoundedJson.text(n, "applicationId", 36), source = BoundedJson.text(n, "sourceId", 36);
            URI u = URI.create(origin);
            if (n.path("schemaVersion").asInt() != 1
                    || !"https".equals(u.getScheme())
                    || u.getHost() == null
                    || u.getRawUserInfo() != null
                    || (u.getRawPath() != null && !u.getRawPath().isEmpty())
                    || u.getRawQuery() != null
                    || u.getRawFragment() != null
                    || !token.matches("awscan_[0-9a-f]{32}_[A-Za-z0-9_-]{43}")
                    || !app.matches("[0-9a-f-]{36}")
                    || !source.matches("[0-9a-f-]{36}")) throw new AbortException("Invalid Monitor credential");
            if (!AwarelyConfiguration.get().permitsOrigin(origin))
                throw new AbortException("Credential destination is not in the administrator's allowed API origins");
            return new MonitorCredential(
                    data,
                    PinnedTools.digest((("https://" + u.getHost().toLowerCase(java.util.Locale.ROOT)
                                            + (u.getPort() == -1 || u.getPort() == 443 ? "" : ":" + u.getPort()))
                                    + "\n" + app + "\n" + source)
                            .getBytes(StandardCharsets.UTF_8)));
        } catch (IllegalArgumentException | IOException e) {
            Arrays.fill(data, (byte) 0);
            throw new AbortException(
                    "Credential rejected: verify its format and the allowed API origins in Manage Jenkins");
        }
    }

    InputStream input() {
        return new java.io.ByteArrayInputStream(data);
    }

    @Override
    public void close() {
        Arrays.fill(data, (byte) 0);
    }
}
