package io.jenkins.plugins.awarely;

import hudson.remoting.VirtualChannel;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Properties;
import java.util.Set;
import jenkins.MasterToSlaveFileCallable;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

/** The plugin release authenticates fixed archive and executable digests. No job controls versions or URLs. */
final class PinnedTools {
    private PinnedTools() {}

    static Properties manifest() throws IOException {
        Properties p = new Properties();
        try (InputStream in = PinnedTools.class.getResourceAsStream("/io/jenkins/plugins/awarely/tools.properties")) {
            if (in == null) throw new IOException("Missing release tool manifest");
            p.load(in);
        }
        if (!p.getProperty("version", "").matches("v[0-9]+\\.[0-9]+\\.[0-9]+(?:-alpha\\.[0-9]+)?"))
            throw new IOException("Invalid pinned tool version");
        for (String arch : ListHolder.ARCHES)
            for (String kind : new String[] {"archive", "binary"})
                if (!p.getProperty(arch + "." + kind, "").matches("[0-9a-f]{64}"))
                    throw new IOException(
                            "This development plugin has no authenticated tool pins; use a published release");
        return p;
    }

    private static final class ListHolder {
        static final String[] ARCHES = {"amd64", "arm64"};
    }

    static String digest(byte[] b) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable");
        }
    }

    static final class Prepare extends MasterToSlaveFileCallable<String> {
        private static final long serialVersionUID = 1L;
        private final Properties pins;
        private final String home;
        private final boolean download;

        Prepare(Properties pins, String home, boolean download) {
            this.pins = pins;
            this.home = home;
            this.download = download;
        }

        @Override
        public String invoke(File directory, VirtualChannel channel) throws IOException, InterruptedException {
            Path work = directory.toPath();
            AgentFiles.privateDirectory(work);
            String arch =
                    switch (System.getProperty("os.arch")) {
                        case "amd64", "x86_64" -> "amd64";
                        case "aarch64", "arm64" -> "arm64";
                        default -> throw new IOException("Unsupported agent architecture");
                    };
            String version = pins.getProperty("version"),
                    file = "awarely-scan_" + version + "_linux_" + arch + ".tar.gz";
            Path cache = Path.of(home);
            AgentFiles.privateDirectory(cache);
            Path archive = cache.resolve(file);
            if (!Files.exists(archive, LinkOption.NOFOLLOW_LINKS)) {
                if (!download)
                    throw new IOException(
                            "Pinned scanner is absent. Ask an administrator to enable verified tool downloads or prepopulate the documented cache");
                Path temp = Files.createTempFile(
                        cache,
                        "download-",
                        ".tmp",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                try {
                    download(
                            URI.create("https://github.com/awarelyeu/awarely-sbom-scanner/releases/download/" + version
                                    + "/" + file),
                            temp);
                    verify(temp, pins.getProperty(arch + ".archive"), 40 * 1024 * 1024);
                    try {
                        Files.move(temp, archive, StandardCopyOption.ATOMIC_MOVE);
                    } catch (java.nio.file.FileAlreadyExistsException concurrentDownload) {
                        verify(archive, pins.getProperty(arch + ".archive"), 40 * 1024 * 1024);
                    }
                } finally {
                    Files.deleteIfExists(temp);
                }
            }
            verify(archive, pins.getProperty(arch + ".archive"), 40 * 1024 * 1024);
            Path binary = work.resolve("awarely-scan");
            boolean found = false;
            long expanded = 0;
            int entries = 0;
            try (InputStream in = Files.newInputStream(archive, LinkOption.NOFOLLOW_LINKS);
                    GzipCompressorInputStream gz = new GzipCompressorInputStream(in);
                    TarArchiveInputStream tar = new TarArchiveInputStream(gz)) {
                TarArchiveEntry entry;
                while ((entry = tar.getNextEntry()) != null) {
                    if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
                    expanded += entry.getSize();
                    if (entry.getSize() < 0 || expanded > 100L * 1024 * 1024 || ++entries > 200)
                        throw new IOException("Release archive exceeds extraction limits");
                    if (!entry.getName().equals("awarely-scan")) continue;
                    if (found
                            || !entry.isFile()
                            || entry.isLink()
                            || entry.isSymbolicLink()
                            || entry.getSize() > 40L * 1024 * 1024)
                        throw new IOException("Invalid release executable entry");
                    found = true;
                    try (var out = Files.newOutputStream(
                            binary,
                            java.nio.file.StandardOpenOption.CREATE_NEW,
                            java.nio.file.StandardOpenOption.WRITE)) {
                        Files.setPosixFilePermissions(binary, PosixFilePermissions.fromString("rw-------"));
                        long copied = tar.transferTo(out);
                        if (copied != entry.getSize()) throw new IOException("Incomplete release executable");
                    }
                }
            }
            if (!found) throw new IOException("Release executable is missing");
            verify(binary, pins.getProperty(arch + ".binary"), 40 * 1024 * 1024);
            Files.setPosixFilePermissions(binary, PosixFilePermissions.fromString("rwx------"));
            return binary.toString();
        }
    }

    static void verify(Path file, String expected, int limit) throws IOException {
        if (expected == null
                || !expected.matches("[0-9a-f]{64}")
                || !digest(AgentFiles.read(file, limit)).equals(expected))
            throw new IOException("Pinned tool verification failed; nothing was executed");
    }

    private static void download(URI uri, Path destination) throws IOException, InterruptedException {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(180);
        for (int redirects = 0; redirects <= 5; redirects++) {
            if (!"https".equals(uri.getScheme())
                    || uri.getRawUserInfo() != null
                    || (uri.getPort() != -1 && uri.getPort() != 443)
                    || !Set.of("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
                            .contains(uri.getHost())) throw new IOException("Unapproved release redirect");
            HttpURLConnection c = (HttpURLConnection) uri.toURL().openConnection(Proxy.NO_PROXY);
            c.setInstanceFollowRedirects(false);
            c.setConnectTimeout(15000);
            c.setReadTimeout(15000);
            c.setRequestProperty("Accept", "application/octet-stream");
            try {
                int status = c.getResponseCode();
                if (status >= 300 && status < 400) {
                    String location = c.getHeaderField("Location");
                    if (location == null) throw new IOException("Missing release redirect");
                    uri = uri.resolve(location);
                    continue;
                }
                if (status != 200) throw new IOException("Pinned release download failed; check agent HTTPS access");
                if (c.getContentLengthLong() > 40L * 1024 * 1024) throw new IOException("Release archive is too large");
                try (InputStream in = c.getInputStream();
                        var out = Files.newOutputStream(destination)) {
                    byte[] buf = new byte[32768];
                    int n;
                    long count = 0;
                    while ((n = in.read(buf)) != -1) {
                        if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
                        if ((count += n) > 40L * 1024 * 1024 || System.nanoTime() > deadline)
                            throw new IOException("Release download limit exceeded");
                        out.write(buf, 0, n);
                    }
                }
                return;
            } finally {
                c.disconnect();
            }
        }
        throw new IOException("Too many release redirects");
    }
}
