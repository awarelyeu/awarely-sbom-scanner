package io.jenkins.plugins.awarely;

import hudson.remoting.VirtualChannel;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import jenkins.MasterToSlaveFileCallable;

/** All paths are resolved on the selected agent, never on the controller. */
final class AgentFiles {
    private AgentFiles() {}

    static void privateDirectory(Path p) throws IOException {
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS))
            Files.createDirectory(
                    p, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        int uid = (int) Files.getAttribute(Path.of("/proc/self"), "unix:uid");
        if (uid == 0
                || Files.isSymbolicLink(p)
                || !Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)
                || (int) Files.getAttribute(p, "unix:uid") != uid
                || !Files.getPosixFilePermissions(p).equals(PosixFilePermissions.fromString("rwx------")))
            throw new IOException("Awarely requires an owned private tool directory on a non-root Linux agent");
    }

    static byte[] read(Path path, int limit) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || (int) Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) != 1
                || Files.size(path) > limit) throw new IOException("Expected a bounded regular result file");
        try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] result = in.readNBytes(limit + 1);
            if (result.length > limit) throw new IOException("Result exceeds size limit");
            return result;
        }
    }

    static final class Session implements Serializable {
        private static final long serialVersionUID = 1L;
        final String work, home, input;

        Session(String work, String home, String input) {
            this.work = work;
            this.home = home;
            this.input = input;
        }
    }

    static final class Prepare extends MasterToSlaveFileCallable<Session> {
        private static final long serialVersionUID = 1L;
        private final String agentRoot, path, collector;

        Prepare(String agentRoot, String path, String collector) {
            this.agentRoot = agentRoot;
            this.path = path;
            this.collector = collector;
        }

        @Override
        public Session invoke(File workspace, VirtualChannel channel) throws IOException {
            if (!System.getProperty("os.name").equals("Linux")) throw new IOException("Awarely requires a Linux agent");
            Path root = Path.of(agentRoot).toRealPath();
            Path cache = root.resolve(".awarely-scan");
            privateDirectory(cache);
            Path ws = workspace.toPath().toRealPath();
            if (ws.startsWith(cache) || cache.startsWith(ws))
                throw new IOException("Workspace and tool directories must be separate");
            Path input = ws.resolve(ScanPolicy.relativePath(path)).toRealPath();
            if (!input.startsWith(ws)) throw new IOException("Selected input escapes the build workspace");
            if (!"linux".equals(collector)) {
                boolean isFile = collector.equals("existing") || collector.equals("import");
                if (isFile
                        ? !Files.isRegularFile(input, LinkOption.NOFOLLOW_LINKS)
                        : !Files.isDirectory(input, LinkOption.NOFOLLOW_LINKS))
                    throw new IOException(
                            isFile
                                    ? "Choose an existing inventory file in the workspace"
                                    : "Choose an existing application directory in the workspace");
                if (isFile && Files.isSymbolicLink(ws.resolve(path)))
                    throw new IOException("Inventory input must not be a symbolic link");
            }
            Path work = Files.createTempDirectory(
                    cache, "run-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            return new Session(work.toString(), cache.toString(), input.toString());
        }
    }

    static final class Read extends MasterToSlaveFileCallable<byte[]> {
        private static final long serialVersionUID = 1L;

        @Override
        public byte[] invoke(File file, VirtualChannel channel) throws IOException {
            return read(file.toPath(), BoundedJson.LIMIT);
        }
    }

    static final class CopyInventory extends MasterToSlaveFileCallable<Void> {
        private static final long serialVersionUID = 1L;
        private final String destination;

        CopyInventory(String destination) {
            this.destination = destination;
        }

        @Override
        public Void invoke(File file, VirtualChannel channel) throws IOException {
            byte[] bytes = read(file.toPath(), 2 * 1024 * 1024);
            Path p = Path.of(destination);
            try (var out = Files.newOutputStream(
                    p, java.nio.file.StandardOpenOption.CREATE_NEW, java.nio.file.StandardOpenOption.WRITE)) {
                Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
                out.write(bytes);
            }
            return null;
        }
    }
}
