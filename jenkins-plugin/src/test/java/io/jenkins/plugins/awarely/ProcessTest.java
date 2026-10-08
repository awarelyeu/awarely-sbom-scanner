package io.jenkins.plugins.awarely;

import static org.junit.jupiter.api.Assertions.*;

import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProcessTest {
    @TempDir
    Path directory;

    @Test
    void launcherDoesNotExpandDollarMacrosInPathsOrLabels() throws Exception {
        Path script = directory.resolve("copy-argument.sh"), output = directory.resolve("literal $HOME.txt");
        Files.writeString(script, "printf '%s' \"$1\" > \"$2\"\n");
        String literal = "$HOME;$(touch should-not-exist)";
        int code = AwarelyScanBuilder.execute(
                new Launcher.LocalLauncher(TaskListener.NULL),
                new FilePath(directory.toFile()),
                directory.toString(),
                "/bin/sh",
                List.of(script.toString(), literal, output.toString()),
                null,
                TaskListener.NULL);
        assertEquals(0, code);
        assertEquals(literal, Files.readString(output));
        assertFalse(Files.exists(directory.resolve("should-not-exist")));
    }

    @Test
    void cancellingTheStepKillsItsProcessBeforeCleanup() throws Exception {
        Path pid = directory.resolve("pid");
        AtomicReference<Throwable> outcome = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try {
                AwarelyScanBuilder.execute(
                        new Launcher.LocalLauncher(TaskListener.NULL),
                        new FilePath(directory.toFile()),
                        directory.toString(),
                        "/bin/sh",
                        List.of("-c", "echo $$ > \"$1\"; exec sleep 60", "test", pid.toString()),
                        null,
                        TaskListener.NULL);
            } catch (Throwable e) {
                outcome.set(e);
            }
        });
        worker.start();
        ProcessHandle process = null;
        try {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
            while ((!Files.exists(pid) || Files.size(pid) == 0) && System.nanoTime() < deadline) Thread.sleep(25);
            process = ProcessHandle.of(Long.parseLong(Files.readString(pid).trim()))
                    .orElseThrow();
            assertTrue(process.isAlive());
            worker.interrupt();
            worker.join(10000);
            assertFalse(worker.isAlive());
            assertInstanceOf(InterruptedException.class, outcome.get());
            assertFalse(process.isAlive(), "Cancellation must not leave the scanner running");
        } finally {
            worker.interrupt();
            if (process != null && process.isAlive()) process.destroyForcibly();
            worker.join(5000);
        }
    }
}
