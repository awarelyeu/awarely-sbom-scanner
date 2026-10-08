package io.jenkins.plugins.awarely;

import hudson.AbortException;
import hudson.Extension;
import hudson.model.Run;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import jenkins.model.GlobalConfiguration;

/** Serializes source writes and persists a conservative high-water mark before transmitting. */
@Extension
public final class SyncState extends GlobalConfiguration {
    private Map<String, Writer> writers = new HashMap<>();
    private static final ReentrantLock LOCK = new ReentrantLock();

    public SyncState() {
        load();
    }

    @Override
    public String getGlobalConfigPage() {
        return null; // Internal persistence only; do not insert a nonexistent form into System configuration.
    }

    static Lease acquire(String sourceKey, Run<?, ?> run) throws IOException, InterruptedException {
        if (!LOCK.tryLock(300, TimeUnit.SECONDS))
            throw new AbortException("Another inventory synchronization is still running; retry this build later");
        boolean owned = false;
        try {
            SyncState state = GlobalConfiguration.all().get(SyncState.class);
            if (state == null) throw new AbortException("Synchronization state is unavailable; no inventory was sent");
            Writer last = state.writers.get(sourceKey);
            String job = run.getParent().getFullName();
            if (last != null && (!last.job.equals(job) || last.build > run.getNumber()))
                throw new AbortException(
                        "Source is assigned to another job or a newer build. Use one trusted writer job per source");
            if (last == null && state.writers.size() >= 10000)
                throw new AbortException(
                        "Too many source bindings; ask an administrator to review synchronization configuration");
            state.writers.put(sourceKey, new Writer(job, run.getNumber()));
            state.getConfigFile().write(state);
            owned = true;
            return new Lease();
        } finally {
            if (!owned) LOCK.unlock();
        }
    }

    private static final class Writer implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String job;
        private final int build;

        Writer(String job, int build) {
            this.job = job;
            this.build = build;
        }
    }

    static final class Lease implements AutoCloseable {
        @Override
        public void close() {
            LOCK.unlock();
        }
    }
}
