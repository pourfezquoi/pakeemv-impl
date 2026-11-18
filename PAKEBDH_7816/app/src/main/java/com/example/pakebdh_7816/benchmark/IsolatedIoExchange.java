package com.example.pakebdh_7816.benchmark;

import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Serialize reader operations on a dedicated thread, outside the protocol
 * thread's CPU clock. Waiting/submission CPU on the caller remains measured.
 * This class never retries a reader command or manufactures timing values.
 */
public final class IsolatedIoExchange implements ProtocolMeasurements.Exchange, AutoCloseable {
    private final ProtocolMeasurements.Exchange delegate;
    private final Object lifecycleLock = new Object();
    private final Set<Future<?>> pending = ConcurrentHashMap.newKeySet();
    private final ExecutorService worker;
    private volatile Thread ioThread;
    private boolean closed;

    public IsolatedIoExchange(ProtocolMeasurements.Exchange delegate) {
        if (delegate == null) throw new IllegalArgumentException("An I/O exchange is required.");
        this.delegate = delegate;
        worker = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "benchmark-ccid-io");
            thread.setDaemon(true);
            ioThread = thread;
            return thread;
        });
    }

    @Override public boolean isCpuIsolated() { return true; }

    /** Java thread ID, not a Linux TID; -1 until the worker has been started. */
    @Override public long ioThreadId() {
        Thread thread = ioThread;
        return thread == null ? -1 : thread.getId();
    }

    @Override public byte[] send(byte[] command) throws Exception {
        return call(() -> delegate.send(command));
    }

    /** Also use this for reader connect/close outside measured protocol phases. */
    public <T> T call(Callable<T> operation) throws Exception {
        if (operation == null) throw new IllegalArgumentException("An I/O operation is required.");
        if (Thread.currentThread() == ioThread) {
            throw new IllegalStateException("Recursive I/O dispatch would deadlock the reader worker.");
        }
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("Interrupted before reader I/O dispatch.");
        }
        Future<T> task;
        synchronized (lifecycleLock) {
            if (closed) throw new IllegalStateException("Reader I/O worker is closed.");
            task = worker.submit(operation);
            pending.add(task);
        }
        try {
            return task.get();
        } catch (InterruptedException interrupted) {
            task.cancel(true);
            Thread.currentThread().interrupt();
            throw interrupted;
        } catch (CancellationException cancelled) {
            throw new IllegalStateException("Reader I/O operation was cancelled.", cancelled);
        } catch (ExecutionException failed) {
            Throwable cause = failed.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new IllegalStateException("Reader I/O failed.", cause);
        } finally {
            pending.remove(task);
        }
    }

    /**
     * Allow submitted work up to one second to finish, then cancel outstanding
     * waits. Native USB operations may ignore interruption; the daemon thread
     * prevents an uninterruptible driver from keeping the process alive.
     */
    @Override public void close() {
        if (Thread.currentThread() == ioThread) {
            throw new IllegalStateException("Close the reader I/O worker from its caller thread.");
        }
        synchronized (lifecycleLock) {
            if (closed) return;
            closed = true;
            worker.shutdown();
        }
        try {
            if (!worker.awaitTermination(1, TimeUnit.SECONDS)) cancelPending();
        } catch (InterruptedException interrupted) {
            cancelPending();
            Thread.currentThread().interrupt();
        }
    }

    private void cancelPending() {
        for (Future<?> task : pending) task.cancel(true);
        for (Runnable queued : worker.shutdownNow()) {
            if (queued instanceof Future<?>) ((Future<?>) queued).cancel(false);
        }
    }
}
