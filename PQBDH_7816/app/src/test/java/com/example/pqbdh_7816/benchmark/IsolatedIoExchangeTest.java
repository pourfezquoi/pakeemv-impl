package com.example.pqbdh_7816.benchmark;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;

/** Exercises actual thread handoff; these tests do not assert performance. */
public class IsolatedIoExchangeTest {
    @Test(timeout = 5000)
    public void connectSendAndCloseCallbacksShareOneWorkerOutsideTheCaller() throws Exception {
        long caller = Thread.currentThread().getId();
        AtomicInteger sends = new AtomicInteger();
        AtomicReference<Long> sendThread = new AtomicReference<>();
        byte[] command = {1, 2, 3};
        byte[] response = {4, 5};
        try (IsolatedIoExchange io = new IsolatedIoExchange(request -> {
            assertSame(command, request);
            sends.incrementAndGet();
            sendThread.set(Thread.currentThread().getId());
            return response;
        })) {
            assertTrue(io.isCpuIsolated());
            assertEquals(-1, io.ioThreadId());
            long connectThread = io.call(() -> Thread.currentThread().getId());
            assertNotEquals(caller, connectThread);
            assertEquals(connectThread, io.ioThreadId());
            assertSame(response, io.send(command));
            assertSame(response, io.send(command));
            long closeThread = io.call(() -> Thread.currentThread().getId());
            assertEquals(connectThread, closeThread);
            assertEquals(connectThread, sendThread.get().longValue());
            assertEquals(2, sends.get());
        }
    }

    @Test(timeout = 5000)
    public void concurrentCallersCannotRunReaderOperationsInParallel() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch secondCalling = new CountDownLatch(1);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximum = new AtomicInteger();
        ExecutorService callers = Executors.newFixedThreadPool(2);
        try (IsolatedIoExchange io = new IsolatedIoExchange(command -> command)) {
            Future<Integer> first = callers.submit(() -> io.call(() -> {
                maximum.accumulateAndGet(active.incrementAndGet(), Math::max);
                entered.countDown();
                try {
                    assertTrue(release.await(2, TimeUnit.SECONDS));
                    return 1;
                } finally {
                    active.decrementAndGet();
                }
            }));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            Future<Integer> second = callers.submit(() -> {
                secondCalling.countDown();
                return io.call(() -> {
                    maximum.accumulateAndGet(active.incrementAndGet(), Math::max);
                    try {
                        return 2;
                    } finally {
                        active.decrementAndGet();
                    }
                });
            });
            assertTrue(secondCalling.await(2, TimeUnit.SECONDS));
            release.countDown();
            assertEquals(1, first.get(2, TimeUnit.SECONDS).intValue());
            assertEquals(2, second.get(2, TimeUnit.SECONDS).intValue());
            assertEquals(1, maximum.get());
        } finally {
            release.countDown();
            callers.shutdownNow();
        }
    }

    @Test(timeout = 5000)
    public void preservesCheckedFailuresAndErrorsWithoutRetryingTheOperation() throws Exception {
        IOException failure = new IOException("reader disconnected");
        AssertionError error = new AssertionError("native bridge error");
        AtomicInteger sends = new AtomicInteger();
        try (IsolatedIoExchange io = new IsolatedIoExchange(command -> {
            sends.incrementAndGet();
            throw failure;
        })) {
            assertSame(failure, assertThrows(IOException.class, () -> io.send(new byte[]{1})));
            assertEquals(1, sends.get());
            assertSame(error, assertThrows(AssertionError.class,
                    () -> io.call(() -> { throw error; })));
            assertEquals(7, io.call(() -> 7).intValue());
        }
    }

    @Test(timeout = 5000)
    public void rejectsRecursiveDispatchBeforeItCanDeadlock() throws Exception {
        try (IsolatedIoExchange io = new IsolatedIoExchange(command -> command)) {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> io.call(() -> io.call(() -> 1)));
            assertTrue(failure.getMessage().contains("Recursive"));
            assertEquals(2, io.call(() -> 2).intValue());
        }
    }

    @Test(timeout = 5000)
    public void closeIsIdempotentAndPreventsFurtherReaderCommands() {
        AtomicInteger sends = new AtomicInteger();
        IsolatedIoExchange io = new IsolatedIoExchange(command -> {
            sends.incrementAndGet();
            return command;
        });
        io.close();
        io.close();
        assertThrows(IllegalStateException.class, () -> io.send(new byte[]{1}));
        assertThrows(IllegalStateException.class, () -> io.call(() -> 1));
        assertEquals(0, sends.get());
        assertThrows(IllegalArgumentException.class, () -> new IsolatedIoExchange(null));
    }

    @Test(timeout = 5000)
    public void interruptedWaitCancelsWorkAndPreservesTheCallersInterruptFlag() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch workerInterrupted = new CountDownLatch(1);
        AtomicBoolean callerInterrupted = new AtomicBoolean();
        AtomicReference<Throwable> callerFailure = new AtomicReference<>();
        try (IsolatedIoExchange io = new IsolatedIoExchange(command -> command)) {
            Thread caller = new Thread(() -> {
                try {
                    io.call(() -> {
                        entered.countDown();
                        try {
                            new CountDownLatch(1).await();
                        } catch (InterruptedException interrupted) {
                            workerInterrupted.countDown();
                            throw interrupted;
                        }
                        return null;
                    });
                    callerFailure.set(new AssertionError("Interrupted operation unexpectedly succeeded"));
                } catch (InterruptedException expected) {
                    callerInterrupted.set(Thread.currentThread().isInterrupted());
                } catch (Throwable unexpected) {
                    callerFailure.set(unexpected);
                }
            }, "interrupted-protocol-caller");
            caller.start();
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            caller.interrupt();
            caller.join(2000);
            assertFalse(caller.isAlive());
            assertEquals(null, callerFailure.get());
            assertTrue(callerInterrupted.get());
            assertTrue(workerInterrupted.await(2, TimeUnit.SECONDS));
        }
    }

    @Test(timeout = 5000)
    public void alreadyInterruptedCallerDoesNotSubmitAReaderOperation() throws Exception {
        AtomicInteger sends = new AtomicInteger();
        try (IsolatedIoExchange io = new IsolatedIoExchange(command -> {
            sends.incrementAndGet();
            return command;
        })) {
            Thread.currentThread().interrupt();
            try {
                assertThrows(InterruptedException.class, () -> io.send(new byte[]{1}));
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                Thread.interrupted();
            }
            assertEquals(0, sends.get());
        }
    }

    @Test(timeout = 5000)
    public void interruptedCloseReleasesTheCallerEvenWhenTheDriverIgnoresInterrupts() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch releaseDriver = new CountDownLatch(1);
        CountDownLatch driverFinished = new CountDownLatch(1);
        AtomicReference<Throwable> callerFailure = new AtomicReference<>();
        IsolatedIoExchange io = new IsolatedIoExchange(command -> command);
        Thread caller = new Thread(() -> {
            try {
                io.call(() -> {
                    entered.countDown();
                    try {
                        while (releaseDriver.getCount() != 0) {
                            try {
                                releaseDriver.await();
                            } catch (InterruptedException ignored) {
                                // Model a native reader call which ignores interruption.
                            }
                        }
                    } finally {
                        driverFinished.countDown();
                    }
                    return null;
                });
                callerFailure.set(new AssertionError("Cancelled operation unexpectedly succeeded"));
            } catch (Throwable failure) {
                callerFailure.set(failure);
            }
        }, "driver-waiting-protocol-caller");
        try {
            caller.start();
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            Thread.currentThread().interrupt();
            io.close();
            assertTrue(Thread.currentThread().isInterrupted());
            Thread.interrupted();
            caller.join(2000);
            assertFalse(caller.isAlive());
            assertTrue(callerFailure.get() instanceof IllegalStateException);
            assertThrows(IllegalStateException.class, () -> io.send(new byte[]{1}));
        } finally {
            Thread.interrupted();
            releaseDriver.countDown();
            io.close();
            caller.join(2000);
        }
        assertTrue(driverFinished.await(2, TimeUnit.SECONDS));
    }

    @Test(timeout = 5000)
    public void closingFromTheWorkerIsRejectedWithoutStoppingFutureCalls() throws Exception {
        try (IsolatedIoExchange io = new IsolatedIoExchange(command -> command)) {
            assertThrows(IllegalStateException.class, () -> io.call(() -> {
                io.close();
                return null;
            }));
            assertEquals(3, io.call(() -> 3).intValue());
        }
    }
}
