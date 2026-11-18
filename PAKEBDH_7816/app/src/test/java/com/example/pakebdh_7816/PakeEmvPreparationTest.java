package com.example.pakebdh_7816;

import static org.junit.Assert.*;

import com.example.pakebdh_7816.apdu.T1Channel;
import com.example.pakebdh_7816.benchmark.BenchmarkSupport.TimerSource;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Exchange;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import org.junit.Test;

/** Compatibility and optional-query tests; dummy bytes are not cryptographic or timing results. */
public class PakeEmvPreparationTest {
    @Test
    public void unsupportedProfileNeverTriggersAnF7QueryInTheNormalApp() throws Exception {
        for (int sw : new int[]{0x6D00, 0x6A81}) {
            List<Integer> instructions = new ArrayList<>();
            List<String> status = new ArrayList<>();
            PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
                instructions.add(command[1] & 255);
                assertArrayEquals(new byte[]{(byte) 0x80, (byte) 0xF8, 0, 0, 0}, command);
                return status(sw);
            }, false, status::add);
            assertEquals(Arrays.asList(0xF8), instructions);
            assertNull(preparation.baseline);
            assertTrue(preparation.profile.contains(String.format(Locale.ROOT, "SW=%04X", sw)));
            assertTrue(preparation.cardTimingError.contains("No F7 reset/query was sent"));
            assertTrue(status.stream().anyMatch(message -> message.contains("skipping F7 timing queries")));
        }
    }

    @Test
    public void compatibleProfileWithoutTimingAlsoSkipsF7() throws Exception {
        List<Integer> instructions = new ArrayList<>();
        PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
            instructions.add(command[1] & 255);
            return profile(7);
        }, false, ignored -> { });
        assertEquals(Arrays.asList(0xF8), instructions);
        assertNull(preparation.baseline);
        assertNotNull(preparation.cardTimingError);
        assertTrue(preparation.profile.contains("C1/B2/50 advertised"));
    }

    @Test
    public void advertisedTimingResetsCountersBeforeCoreProtocol() throws Exception {
        List<Integer> instructions = new ArrayList<>();
        PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
            instructions.add(command[1] & 255);
            if ((command[1] & 255) == 0xF8) return profile(15);
            assertArrayEquals(new byte[]{(byte) 0x80, (byte) 0xF7, 0, 0, 0}, command);
            return timing(1, 0, 0, 0, 0);
        }, true, ignored -> { });
        assertEquals(Arrays.asList(0xF8, 0xF7), instructions);
        assertNotNull(preparation.baseline);
        assertEquals(105_000_000L, preparation.baseline.clockHz);
        assertEquals(0, preparation.baseline.commandCount);
        assertEquals(0, preparation.baseline.pakeCycles);
        assertEquals(0, preparation.baseline.certCycles);
        assertEquals(0, preparation.baseline.establishCycles);
        assertNull(preparation.cardTimingError);
    }

    @Test
    public void strictBenchmarkRejectsMissingTimingWithoutSendingF7OrCoreCommands() {
        for (byte[] response : new byte[][]{status(0x6D00), status(0x6A81), profile(7)}) {
            List<Integer> instructions = new ArrayList<>();
            PakeEmvSession.CardTimingUnavailableException failure = assertThrows(
                    PakeEmvSession.CardTimingUnavailableException.class,
                    () -> PakeEmvSession.prepare(command -> {
                        instructions.add(command[1] & 255);
                        return response;
                    }, true, ignored -> { }));
            assertTrue(failure.getMessage().contains("No F7 reset/query was sent"));
            assertEquals(Arrays.asList(0xF8), instructions);
        }
    }

    @Test
    public void stoppedCounterIsOptionalForTheAppButFailsTheStrictBenchmark() throws Exception {
        for (boolean strict : new boolean[]{false, true}) {
            List<Integer> instructions = new ArrayList<>();
            Exchange exchange = command -> {
                instructions.add(command[1] & 255);
                return (command[1] & 255) == 0xF8 ? profile(15) : timing(0, 0, 0, 0, 0);
            };
            if (strict) {
                assertThrows(PakeEmvSession.CardTimingUnavailableException.class,
                        () -> PakeEmvSession.prepare(exchange, true, ignored -> { }));
            } else {
                PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(exchange, false, ignored -> { });
                assertNull(preparation.baseline);
                assertTrue(preparation.cardTimingError.contains("hardware cycle counter is not ready"));
            }
            assertEquals(Arrays.asList(0xF8, 0xF7), instructions);
        }
    }

    @Test
    public void advertisedDiagnosticsExplainAValidNotReadyResetInBothRunModes() throws Exception {
        for (boolean strict : new boolean[]{false, true}) {
            List<String> requests = new ArrayList<>();
            Exchange exchange = command -> {
                requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
                if ((command[1] & 255) == 0xF8) return profile(31);
                if (command[2] == 0) return timing(0, 0, 0, 0, 0);
                assertArrayEquals(new byte[]{(byte) 0x80, (byte) 0xF7, 2, 0, 0}, command);
                return diagnostics(6, 0);
            };
            String reason;
            if (strict) {
                reason = assertThrows(PakeEmvSession.CardTimingUnavailableException.class,
                        () -> PakeEmvSession.prepare(exchange, true, ignored -> { })).getMessage();
            } else {
                List<String> log = new ArrayList<>();
                PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(exchange, false, log::add);
                assertNull(preparation.baseline);
                reason = preparation.cardTimingError;
                assertTrue(log.stream().anyMatch(line -> line.contains("counter did not advance")));
            }
            assertEquals(Arrays.asList("F8/00", "F7/00", "F7/02"), requests);
            assertTrue(reason.contains("hardware cycle counter is not ready"));
            assertTrue(reason.contains("counter did not advance"));
            assertTrue(reason.contains("DEMCR=0x00000000 -> 0x01000000"));
            assertTrue(reason.contains("DWT_CTRL=0x00000000 -> 0x00000001"));
            assertTrue(reason.contains("CYCCNT=0x00000011 -> 0x00000011"));
            assertFalse(reason.contains("Rebuild"));
        }
    }

    @Test
    public void readyTimingDoesNotQueryAdvertisedDiagnostics() throws Exception {
        for (int capabilities : new int[]{31, 63}) {
            List<String> requests = new ArrayList<>();
            PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
                requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
                return (command[1] & 255) == 0xF8 ? profile(capabilities) : timing(1, 0, 0, 0, 0);
            }, true, ignored -> { });
            assertNotNull(preparation.baseline);
            assertEquals(Arrays.asList("F8/00", "F7/00"), requests);
        }
    }

    @Test
    public void diagnosticsCapabilityAloneCannotEnableTimingCommands() throws Exception {
        for (int capabilities : new int[]{23, 39, 55}) {
            List<Integer> instructions = new ArrayList<>();
            PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
                instructions.add(command[1] & 255);
                return profile(capabilities);
            }, false, ignored -> { });
            assertNull(preparation.baseline);
            assertEquals(Arrays.asList(0xF8), instructions);
        }
    }

    @Test
    public void readySysTickRequiresMatchingAdvertisedCachedReadinessBeforeMeasurement() throws Exception {
        List<String> requests = new ArrayList<>();
        List<String> log = new ArrayList<>();
        PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
            requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
            if ((command[1] & 255) == 0xF8) return profile(63);
            if (command[2] == 0) return timing(3, 0, 0, 0, 0);
            assertArrayEquals(new byte[]{(byte) 0x80, (byte) 0xF7, 3, 0, 0}, command);
            return sysTickDiagnostics(1, 3);
        }, true, log::add);
        assertNotNull(preparation.baseline);
        assertEquals(TimerSource.SYSTICK_IRQ, preparation.baseline.timerSource);
        assertEquals(105_000_000L, preparation.baseline.clockHz);
        assertEquals(Arrays.asList("F8/00", "F7/00", "F7/03"), requests);
        assertTrue(log.stream().anyMatch(line -> line.contains("cached PES1")));
    }

    @Test
    public void olderProfilesCannotEnableOrQueryAnUnadvertisedSysTickSource() throws Exception {
        for (int capabilities : new int[]{15, 31}) {
            for (boolean strict : new boolean[]{false, true}) {
                List<String> requests = new ArrayList<>();
                Exchange exchange = command -> {
                    requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
                    return (command[1] & 255) == 0xF8 ? profile(capabilities) : timing(3, 0, 0, 0, 0);
                };
                String reason;
                if (strict) {
                    reason = assertThrows(PakeEmvSession.CardTimingUnavailableException.class,
                            () -> PakeEmvSession.prepare(exchange, true, ignored -> { })).getMessage();
                } else {
                    PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(exchange, false, ignored -> { });
                    assertNull(preparation.baseline);
                    reason = preparation.cardTimingError;
                }
                assertTrue(reason.contains("without advertising that source"));
                assertEquals(Arrays.asList("F8/00", "F7/00"), requests);
            }
        }
    }

    @Test
    public void malformedUnreadyOrDifferentClockSysTickDiagnosticsInvalidateTiming() throws Exception {
        byte[] otherClock = sysTickDiagnostics(1, 3);
        ByteBuffer.wrap(otherClock).putInt(8, 120_000_000);
        byte[] wrongMagic = sysTickDiagnostics(1, 3);
        wrongMagic[2] = 'D';
        for (byte[] diagnostic : new byte[][]{status(0x6D00), status(0x9000), wrongMagic,
                sysTickDiagnostics(6, 0), otherClock}) {
            for (boolean strict : new boolean[]{false, true}) {
                List<String> requests = new ArrayList<>();
                Exchange exchange = command -> {
                    requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
                    if ((command[1] & 255) == 0xF8) return profile(63);
                    return command[2] == 0 ? timing(3, 0, 0, 0, 0) : diagnostic;
                };
                if (strict) {
                    Exception failure = assertThrows(PakeEmvSession.CardTimingUnavailableException.class,
                            () -> PakeEmvSession.prepare(exchange, true, ignored -> { }));
                    assertTrue(failure.getMessage().contains("readiness/clock do not match"));
                } else {
                    PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(exchange, false, ignored -> { });
                    assertNull(preparation.baseline);
                    assertTrue(preparation.cardTimingError.contains("readiness/clock do not match"));
                }
                assertEquals(Arrays.asList("F8/00", "F7/00", "F7/03"), requests);
            }
        }
    }

    @Test
    public void failedFallbackExplainsBothCountersWithoutProducingValidTiming() throws Exception {
        List<String> requests = new ArrayList<>();
        PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
            requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
            if ((command[1] & 255) == 0xF8) return profile(63);
            if (command[2] == 0) return timing(0, 0, 0, 0, 0);
            return command[2] == 2 ? diagnostics(4, 0) : sysTickDiagnostics(6, 0);
        }, false, ignored -> { });
        assertNull(preparation.baseline);
        assertTrue(preparation.cardTimingError.contains("NOCYCCNT=1"));
        assertTrue(preparation.cardTimingError.contains("SysTick interrupt self-test failed"));
        assertEquals(Arrays.asList("F8/00", "F7/00", "F7/02", "F7/03"), requests);
    }

    @Test
    public void readySysTickDiagnosticCannotPromoteAnUnavailableTimingReset() throws Exception {
        List<String> requests = new ArrayList<>();
        PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
            requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
            if ((command[1] & 255) == 0xF8) return profile(47);
            return command[2] == 0 ? timing(0, 0, 0, 0, 0) : sysTickDiagnostics(1, 3);
        }, false, ignored -> { });
        assertNull(preparation.baseline);
        assertTrue(preparation.cardTimingError.contains("readiness differs from the failed timing response"));
        assertEquals(Arrays.asList("F8/00", "F7/00", "F7/03"), requests);
    }

    @Test
    public void postProtocolCounterFailureIncludesTheCachedSysTickFailureReason() throws Exception {
        PakeEmvSession.Preparation preparation = new PakeEmvSession.Preparation(
                com.example.pakebdh_7816.benchmark.BenchmarkSupport.CardTiming.parse(timing(3, 0, 0, 0, 0)),
                "SysTick profile", null, true, true);
        List<String> requests = new ArrayList<>();
        Exception failure = assertThrows(PakeEmvSession.CardTimingUnavailableException.class,
                () -> PakeEmvSession.snapshotTiming(command -> {
                    requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
                    if (command[2] == 1) return timing(0, 0, 0, 0, 0);
                    return command[2] == 2 ? diagnostics(4, 0) : sysTickDiagnostics(7, 0);
                }, preparation, ignored -> { }));
        assertTrue(failure.getMessage().contains("changed after initialization"));
        assertEquals(Arrays.asList("F7/01", "F7/02", "F7/03"), requests);
    }

    @Test
    public void sysTickReadinessTransportFailuresPropagateInBothRunModes() {
        IOException expected = new IOException("SysTick diagnostic transfer failed");
        for (boolean strict : new boolean[]{false, true}) {
            List<String> requests = new ArrayList<>();
            assertSame(expected, assertThrows(IOException.class, () -> PakeEmvSession.prepare(command -> {
                requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
                if ((command[1] & 255) == 0xF8) return profile(63);
                if (command[2] == 0) return timing(3, 0, 0, 0, 0);
                throw expected;
            }, strict, ignored -> { })));
            assertEquals(Arrays.asList("F8/00", "F7/00", "F7/03"), requests);
        }
    }

    @Test
    public void malformedOrUnsupportedResetDoesNotTriggerDiagnosticQueries() throws Exception {
        for (byte[] reset : new byte[][]{status(0x6D00), status(0x9000), timing(2, 0, 0, 0, 0)}) {
            List<String> requests = new ArrayList<>();
            PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
                requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
                return (command[1] & 255) == 0xF8 ? profile(31) : reset;
            }, false, ignored -> { });
            assertNull(preparation.baseline);
            assertEquals(Arrays.asList("F8/00", "F7/00"), requests);
            assertFalse(preparation.cardTimingError.contains("PED1"));
        }
    }

    @Test
    public void rejectedOrMalformedDiagnosticsPreserveTheUnavailableResetAndRawEvidence() throws Exception {
        byte[] wrongMagic = diagnostics(6, 0);
        wrongMagic[2] = 'B';
        for (byte[] diagnostic : new byte[][]{status(0x6D00), status(0x9000), wrongMagic}) {
            for (boolean strict : new boolean[]{false, true}) {
                Exchange exchange = command -> {
                    if ((command[1] & 255) == 0xF8) return profile(31);
                    return command[2] == 0 ? timing(0, 0, 0, 0, 0) : diagnostic;
                };
                String reason = strict
                        ? assertThrows(PakeEmvSession.CardTimingUnavailableException.class,
                        () -> PakeEmvSession.prepare(exchange, true, ignored -> { })).getMessage()
                        : PakeEmvSession.prepare(exchange, false, ignored -> { }).cardTimingError;
                assertTrue(reason.contains("hardware cycle counter is not ready"));
                assertTrue(reason.contains("Card counter diagnostics unavailable:"));
                assertTrue(reason.contains("bytes, SW="));
                assertTrue(reason.contains("prefix="));
            }
        }
    }

    @Test
    public void diagnosticTransportFailuresPropagateWithoutRetryOrSuccessfulMeasurement() {
        IOException expected = new IOException("Card diagnostic transfer failed");
        for (boolean strict : new boolean[]{false, true}) {
            List<String> requests = new ArrayList<>();
            assertSame(expected, assertThrows(IOException.class, () -> PakeEmvSession.prepare(command -> {
                requests.add(String.format(Locale.ROOT, "%02X/%02X", command[1], command[2]));
                if ((command[1] & 255) == 0xF8) return profile(31);
                if (command[2] == 0) return timing(0, 0, 0, 0, 0);
                throw expected;
            }, strict, ignored -> { })));
            assertEquals(Arrays.asList("F8/00", "F7/00", "F7/02"), requests);
        }
    }

    @Test
    public void readyDiagnosticCannotReplaceAFailedTimingReset() throws Exception {
        PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(command -> {
            if ((command[1] & 255) == 0xF8) return profile(31);
            return command[2] == 0 ? timing(0, 0, 0, 0, 0) : diagnostics(1, 1);
        }, false, ignored -> { });
        assertNull(preparation.baseline);
        assertTrue(preparation.cardTimingError.contains("Diagnostic readiness differs from the reset response"));
    }

    @Test
    public void validPacketsWithUnresetCountersCannotBecomeSuccessfulBaselines() {
        byte[][] packets = {timing(1, 1, 0, 0, 0), timing(1, 0, 1, 0, 0),
                timing(1, 0, 0, 1, 0), timing(1, 0, 0, 0, 1)};
        for (boolean strict : new boolean[]{false, true}) {
            for (byte[] packet : packets) {
                List<Integer> instructions = new ArrayList<>();
                IllegalStateException failure = assertThrows(IllegalStateException.class,
                        () -> PakeEmvSession.prepare(command -> {
                            instructions.add(command[1] & 255);
                            return (command[1] & 255) == 0xF8 ? profile(15) : packet;
                        }, strict, ignored -> { }));
                assertEquals("Card benchmark counters did not reset", failure.getMessage());
                assertEquals(Arrays.asList(0xF8, 0xF7), instructions);
            }
        }
    }

    @Test
    public void corruptedProfileCannotEnableTimingOrStartCoreProtocol() {
        byte[] corrupted = profile(15);
        corrupted[2] = 'B';
        List<Integer> instructions = new ArrayList<>();
        assertThrows(IllegalStateException.class, () -> PakeEmvSession.prepare(command -> {
            instructions.add(command[1] & 255);
            return corrupted;
        }, false, ignored -> { }));
        assertEquals(Arrays.asList(0xF8), instructions);
    }

    @Test
    public void malformedTimingResponseFailsTheStrictBenchmark() {
        List<Integer> instructions = new ArrayList<>();
        assertThrows(PakeEmvSession.CardTimingUnavailableException.class,
                () -> PakeEmvSession.prepare(command -> {
                    instructions.add(command[1] & 255);
                    return (command[1] & 255) == 0xF8 ? profile(15) : status(0x9000);
                }, true, ignored -> { }));
        assertEquals(Arrays.asList(0xF8, 0xF7), instructions);
    }

    @Test
    public void profileTransportFailuresPropagateWithoutFallbackOrRetry() {
        IOException expected = new IOException("Profile transfer failed");
        int[] calls = {0};
        List<String> status = new ArrayList<>();
        assertSame(expected, assertThrows(IOException.class, () -> PakeEmvSession.prepare(command -> {
            calls[0]++;
            throw expected;
        }, false, status::add)));
        assertEquals(1, calls[0]);
        assertTrue(status.isEmpty());
    }

    @Test
    public void advertisedTimingTransportFailuresRemainFatalInTheNormalApp() {
        IOException expected = new IOException("CCID command failed: status=0x40, error=0xFE");
        List<Integer> instructions = new ArrayList<>();
        List<String> status = new ArrayList<>();
        assertSame(expected, assertThrows(IOException.class, () -> PakeEmvSession.prepare(command -> {
            instructions.add(command[1] & 255);
            if ((command[1] & 255) == 0xF8) return profile(15);
            throw expected;
        }, false, status::add)));
        assertEquals(Arrays.asList(0xF8, 0xF7), instructions);
        assertFalse(status.stream().anyMatch(message -> message.startsWith("Card timing unavailable:")));
    }

    @Test
    public void fixedZeroT1TransportCanCarryChicFragmentsAfterUnsupportedF8() throws Exception {
        LegacyPakeCard card = new LegacyPakeCard();
        T1Channel channel = new T1Channel();
        Exchange exchange = command -> channel.exchange(command, card::send);
        PakeEmvSession.Preparation preparation = PakeEmvSession.prepare(exchange, false, ignored -> { });
        assertNull(preparation.baseline);
        assertEquals(Arrays.asList(0xF8), card.instructions);

        byte[] payload = pattern(832);
        byte[] first = PakeEmvIo.sendPakeInitFragmented(exchange::send, payload, ignored -> { });
        byte[] ciphertext = PakeEmvIo.collectPakeResponse(exchange::send, first);
        assertArrayEquals(payload, card.pakeInput.toByteArray());
        assertArrayEquals(pattern(800), ciphertext);
        assertEquals(7, card.coreCount);
        assertEquals(832, card.coreRequestPayloadBytes);
        assertEquals(800, card.coreResponsePayloadBytes);
        assertEquals(867, card.coreCommandBytes);
        assertEquals(814, card.coreResponseBytes);
        assertEquals(Arrays.asList(0xF8, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1), card.instructions);
        assertEquals(Arrays.asList(0, 0, 0, 0, 0, 0, 0, 0), card.requestPcbs);
    }

    private static byte[] status(int sw) {
        return new byte[]{(byte) (sw >>> 8), (byte) sw};
    }

    private static byte[] profile(int capabilities) {
        return ByteBuffer.allocate(14).put(new byte[]{'P', 'E', 'M', '1'})
                .putInt(3).putInt(capabilities).putShort((short) 0x9000).array();
    }

    private static byte[] timing(int flags, int commands, long pake, long cert, long establish) {
        return ByteBuffer.allocate(42).put(new byte[]{'P', 'E', 'B', '1'})
                .putInt(flags).putInt(105_000_000).putInt(commands)
                .putLong(pake).putLong(cert).putLong(establish).putShort((short) 0x9000).array();
    }

    private static byte[] diagnostics(int reason, int flags) {
        return ByteBuffer.allocate(42).put(new byte[]{'P', 'E', 'D', '1'})
                .putInt(reason).putInt(105_000_000).putInt(0).putInt(0x01000000)
                .putInt(0).putInt(1).putInt(17).putInt(reason == 1 ? 100 : 17).putInt(flags)
                .putShort((short) 0x9000).array();
    }

    private static byte[] sysTickDiagnostics(int reason, int flags) {
        return ByteBuffer.allocate(42).put(new byte[]{'P', 'E', 'S', '1'})
                .putInt(reason).putInt(105_000_000).putInt(7).putInt(0xffffff)
                .putInt(0xfffffe).putInt(0).putInt(0).putInt(1).putInt(flags)
                .putShort((short) 0x9000).array();
    }

    private static byte[] pattern(int length) {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++) data[i] = (byte) i;
        return data;
    }

    /** The old receive gate accepts only PCB=00; each such fragment is a new request. */
    private static final class LegacyPakeCard {
        final ByteArrayOutputStream pakeInput = new ByteArrayOutputStream();
        final List<Integer> instructions = new ArrayList<>();
        final List<Integer> requestPcbs = new ArrayList<>();
        int coreCount;
        int coreRequestPayloadBytes;
        int coreResponsePayloadBytes;
        int coreCommandBytes;
        int coreResponseBytes;
        int ciphertextOffset;

        byte[] send(byte[] frame) throws Exception {
            assertEquals(0, frame[0]);
            assertEquals(0, frame[1]);
            assertEquals((frame[2] & 255) + 4, frame.length);
            byte lrc = 0;
            for (byte value : frame) lrc ^= value;
            assertEquals(0, lrc);
            requestPcbs.add(frame[1] & 255);
            byte[] command = Arrays.copyOfRange(frame, 3, frame.length - 1);
            int ins = command[1] & 255;
            instructions.add(ins);
            byte[] response;
            if (ins == 0xF8) {
                response = status(0x6D00);
            } else {
                assertEquals("The unsupported profile must not trigger F7", 0xC1, ins);
                coreCount++;
                coreCommandBytes += command.length;
                if (command.length > 5) {
                    int size = command[4] & 255;
                    assertEquals(5 + size, command.length);
                    pakeInput.write(command, 5, size);
                    coreRequestPayloadBytes += size;
                    boolean more = pakeInput.size() < 832;
                    assertEquals(more ? 1 : 0, command[2]);
                    response = more ? status(0x9000) : nextCiphertext();
                } else {
                    assertEquals(1, command[2]);
                    response = nextCiphertext();
                }
                coreResponseBytes += response.length;
                coreResponsePayloadBytes += response.length - 2;
            }
            byte[] output = new byte[response.length + 4];
            output[2] = (byte) response.length;
            System.arraycopy(response, 0, output, 3, response.length);
            for (int i = 0; i < output.length - 1; i++) output[output.length - 1] ^= output[i];
            return output;
        }

        private byte[] nextCiphertext() {
            byte[] ciphertext = pattern(800);
            int size = Math.min(240, ciphertext.length - ciphertextOffset);
            byte[] response = new byte[size + 2];
            System.arraycopy(ciphertext, ciphertextOffset, response, 0, size);
            ciphertextOffset += size;
            int remaining = ciphertext.length - ciphertextOffset;
            response[size] = (byte) (remaining > 0 ? 0x61 : 0x90);
            response[size + 1] = (byte) (remaining > 255 ? 0 : remaining);
            return response;
        }
    }
}
