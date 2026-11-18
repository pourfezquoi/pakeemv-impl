package com.example.pqbdh_7816.apdu;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Locale;
import org.junit.Test;

/** Descriptor parsing fixtures do not establish the capabilities of an attached reader. */
public class CcidDescriptorTest {
    @Test
    public void describesPublished5321TpduCapabilitiesWithoutSelectingAMode() {
        // Published libccid CardMan5321 values: 000103B0, protocols3, message271, IFSD254.
        String text = CcidDescriptor.describe(concat(device(), configuration(),
                usbInterface(0, 0, 0x0B), ccid(0x000103B0L, 3, 271, 254, 7)), 0, 0);
        assertTrue(text.contains("interface=0, alternate=0"));
        assertTrue(text.contains("dwFeatures=0x000103B0"));
        assertTrue(text.contains("exchange=TPDU level (mask=0x00010000)"));
        assertTrue(text.contains("protocols=0x00000003"));
        assertTrue(text.contains("maxCCIDMessage=271 B; maxIFSD=254 B"));
        assertTrue(text.contains("voltageSupport=0x07 (5 V, 3 V, 1.8 V)"));
        assertTrue(text.contains("automaticVoltageSelection=false"));
        assertTrue(text.endsWith("No transport change requested."));
    }

    @Test
    public void voltageCapabilitiesBelongToTheExactSelectedInterfaceAndAlternate() {
        byte[] raw = concat(usbInterface(1, 0, 0x0B), ccid(0x10008, 3, 271, 254, 1),
                usbInterface(2, 0, 0x0B), ccid(0x10008, 3, 271, 254, 2),
                usbInterface(2, 1, 0x0B), ccid(0x10000, 3, 271, 254, 4));
        String text = CcidDescriptor.describe(raw, 2, 1);
        assertTrue(text.contains("voltageSupport=0x04 (1.8 V)"));
        assertTrue(text.contains("automaticVoltageSelection=false"));
        assertFalse(text.contains("voltageSupport=0x01"));
        assertFalse(text.contains("voltageSupport=0x02"));
    }

    @Test
    public void automaticVoltageSelectionUsesItsOwnFeatureBit() {
        long[] features = {0x000103B0L, 0x000103B8L, 0x000103B4L};
        boolean[] automatic = {false, true, false};
        for (int i = 0; i < features.length; i++) {
            String text = CcidDescriptor.describe(concat(usbInterface(0, 0, 0x0B),
                    ccid(features[i], 3, 271, 254, 7)), 0, 0);
            assertTrue(text.contains("voltageSupport=0x07 (5 V, 3 V, 1.8 V)"));
            assertTrue(text.contains("automaticVoltageSelection=" + automatic[i]));
        }
    }

    @Test
    public void zeroAndReservedVoltageBitsAreRetainedWithoutGuessing() {
        int[] masks = {0, 0x80, 0x82, 0xFF};
        String[] names = {"none advertised", "unknown bits 0x80",
                "3 V, unknown bits 0x80", "5 V, 3 V, 1.8 V, unknown bits 0xF8"};
        for (int i = 0; i < masks.length; i++) {
            String text = CcidDescriptor.describe(concat(usbInterface(0, 0, 0x0B),
                    ccid(0x10000, 3, 271, 254, masks[i])), 0, 0);
            assertTrue(text.contains(String.format(Locale.ROOT,
                    "voltageSupport=0x%02X (%s)", masks[i], names[i])));
            assertTrue(text.contains("automaticVoltageSelection=false"));
            assertTrue(text.endsWith("No transport change requested."));
        }
    }

    @Test
    public void recognizesEveryDefinedExchangeLevelWithoutInferringFromProductIds() {
        long[] features = {0, 0x00010000L, 0x00020000L, 0x00040000L};
        String[] names = {"character level", "TPDU level", "short APDU level", "extended APDU level"};
        for (int i = 0; i < features.length; i++) {
            String text = CcidDescriptor.describe(concat(usbInterface(4, 2, 0x0B),
                    ccid(features[i], 3, 1024, 254)), 4, 2);
            assertTrue(text.contains("exchange=" + names[i]));
        }
    }

    @Test
    public void undefinedCombinedExchangeBitsAreReportedWithoutGuessing() {
        String text = CcidDescriptor.describe(concat(usbInterface(0, 0, 0x0B),
                ccid(0x00030000L, 3, 271, 254)), 0, 0);
        assertTrue(text.contains("exchange=unknown/unsupported level (mask=0x00030000)"));
        assertTrue(text.contains("No transport change requested"));
    }

    @Test
    public void reportsUnsignedLittleEndianValuesUnderAnyLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("ar"));
            String text = CcidDescriptor.describe(concat(usbInterface(255, 255, 0x0B),
                    ccid(0x800103B0L, 0x80000003L, 0xFFFFFFFFL, 0xFFFFFFFEL)), 255, 255);
            assertTrue(text.contains("interface=255, alternate=255"));
            assertTrue(text.contains("dwFeatures=0x800103B0"));
            assertTrue(text.contains("protocols=0x80000003"));
            assertTrue(text.contains("maxCCIDMessage=4294967295 B; maxIFSD=4294967294 B"));
        } finally {
            Locale.setDefault(original);
        }
    }

    @Test
    public void classDescriptorMustBelongToTheExactSelectedInterfaceAndAlternate() {
        byte[] raw = concat(usbInterface(1, 0, 0x0B), ccid(0x10000, 1, 111, 11),
                usbInterface(2, 0, 0x0B), ccid(0x20000, 2, 222, 22),
                usbInterface(2, 1, 0x0B), ccid(0x40000, 3, 333, 33));
        String text = CcidDescriptor.describe(raw, 2, 1);
        assertTrue(text.contains("extended APDU level"));
        assertTrue(text.contains("maxCCIDMessage=333 B; maxIFSD=33 B"));
        assertFalse(text.contains("maxCCIDMessage=111"));
        assertFalse(text.contains("maxCCIDMessage=222"));
    }

    @Test
    public void nonCcidInterfaceCannotBorrowAnAdjacentClassDescriptor() {
        byte[] raw = concat(usbInterface(0, 0, 0x03), ccid(0x10000, 3, 271, 254),
                usbInterface(1, 0, 0x0B), ccid(0x10000, 3, 271, 254));
        assertUnavailable(CcidDescriptor.describe(raw, 0, 0), "not CCID class 0B");
    }

    @Test
    public void matchingInterfaceIsRequiredEvenWhenAClassDescriptorExists() {
        assertUnavailable(CcidDescriptor.describe(ccid(0x10000, 3, 271, 254), 0, 0), "not found");
        assertUnavailable(CcidDescriptor.describe(concat(usbInterface(1, 0, 0x0B),
                ccid(0x10000, 3, 271, 254)), 0, 0), "not found");
    }

    @Test
    public void anotherInterfaceOrConfigurationEndsTheSelectedInterfacesScope() {
        assertUnavailable(CcidDescriptor.describe(concat(usbInterface(0, 0, 0x0B),
                usbInterface(1, 0, 0x0B), ccid(0x10000, 3, 271, 254)), 0, 0), "no CCID class descriptor");
        assertUnavailable(CcidDescriptor.describe(concat(usbInterface(0, 0, 0x0B),
                configuration(), ccid(0x10000, 3, 271, 254)), 0, 0), "no CCID class descriptor");
    }

    @Test
    public void multipleMatchingInterfacesAcrossConfigurationsAreAmbiguous() {
        byte[] profile = concat(usbInterface(0, 0, 0x0B), ccid(0x10000, 3, 271, 254));
        assertUnavailable(CcidDescriptor.describe(concat(configuration(), profile,
                configuration(), profile), 0, 0), "ambiguous");
    }

    @Test
    public void multipleClassDescriptorsForSelectedInterfaceAreRejected() {
        assertUnavailable(CcidDescriptor.describe(concat(usbInterface(0, 0, 0x0B),
                ccid(0x10000, 3, 271, 254), ccid(0x20000, 3, 271, 254)), 0, 0), "multiple CCID class descriptors");
    }

    @Test
    public void missingAndTruncatedStreamsReturnBoundedUnavailableReasons() {
        for (byte[] raw : new byte[][]{null, new byte[0], new byte[]{9},
                new byte[]{9, 4, 0, 0, 0}, new byte[]{0, 4}, new byte[]{1, 4}}) {
            assertUnavailable(CcidDescriptor.describe(raw, 0, 0), "");
        }
        byte[] full = concat(usbInterface(0, 0, 0x0B), ccid(0x10000, 3, 271, 254));
        for (int size = 10; size < full.length; size++) {
            assertUnavailable(CcidDescriptor.describe(Arrays.copyOf(full, size), 0, 0), "");
        }
        assertUnavailable(CcidDescriptor.describe(concat(full, new byte[]{7, 5, 1}), 0, 0), "truncated");
    }

    @Test
    public void malformedInterfaceAndShortSelectedCcidDescriptorsAreRejected() {
        assertUnavailable(CcidDescriptor.describe(new byte[]{2, 4}, 0, 0), "interface descriptor is malformed");
        assertUnavailable(CcidDescriptor.describe(concat(usbInterface(0, 0, 0x0B),
                new byte[]{2, 0x21}), 0, 0), "too short");
        assertUnavailable(CcidDescriptor.describe(new byte[]{2, 1}, 0, 0), "device/configuration descriptor");
        assertUnavailable(CcidDescriptor.describe(new byte[]{2, 2}, 0, 0), "device/configuration descriptor");
    }

    @Test
    public void unselectedHidDescriptorDoesNotBecomeAnInvalidCcidDescriptor() {
        byte[] raw = concat(usbInterface(1, 0, 3), new byte[]{2, 0x21},
                usbInterface(0, 0, 0x0B), ccid(0x10000, 3, 271, 254));
        assertTrue(CcidDescriptor.describe(raw, 0, 0).contains("TPDU level"));
    }

    @Test
    public void invalidInterfaceArgumentsAreRejected() {
        for (int value : new int[]{-1, 256}) {
            assertThrows(IllegalArgumentException.class, () -> CcidDescriptor.describe(null, value, 0));
            assertThrows(IllegalArgumentException.class, () -> CcidDescriptor.describe(null, 0, value));
        }
    }

    private static void assertUnavailable(String text, String reason) {
        assertTrue(text, text.startsWith("CCID capabilities unavailable:"));
        assertTrue(text, text.contains(reason));
        assertTrue(text, text.length() < 256);
        assertTrue(text, text.endsWith("No transport change requested."));
    }

    private static byte[] usbInterface(int number, int alternate, int usbClass) {
        return new byte[]{9, 4, (byte) number, (byte) alternate, 3, (byte) usbClass, 0, 0, 0};
    }

    private static byte[] ccid(long features, long protocols, long message, long ifsd) {
        byte[] descriptor = new byte[54];
        descriptor[0] = 54;
        descriptor[1] = 0x21;
        descriptor[3] = 1; // CCID version 1.00
        putU32(descriptor, 6, protocols);
        putU32(descriptor, 28, ifsd);
        putU32(descriptor, 40, features);
        putU32(descriptor, 44, message);
        return descriptor;
    }

    private static byte[] ccid(long features, long protocols, long message, long ifsd, int voltageSupport) {
        byte[] descriptor = ccid(features, protocols, message, ifsd);
        descriptor[5] = (byte) voltageSupport;
        return descriptor;
    }

    private static void putU32(byte[] descriptor, int offset, long value) {
        for (int i = 0; i < 4; i++) descriptor[offset + i] = (byte) (value >>> (i * 8));
    }

    private static byte[] device() {
        byte[] descriptor = new byte[18];
        descriptor[0] = 18;
        descriptor[1] = 1;
        return descriptor;
    }

    private static byte[] configuration() {
        return new byte[]{9, 2, 0, 0, 1, 1, 0, (byte) 0x80, 50};
    }

    private static byte[] concat(byte[]... descriptors) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (byte[] descriptor : descriptors) output.write(descriptor, 0, descriptor.length);
        return output.toByteArray();
    }
}
