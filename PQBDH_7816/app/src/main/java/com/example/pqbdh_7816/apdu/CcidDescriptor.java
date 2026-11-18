package com.example.pqbdh_7816.apdu;

import java.util.Locale;

/** Public USB capability diagnostics only; this class never selects a transport mode. */
public final class CcidDescriptor {
    private static final long EXCHANGE_MASK = 0x00070000L;
    private static final long AUTO_VOLTAGE = 0x00000008L;

    private CcidDescriptor() { }

    public static String describe(byte[] rawDescriptors, int interfaceNumber, int alternateSetting) {
        if (interfaceNumber < 0 || interfaceNumber > 255
                || alternateSetting < 0 || alternateSetting > 255) {
            throw new IllegalArgumentException("USB interface and alternate setting must be unsigned bytes.");
        }
        if (rawDescriptors == null || rawDescriptors.length == 0) {
            return unavailable("USB descriptors are missing.");
        }

        int matchingInterfaces = 0;
        int matchingClassDescriptors = 0;
        boolean selectedInterface = false;
        boolean selectedClassIsCcid = false;
        int voltageSupport = 0;
        long features = 0, protocols = 0, maxMessage = 0, maxIfsd = 0;
        for (int offset = 0; offset < rawDescriptors.length; ) {
            int remaining = rawDescriptors.length - offset;
            if (remaining < 2) return unavailable("A USB descriptor header is truncated.");
            int length = rawDescriptors[offset] & 255;
            int type = rawDescriptors[offset + 1] & 255;
            if (length < 2) return unavailable("A USB descriptor has an invalid length.");
            if (length > remaining) return unavailable("A USB descriptor is truncated.");

            if (type == 0x01 || type == 0x02) {
                // A device/configuration boundary ends the previous interface's scope.
                selectedInterface = false;
                if ((type == 0x01 && length < 18) || (type == 0x02 && length < 9)) {
                    return unavailable("A USB device/configuration descriptor is malformed.");
                }
            } else if (type == 0x04) {
                if (length < 9) return unavailable("A USB interface descriptor is malformed.");
                selectedInterface = (rawDescriptors[offset + 2] & 255) == interfaceNumber
                        && (rawDescriptors[offset + 3] & 255) == alternateSetting;
                if (selectedInterface) {
                    matchingInterfaces++;
                    selectedClassIsCcid = (rawDescriptors[offset + 5] & 255) == 0x0B;
                }
            } else if (type == 0x21 && selectedInterface && selectedClassIsCcid) {
                if (length < 54) return unavailable("The selected CCID class descriptor is too short.");
                matchingClassDescriptors++;
                // CCID bVoltageSupport is reader capability, not the card's voltage rating.
                voltageSupport = rawDescriptors[offset + 5] & 255;
                protocols = u32(rawDescriptors, offset + 6);
                maxIfsd = u32(rawDescriptors, offset + 28);
                features = u32(rawDescriptors, offset + 40);
                maxMessage = u32(rawDescriptors, offset + 44);
            }
            offset += length;
        }

        if (matchingInterfaces == 0) return unavailable("The selected USB interface/alternate was not found.");
        if (matchingInterfaces != 1) return unavailable("The selected USB interface/alternate is ambiguous.");
        if (!selectedClassIsCcid) return unavailable("The selected USB interface is not CCID class 0B.");
        if (matchingClassDescriptors == 0) return unavailable("The selected interface has no CCID class descriptor.");
        if (matchingClassDescriptors != 1) return unavailable("The selected interface has multiple CCID class descriptors.");

        long exchange = features & EXCHANGE_MASK;
        return String.format(Locale.ROOT,
                "CCID capabilities: interface=%d, alternate=%d; dwFeatures=0x%08X; "
                        + "exchange=%s (mask=0x%08X); protocols=0x%08X; "
                        + "maxCCIDMessage=%d B; maxIFSD=%d B; voltageSupport=0x%02X (%s); "
                        + "automaticVoltageSelection=%s. No transport change requested.",
                interfaceNumber, alternateSetting, features, exchangeName(exchange), exchange,
                protocols, maxMessage, maxIfsd, voltageSupport, voltageNames(voltageSupport),
                (features & AUTO_VOLTAGE) != 0);
    }

    private static String voltageNames(int support) {
        StringBuilder names = new StringBuilder();
        if ((support & 1) != 0) names.append("5 V");
        if ((support & 2) != 0) {
            if (names.length() > 0) names.append(", ");
            names.append("3 V");
        }
        if ((support & 4) != 0) {
            if (names.length() > 0) names.append(", ");
            names.append("1.8 V");
        }
        if ((support & 0xF8) != 0) {
            if (names.length() > 0) names.append(", ");
            names.append(String.format(Locale.ROOT, "unknown bits 0x%02X", support & 0xF8));
        }
        return names.length() == 0 ? "none advertised" : names.toString();
    }

    private static String exchangeName(long exchange) {
        if (exchange == 0x00000000L) return "character level";
        if (exchange == 0x00010000L) return "TPDU level";
        if (exchange == 0x00020000L) return "short APDU level";
        if (exchange == 0x00040000L) return "extended APDU level";
        return "unknown/unsupported level";
    }

    private static long u32(byte[] bytes, int offset) {
        return (bytes[offset] & 255L) | ((bytes[offset + 1] & 255L) << 8)
                | ((bytes[offset + 2] & 255L) << 16) | ((bytes[offset + 3] & 255L) << 24);
    }

    private static String unavailable(String reason) {
        return "CCID capabilities unavailable: " + reason + " No transport change requested.";
    }
}
