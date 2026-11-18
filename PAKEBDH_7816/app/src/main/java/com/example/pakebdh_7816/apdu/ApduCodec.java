package com.example.pakebdh_7816.apdu;

public final class ApduCodec {
    private ApduCodec() {
    }

    public static byte[] buildCommandApdu(int cla, int ins, int p1, int p2, byte[] data) {
        return buildCommandApdu(cla, ins, p1, p2, data, true);
    }

    public static byte[] buildCommandApduNoLe(int cla, int ins, int p1, int p2, byte[] data) {
        return buildCommandApdu(cla, ins, p1, p2, data, false);
    }

    private static byte[] buildCommandApdu(int cla, int ins, int p1, int p2, byte[] data, boolean includeLe) {
        int lc = (data == null) ? 0 : data.length;
        if (lc > 255) {
            byte[] apdu = new byte[7 + lc + (includeLe ? 2 : 0)];
            apdu[0] = (byte) cla;
            apdu[1] = (byte) ins;
            apdu[2] = (byte) p1;
            apdu[3] = (byte) p2;
            apdu[4] = 0x00;
            apdu[5] = (byte) ((lc >> 8) & 0xFF);
            apdu[6] = (byte) (lc & 0xFF);
            if (data != null) {
                System.arraycopy(data, 0, apdu, 7, lc);
            }
            if (includeLe) {
                apdu[apdu.length - 2] = 0x00;
                apdu[apdu.length - 1] = 0x00;
            }
            return apdu;
        }

        if (lc == 0) {
            byte[] apdu = new byte[5];
            apdu[0] = (byte) cla;
            apdu[1] = (byte) ins;
            apdu[2] = (byte) p1;
            apdu[3] = (byte) p2;
            apdu[4] = 0x00;
            return apdu;
        }

        byte[] apdu = new byte[5 + lc + (includeLe ? 1 : 0)];
        apdu[0] = (byte) cla;
        apdu[1] = (byte) ins;
        apdu[2] = (byte) p1;
        apdu[3] = (byte) p2;
        apdu[4] = (byte) lc;
        if (data != null) {
            System.arraycopy(data, 0, apdu, 5, lc);
        }
        if (includeLe) {
            apdu[apdu.length - 1] = 0x00;
        }
        return apdu;
    }
}
