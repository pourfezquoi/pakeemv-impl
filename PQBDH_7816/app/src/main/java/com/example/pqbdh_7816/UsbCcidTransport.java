package com.example.pqbdh_7816;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.os.Build;
import androidx.core.content.ContextCompat;
import com.example.pqbdh_7816.apdu.T1Channel;
import com.example.pqbdh_7816.apdu.CcidDescriptor;
import com.example.pqbdh_7816.apdu.CcidSlotStatus;

import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class UsbCcidTransport {
    public interface Logger {
        void log(String message);
    }

    private static final String ACTION_USB_PERMISSION = "com.example.pqbdh_7816.USB_PERMISSION";
    private static final long USB_PERMISSION_TIMEOUT_SECONDS = 120;
    private static final int USB_CLASS_SMARTCARD = 0x0B;
    private static final int MSG_PC_TO_RDR_ICC_POWER_ON = 0x62;
    private static final int MSG_PC_TO_RDR_ICC_POWER_OFF = 0x63;
    private static final int MSG_PC_TO_RDR_GET_SLOT_STATUS = 0x65;
    private static final int MSG_PC_TO_RDR_SET_PARAMETERS = 0x61;
    private static final int MSG_PC_TO_RDR_GET_PARAMETERS = 0x6C;
    private static final int MSG_PC_TO_RDR_XFR_BLOCK = 0x6F;
    private static final int MSG_RDR_TO_PC_DATABLOCK = 0x80;
    private static final int MSG_RDR_TO_PC_PARAMETERS = 0x82;
    private static final int DEFAULT_APDU_READ_TIMEOUT_MS = 15000;

    private final Context context;
    private final Logger logger;
    private final int vendorId;
    private final int productId;

    private UsbManager mgr;
    private UsbDevice dev;
    private UsbDeviceConnection conn;
    private UsbInterface intf;
    private UsbEndpoint epIn;
    private UsbEndpoint epOut;
    private int seq;
    private boolean cardPowered;
    private final T1Channel t1Channel = new T1Channel();

    public UsbCcidTransport(Context context, int vendorId, int productId, Logger logger) {
        this.context = context.getApplicationContext();
        this.vendorId = vendorId;
        this.productId = productId;
        this.logger = logger;
    }

    public void connect() throws Exception {
        connect(false);
    }

    /** Add a read-only presence query for the interactive connection diagnostic. */
    public void connectForDiagnostics() throws Exception {
        connect(true);
    }

    private void connect(boolean probeSlotStatus) throws Exception {
        mgr = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (mgr == null) throw new IllegalStateException("USB manager unavailable");

        dev = findReaderDevice(mgr);
        if (dev == null) throw new IllegalStateException("No CCID reader found (VID=" + vendorId + ", PID=" + productId + ")");

        if (!mgr.hasPermission(dev)) requestPermission(mgr, dev);

        if (!open()) {
            throw new IllegalStateException("Open CCID failed");
        }
        if (logger != null) logger.log(CcidDescriptor.describe(conn.getRawDescriptors(),
                intf.getId(), intf.getAlternateSetting()));
        if (probeSlotStatus) probeSlotStatus(0);
        byte[] atr = powerOn(0);
        if (!atrAdvertisesT1(atr)) {
            throw new IllegalStateException("Card ATR does not advertise T=1 protocol");
        }
        configureAndVerifyT1(0);
        t1Channel.reset();
        cardPowered = true;
        if (logger != null) logger.log("Card ATR: " + toHex(atr));
        if (logger != null) logger.log("Transport: original demo profile, fixed T=1 PCB=00.");
    }

    public byte[] sendApdu(byte[] apdu) throws Exception {
        return sendApdu(apdu, DEFAULT_APDU_READ_TIMEOUT_MS);
    }

    public byte[] sendApdu(byte[] apdu, int readTimeoutMs) throws Exception {
        if (conn == null || epIn == null || epOut == null) {
            throw new IllegalStateException("CCID is not connected");
        }
        if (!cardPowered) {
            byte[] atr = powerOn(0);
            if (!atrAdvertisesT1(atr)) {
                throw new IllegalStateException("Card ATR does not advertise T=1 protocol");
            }
            configureAndVerifyT1(0);
            t1Channel.reset();
            cardPowered = true;
        }
        try {
            return t1Channel.exchange(apdu, frame -> transmit(frame, 0, 0, readTimeoutMs));
        } catch (Exception failure) {
            // Include the public header only. Never log PINs, keys, or APDU data.
            String header = apdu != null && apdu.length >= 4
                    ? String.format(Locale.ROOT, "%02X %02X %02X %02X",
                            apdu[0] & 255, apdu[1] & 255, apdu[2] & 255, apdu[3] & 255)
                    : "invalid";
            throw new IllegalStateException("APDU " + header + " failed: " + failure.getMessage(), failure);
        }
    }

    public byte[] transmit(byte[] apdu, int slot, int bBWI) throws Exception {
        return transmit(apdu, slot, bBWI, DEFAULT_APDU_READ_TIMEOUT_MS);
    }

    public byte[] transmit(byte[] apdu, int slot, int bBWI, int readTimeoutMs) throws Exception {
        byte[] header = ccidHeader(MSG_PC_TO_RDR_XFR_BLOCK, apdu.length, slot, 0, bBWI, 0);
        int expectedSeq = header[6] & 0xFF;
        byte[] outBuf = new byte[header.length + apdu.length];
        System.arraycopy(header, 0, outBuf, 0, header.length);
        System.arraycopy(apdu, 0, outBuf, header.length, apdu.length);
        xferOut(outBuf, 8000);

        for (int attempt = 1; attempt <= 3; attempt++) {
            byte[] resp;
            try {
                resp = readCcidFrame(readTimeoutMs);
            } catch (UsbBulkInFailure failure) {
                if (attempt < 3) continue;
                throw new IllegalStateException("CCID XfrBlock slot=" + slot + ", seq="
                        + expectedSeq + " failed after " + attempt + " reads: " + failure.getMessage(),
                        failure);
            }
            validateCcidResponse(resp, MSG_RDR_TO_PC_DATABLOCK, slot, expectedSeq);
            int respLen = le32(resp, 1);
            if (respLen == 0 && attempt < 3) continue; // empty status frame
            if (respLen < 2) {
                throw new IllegalStateException("Invalid APDU response length: " + respLen + " bytes");
            }
            byte[] apduResp = new byte[respLen];
            System.arraycopy(resp, 10, apduResp, 0, respLen);
            return apduResp;
        }
        throw new IllegalStateException("No APDU payload DataBlock received.");
    }

    public void close() {
        cardPowered = false;
        if (conn != null && intf != null) {
            try {
                conn.releaseInterface(intf);
            } catch (Exception ignored) {}
        }
        if (conn != null) {
            try {
                conn.close();
            } catch (Exception ignored) {}
        }
        conn = null;
        intf = null;
        epIn = null;
        epOut = null;
    }

    private UsbDevice findReaderDevice(UsbManager usbManager) {
        for (Map.Entry<String, UsbDevice> entry : usbManager.getDeviceList().entrySet()) {
            UsbDevice d = entry.getValue();
            if (d.getVendorId() == vendorId && d.getProductId() == productId) {
                return d;
            }
        }
        return null;
    }

    @SuppressWarnings("deprecation")
    private void requestPermission(UsbManager usbManager, UsbDevice device) throws InterruptedException {
        // A late response from an earlier request must not complete this wait.
        String action = ACTION_USB_PERMISSION + "." + UUID.randomUUID();
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Boolean> reply = new AtomicReference<>();

        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!action.equals(intent.getAction())) return;
                UsbDevice replyDevice = Build.VERSION.SDK_INT >= 33
                        ? intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice.class)
                        : intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                if (replyDevice != null && !device.equals(replyDevice)) return;
                if (intent.hasExtra(UsbManager.EXTRA_PERMISSION_GRANTED)) {
                    reply.set(intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false));
                }
                latch.countDown();
            }
        };

        IntentFilter filter = new IntentFilter(action);
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED);

        PendingIntent permissionIntent = null;
        try {
            // Permission may have become available since connect() checked it.
            if (usbManager.hasPermission(device)) return;
            permissionIntent = createUsbPermissionCallback(context, action);
            if (logger != null) logger.log("Requesting USB permission...");
            usbManager.requestPermission(device, permissionIntent);
            boolean received = latch.await(USB_PERMISSION_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            // The manager is authoritative, including when a framework omits callback extras.
            if (usbManager.hasPermission(device)) return;
            if (!received) {
                throw new IllegalStateException("Timed out waiting for USB permission after "
                        + USB_PERMISSION_TIMEOUT_SECONDS + " seconds. Approve the Android USB access dialog before retrying.");
            }
            if (Boolean.FALSE.equals(reply.get())) {
                throw new IllegalStateException("USB permission denied by user");
            }
            throw new IllegalStateException("USB permission callback received, but Android has not granted access to the selected reader.");
        } finally {
            if (permissionIntent != null) permissionIntent.cancel();
            try {
                context.unregisterReceiver(receiver);
            } catch (Exception ignored) {}
        }
    }

    static PendingIntent createUsbPermissionCallback(Context context, String action) {
        // UsbManager supplies EXTRA_DEVICE and EXTRA_PERMISSION_GRANTED at send time.
        // An immutable PendingIntent discards those extras even after the user approves.
        Intent intent = new Intent(action).setPackage(context.getPackageName());
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 31) flags |= PendingIntent.FLAG_MUTABLE;
        return PendingIntent.getBroadcast(context, 0, intent, flags);
    }

    public boolean open() {
        if (mgr == null || dev == null) return false;
        UsbInterface scInterface = null;
        for (int i = 0; i < dev.getInterfaceCount(); i++) {
            UsbInterface usbIntf = dev.getInterface(i);
            if (usbIntf.getInterfaceClass() == USB_CLASS_SMARTCARD) {
                scInterface = usbIntf;
                break;
            }
        }
        if (scInterface == null) {
            return false;
        }

        UsbDeviceConnection c = mgr.openDevice(dev);
        if (c == null) return false;
        if (!c.claimInterface(scInterface, true)) {
            c.close();
            return false;
        }

        UsbEndpoint in = null;
        UsbEndpoint out = null;
        for (int i = 0; i < scInterface.getEndpointCount(); i++) {
            UsbEndpoint ep = scInterface.getEndpoint(i);
            if (ep.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                if (ep.getDirection() == UsbConstants.USB_DIR_IN) in = ep;
                if (ep.getDirection() == UsbConstants.USB_DIR_OUT) out = ep;
            }
        }

        if (in == null || out == null) {
            c.releaseInterface(scInterface);
            c.close();
            return false;
        }

        conn = c;
        intf = scInterface;
        epIn = in;
        epOut = out;
        cardPowered = false;
        t1Channel.reset();
        return true;
    }

    private void probeSlotStatus(int slot) {
        byte[] header = ccidHeader(MSG_PC_TO_RDR_GET_SLOT_STATUS, 0, slot, 0, 0, 0);
        int expectedSeq = header[6] & 0xFF;
        try {
            xferOut(header, 5000);
            String status = CcidSlotStatus.describe(readCcidFrame(8000), slot, expectedSeq);
            if (logger != null) logger.log(status);
        } catch (Exception failure) {
            throw new IllegalStateException("CCID GetSlotStatus before power-on failed (command=0x65, slot="
                    + slot + ", seq=" + expectedSeq + "): "
                    + (failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage()), failure);
        }
    }

    public byte[] powerOn(int slot) {
        if (conn == null || epIn == null || epOut == null) {
            throw new IllegalStateException("ICC power on cannot start: USB connection/endpoints are unavailable");
        }
        byte[] header = ccidHeader(MSG_PC_TO_RDR_ICC_POWER_ON, 0, slot, 0, 0, 0);
        int expectedSeq = header[6] & 0xFF;
        try {
            if (logger != null) logger.log("CCID IccPowerOn: slot=" + slot
                    + ", seq=" + expectedSeq + ", voltage=automatic");
            xferOut(header, 5000);
            byte[] resp = readCcidFrame(8000);
            validateCcidResponse(resp, MSG_RDR_TO_PC_DATABLOCK, slot, expectedSeq);
            int len = le32(resp, 1);
            if (len <= 0) {
                throw new IllegalStateException(String.format(Locale.ROOT,
                        "Reader returned no ATR: payload=%d, status=0x%02X, error=0x%02X",
                        len, resp[7] & 0xFF, resp[8] & 0xFF));
            }
            byte[] atr = new byte[len];
            System.arraycopy(resp, 10, atr, 0, len);
            return atr;
        } catch (Exception failure) {
            throw new IllegalStateException("ICC power on failed (CCID command=0x62, slot="
                    + slot + ", seq=" + expectedSeq + "): "
                    + (failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage()), failure);
        }
    }

    public void powerOff(int slot) {
        if (conn == null || epOut == null || epIn == null) return;
        try {
            byte[] header = ccidHeader(MSG_PC_TO_RDR_ICC_POWER_OFF, 0, slot, 0, 0, 0);
            xferOut(header, 5000);
            xferIn(512, 8000);
        } catch (Exception ignored) {}
    }

    private byte nextSeq() {
        seq = (seq + 1) & 0xFF;
        return (byte) seq;
    }

    private void xferOut(byte[] data, int timeoutMs) {
        int sent = conn.bulkTransfer(epOut, data, data.length, timeoutMs);
        if (sent != data.length) {
            throw new IllegalStateException("bulk OUT short write " + sent + "/" + data.length);
        }
    }

    private static final class UsbBulkInFailure extends IllegalStateException {
        UsbBulkInFailure(int result, int endpoint, int timeoutMs) {
            super(String.format(Locale.ROOT,
                    "USB bulk IN received no data: result=%d, endpoint=0x%02X, timeout=%d ms",
                    result, endpoint, timeoutMs));
        }
    }

    private byte[] xferIn(int bufSize, int timeoutMs) {
        byte[] buf = new byte[bufSize];
        int got = conn.bulkTransfer(epIn, buf, buf.length, timeoutMs);
        if (got <= 0) {
            throw new UsbBulkInFailure(got, epIn.getAddress(), timeoutMs);
        }
        byte[] out = new byte[got];
        System.arraycopy(buf, 0, out, 0, got);
        return out;
    }

    private byte[] ccidHeader(int type, int len, int slot, int param1, int param2, int param3) {
        byte[] header = new byte[10];
        header[0] = (byte) type;
        header[1] = (byte) (len & 0xFF);
        header[2] = (byte) ((len >>> 8) & 0xFF);
        header[3] = (byte) ((len >>> 16) & 0xFF);
        header[4] = (byte) ((len >>> 24) & 0xFF);
        header[5] = (byte) slot;
        header[6] = nextSeq();
        header[7] = (byte) param1;
        header[8] = (byte) param2;
        header[9] = (byte) param3;
        return header;
    }

    private void configureAndVerifyT1(int slot) throws Exception {
        setParametersT1(slot);
        int protocol = getParametersProtocol(slot);
        if (protocol != 0x01) {
            throw new IllegalStateException("CCID active protocol is not T=1: " + protocol);
        }
    }

    private void setParametersT1(int slot) throws Exception {
        // CCID T=1 parameters:
        // [Fi/Di, TCCKS, GuardTime, BWI/CWI, ClockStop, IFSC, NAD]
        byte[] t1Params = new byte[]{
                0x11,       // Fi/Di default
                0x10,       // bmTCCKST1: direct convention + LRC (matches card-side T=1)
                0x00,       // extra guard time
                0x4D,       // BWI/CWI default
                0x00,       // clock stop unsupported
                0x20,       // IFSC=32
                0x00        // NAD
        };
        byte[] header = ccidHeader(MSG_PC_TO_RDR_SET_PARAMETERS, t1Params.length, slot, 0x01, 0x00, 0x00);
        int expectedSeq = header[6] & 0xFF;
        byte[] outBuf = new byte[header.length + t1Params.length];
        System.arraycopy(header, 0, outBuf, 0, header.length);
        System.arraycopy(t1Params, 0, outBuf, header.length, t1Params.length);
        xferOut(outBuf, 8000);

        byte[] resp = readCcidFrame(15000);
        validateCcidResponse(resp, MSG_RDR_TO_PC_PARAMETERS, slot, expectedSeq);
    }

    private int getParametersProtocol(int slot) throws Exception {
        byte[] header = ccidHeader(MSG_PC_TO_RDR_GET_PARAMETERS, 0, slot, 0x00, 0x00, 0x00);
        int expectedSeq = header[6] & 0xFF;
        xferOut(header, 8000);
        byte[] resp = readCcidFrame(15000);
        validateCcidResponse(resp, MSG_RDR_TO_PC_PARAMETERS, slot, expectedSeq);
        if (resp.length < 10) {
            throw new IllegalStateException("CCID GetParameters short response");
        }
        return resp[9] & 0xFF;
    }

    private void validateCcidResponse(byte[] resp, int expectedType, int expectedSlot, int expectedSeq) {
        if (resp == null || resp.length < 10) {
            throw new IllegalStateException("CCID short response: received "
                    + (resp == null ? "null" : resp.length + " bytes") + "; need at least 10 bytes");
        }
        int type = resp[0] & 0xFF;
        int slot = resp[5] & 0xFF;
        int seqNo = resp[6] & 0xFF;
        if (type != expectedType) {
            throw new IllegalStateException("Unexpected CCID response type: " + type + ", expected " + expectedType);
        }
        if (slot != (expectedSlot & 0xFF)) {
            throw new IllegalStateException("CCID slot mismatch: " + slot + ", expected " + expectedSlot);
        }
        if (seqNo != (expectedSeq & 0xFF)) {
            throw new IllegalStateException("CCID seq mismatch: " + seqNo + ", expected " + expectedSeq);
        }
        int status = resp[7] & 0xFF;
        int cmdStatus = (status >>> 6) & 0x03;
        if (cmdStatus == 0x01) {
            int error = resp[8] & 0xFF;
            throw new IllegalStateException("CCID command failed: status="
                    + String.format("0x%02X", status) + ", error=" + String.format("0x%02X", error));
        }
        if (cmdStatus == 0x02) {
            throw new IllegalStateException("CCID time extension requested but not handled in this path");
        }
    }

    private byte[] readCcidFrame(int timeoutMs) {
        byte[] first = xferIn(1024, timeoutMs);
        if (first.length < 10) return first;
        int payloadLen = le32(first, 1);
        int totalLen = 10 + payloadLen;
        if (first.length >= totalLen) return first;

        ByteArrayOutputStream acc = new ByteArrayOutputStream(totalLen);
        acc.write(first, 0, first.length);
        while (acc.size() < totalLen) {
            byte[] next;
            try {
                next = xferIn(1024, timeoutMs);
            } catch (UsbBulkInFailure failure) {
                throw new IllegalStateException("CCID fragmented read incomplete: got " + acc.size()
                        + ", need " + totalLen + "; " + failure.getMessage(), failure);
            }
            acc.write(next, 0, next.length);
        }
        return acc.toByteArray();
    }

    private int le32(byte[] b, int off) {
        return (b[off] & 0xFF)
                | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 3] & 0xFF) << 24);
    }


    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    private boolean atrAdvertisesT1(byte[] atr) {
        if (atr == null || atr.length < 2) return false;
        int t0 = atr[1] & 0xFF;              // Y1 in high nibble, K in low nibble
        int y = (t0 >>> 4) & 0x0F;          // interface byte presence flags
        int idx = 2;
        while (true) {
            if ((y & 0x1) != 0) { if (idx >= atr.length) return false; idx++; } // TAi
            if ((y & 0x2) != 0) { if (idx >= atr.length) return false; idx++; } // TBi
            if ((y & 0x4) != 0) { if (idx >= atr.length) return false; idx++; } // TCi
            if ((y & 0x8) == 0) break; // No TDi in this group
            if (idx >= atr.length) return false;
            int td = atr[idx++] & 0xFF;
            if ((td & 0x0F) == 0x01) return true; // protocol T=1 found
            y = (td >>> 4) & 0x0F; // move to next group presence bits
        }
        return false;
    }
}
