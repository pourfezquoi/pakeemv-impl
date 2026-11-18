package com.example.pqbdh_7816;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbManager;
import android.os.Looper;
import androidx.core.content.ContextCompat;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Android callback delivery regression tests; no USB device or card is required. */
@RunWith(AndroidJUnit4.class)
public class UsbPermissionCallbackTest {
    private static final String EXTRA_MARKER = "permission_test_marker";

    @Test
    public void grantResultExtrasReachThePermissionReceiver() throws Exception {
        assertDeliveredPermissionResult(true);
    }

    @Test
    public void explicitDenialExtrasReachThePermissionReceiver() throws Exception {
        assertDeliveredPermissionResult(false);
    }

    private static void assertDeliveredPermissionResult(boolean granted) throws Exception {
        assertTrue("Waiting for a broadcast must not block the receiver's main thread",
                Looper.myLooper() != Looper.getMainLooper());
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        String requestId = UUID.randomUUID().toString();
        String action = context.getPackageName() + ".USB_PERMISSION_TEST." + requestId;
        CountDownLatch received = new CountDownLatch(1);
        AtomicReference<Intent> delivered = new AtomicReference<>();
        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context ignored, Intent intent) {
                delivered.set(new Intent(intent));
                received.countDown();
            }
        };
        ContextCompat.registerReceiver(context, receiver, new IntentFilter(action),
                ContextCompat.RECEIVER_NOT_EXPORTED);
        PendingIntent callback = null;
        try {
            callback = UsbCcidTransport.createUsbPermissionCallback(context, action);
            // UsbManager supplies its result as fill-in extras when sending this callback.
            // An immutable PendingIntent drops them, reproducing the original first-grant bug.
            Intent result = new Intent()
                    .putExtra(UsbManager.EXTRA_PERMISSION_GRANTED, granted)
                    .putExtra(EXTRA_MARKER, requestId);
            callback.send(context, 0, result);
            assertTrue("USB permission callback was not delivered",
                    received.await(10, TimeUnit.SECONDS));
            Intent reply = delivered.get();
            assertNotNull(reply);
            assertEquals(action, reply.getAction());
            assertTrue("Callback discarded the USB permission result extra",
                    reply.hasExtra(UsbManager.EXTRA_PERMISSION_GRANTED));
            assertEquals(granted,
                    reply.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, !granted));
            assertEquals("Callback discarded or replaced the request payload",
                    requestId, reply.getStringExtra(EXTRA_MARKER));
        } finally {
            if (callback != null) callback.cancel();
            context.unregisterReceiver(receiver);
        }
    }
}
