package com.example.pakebdh_7816;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AlertDialog;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.InputType;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import com.example.pakebdh_7816.benchmark.IsolatedIoExchange;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class MainActivity extends AppCompatActivity {
    private static final int CCID_VENDOR_ID = 0x076B;
    private static final int CCID_PRODUCT_ID = 0x5321;
    private static final String SAVED_RESULT = "measured_result";
    private static final String SAVED_STATUS = "protocol_status";

    private TextView statusText;
    private TextView resultText;
    private Button runButton;
    private Button originalFlowButton;
    private Button connectionCheckButton;
    private Button terminalCheckButton;
    private ScrollView scrollView;
    private volatile UsbCcidTransport activeTransport;
    private volatile boolean destroyed;
    private Thread protocolWorker;
    private AlertDialog pinDialog;
    private PakeEmvSession.KeyRecord transactionKeyRecord;

    private enum Action { BENCHMARK, ORIGINAL_FLOW, CONNECTION_CHECK, TERMINAL_CHECK }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        scrollView = new ScrollView(this);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(20);
        content.setPadding(padding, padding, padding, padding);
        scrollView.addView(content);
        TextView title = new TextView(this);
        title.setText("PAKE-EMV Benchmark");
        title.setTextSize(22);
        title.setTypeface(null, Typeface.BOLD);
        content.addView(title);
        TextView description = new TextView(this);
        description.setText("Terminal and card timing | Bidirectional traffic | Per-phase results");
        description.setPadding(0, dp(8), 0, dp(12));
        content.addView(description);
        runButton = new Button(this);
        runButton.setText("Start test");
        runButton.setOnClickListener(view -> startProtocol());
        content.addView(runButton);
        originalFlowButton = new Button(this);
        originalFlowButton.setText("Run original startup");
        originalFlowButton.setOnClickListener(view -> startAction(Action.ORIGINAL_FLOW));
        content.addView(originalFlowButton);
        connectionCheckButton = new Button(this);
        connectionCheckButton.setText("Check connection");
        connectionCheckButton.setOnClickListener(view -> startAction(Action.CONNECTION_CHECK));
        content.addView(connectionCheckButton);
        terminalCheckButton = new Button(this);
        terminalCheckButton.setText("Check terminal + PIN input");
        terminalCheckButton.setOnClickListener(view -> startAction(Action.TERMINAL_CHECK));
        content.addView(terminalCheckButton);
        resultText = new TextView(this);
        resultText.setTextSize(16);
        resultText.setTextIsSelectable(true);
        resultText.setPadding(0, dp(16), 0, dp(16));
        resultText.setText("No measurement completed yet.");
        content.addView(resultText);
        TextView logTitle = new TextView(this);
        logTitle.setText("Run status");
        logTitle.setTypeface(null, Typeface.BOLD);
        content.addView(logTitle);
        statusText = new TextView(this);
        statusText.setTextSize(14);
        statusText.setTextIsSelectable(true);
        content.addView(statusText);
        setContentView(scrollView);
        if (savedInstanceState == null) {
            updateStatus("Ready. Choose Start test, Run original startup or Check connection.");
        } else {
            String saved = savedInstanceState.getString(SAVED_RESULT, "No measurement completed yet.");
            resultText.setText(saved.startsWith("Measuring") || saved.startsWith("Checking connection")
                    || saved.startsWith("Checking terminal")
                    ? "Previous operation was interrupted. Please run it again." : saved);
            statusText.setText(savedInstanceState.getString(SAVED_STATUS, ""));
            updateStatus("Page restored. Run another test if the previous session was interrupted.");
            runButton.setText("Run again");
        }
    }

    private void startProtocol() {
        startAction(Action.BENCHMARK);
    }

    private void startAction(Action action) {
        if (protocolWorker != null && protocolWorker.isAlive()) return;
        setActionsEnabled(false);
        resultText.setText(action == Action.TERMINAL_CHECK
                ? "Checking terminal and PIN input...\nNo reader, card or authentication is used."
                : action == Action.CONNECTION_CHECK
                ? "Checking connection...\nPublic diagnostic commands only; no protocol measurement."
                : "Measuring...\nConnection, startup and PIN entry are excluded from timing.");
        statusText.setText("");
        protocolWorker = new Thread(() -> runAction(action), "pake-emv-operation");
        protocolWorker.start();
    }

    private void runAction(Action action) {
        if (action == Action.TERMINAL_CHECK) {
            runTerminalCheck();
            return;
        }
        UsbCcidTransport transport = new UsbCcidTransport(getApplicationContext(),
                CCID_VENDOR_ID, CCID_PRODUCT_ID, this::updateStatus);
        activeTransport = transport;
        IsolatedIoExchange io = new IsolatedIoExchange(command -> transport.sendApdu(command, 60000));
        try {
            if (destroyed || Thread.currentThread().isInterrupted()) return;
            TerminalDiagnostics.Snapshot runtime = TerminalDiagnostics.capture(getApplicationContext(), false);
            updateStatus("Run conditions before protocol: " + runtime.brief());
            updateStatus("Connecting to the CCID reader and powering on the card...");
            io.call(() -> {
                if (action == Action.CONNECTION_CHECK) transport.connectForDiagnostics();
                else transport.connect();
                return null;
            });
            if (action == Action.CONNECTION_CHECK) {
                updateStatus("Checking public ECHO/TRACE responses; no PIN, PAKE or card timing commands.");
                String report = PakeEmvDiagnostics.checkConnection(
                        io, this::updateStatus);
                updateStatus(report);
                showResult("Connection diagnostic report\nNo protocol measurement was performed.\n\n" + report);
                updateStatus("Connection check finished. See the individual command responses.");
                return;
            }
            PakeEmvSession.RunMode mode = action == Action.ORIGINAL_FLOW
                    ? PakeEmvSession.RunMode.ORIGINAL_FLOW : PakeEmvSession.RunMode.OPTIONAL_TIMING;
            if (action == Action.ORIGINAL_FLOW) {
                updateStatus("Original flow selected: original startup and C1/B2/50; F8/F7 probes are disabled.");
            }
            TerminalCpuClock clock = TerminalCpuClock.capture();
            updateStatus("CPU clock probe: " + clock.diagnostics());
            retainRecordedKey(null);
            updateStatus("Using the preconfigured reference for the laboratory card.");
            PakeEmvSession.Result result = PakeEmvSession.runTransaction(
                    io, PakeEmvBenchmarkConfig.EXPECTED_PAN, this::promptForPin, clock, mode, this::updateStatus);
            retainRecordedKey(result.recordedKey);
            showResult(PakeEmvResultText.format(result)
                    + "\n\nRUN CONDITIONS (before protocol)\n" + runtime.brief());
            if (!result.accepted) {
                updateStatus("Authentication rejected. " + result.rejectionReason);
            } else {
                updateStatus(!result.total().cpuTimingAvailable
                        ? "Authentication accepted; terminal CPU timing is unavailable."
                        : result.hasCardTiming()
                        ? "Authentication accepted; terminal/card timing and traffic measured."
                        : "Authentication accepted; terminal timing and traffic measured.");
            }
        } catch (Exception | LinkageError failure) {
            Log.e("PQC", "PAKE-EMV operation failed", failure);
            String details = failureText(failure);
            if (failure instanceof PakeEmvSession.FinalOutcomeException) {
                retainRecordedKey(((PakeEmvSession.FinalOutcomeException) failure).recordedKey);
            }
            // Protocol failures never trigger an additional TRACE or other response APDU.
            updateStatus("Operation incomplete: " + failureText(failure));
            showResult((action == Action.CONNECTION_CHECK
                    ? "Connection check did not complete. No protocol measurement was performed.\n"
                    : "This test did not complete; no valid measurement was generated.\n") + details);
        } finally {
            try {
                io.call(() -> { transport.close(); return null; });
            } catch (Exception cleanupFailure) {
                // Closing the USB connection also aborts a transfer interrupted by page destruction.
                transport.close();
            } finally {
                io.close();
            }
            activeTransport = null;
            runOnUiThread(() -> {
                if (destroyed) return;
                runButton.setText("Run again");
                setActionsEnabled(true);
            });
        }
    }

    private void setActionsEnabled(boolean enabled) {
        runButton.setEnabled(enabled);
        originalFlowButton.setEnabled(enabled);
        connectionCheckButton.setEnabled(enabled);
        terminalCheckButton.setEnabled(enabled);
    }

    private void runTerminalCheck() {
        TerminalDiagnostics.Snapshot runtime = null;
        try {
            if (destroyed || Thread.currentThread().isInterrupted()) return;
            updateStatus("Terminal-only diagnostic; no reader/card, authentication or protocol measurement.");
            runtime = TerminalDiagnostics.capture(getApplicationContext(), true);
            updateStatus("Runtime checks complete. Enter any six digits to check input responsiveness; the value is discarded.");
            promptForPin(true);
            showResult("Terminal diagnostic complete\nNo authentication or protocol measurement was performed.\n\n"
                    + runtime.format() + "\nNumeric input accepted and discarded; no PIN value was logged.");
            updateStatus("PIN input check complete. The diagnostic input was discarded.");
        } catch (Exception | LinkageError failure) {
            updateStatus("Terminal check incomplete: " + failureText(failure));
            showResult("Terminal check did not complete. No authentication or protocol measurement was performed.\n"
                    + failureText(failure) + (runtime == null ? "" : "\n\n" + runtime.format()));
        } finally {
            runOnUiThread(() -> {
                if (destroyed) return;
                runButton.setText("Run again");
                setActionsEnabled(true);
            });
        }
    }

    private void showResult(String text) {
        runOnUiThread(() -> {
            if (destroyed) return;
            resultText.setText(text);
            scrollView.post(() -> scrollView.smoothScrollTo(0, 0));
        });
    }

    private static String failureText(Throwable failure) {
        return failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage();
    }

    private synchronized void retainRecordedKey(PakeEmvSession.KeyRecord record) {
        if (transactionKeyRecord != null && transactionKeyRecord != record) transactionKeyRecord.close();
        if (destroyed && record != null) { record.close(); record = null; }
        transactionKeyRecord = record;
    }

    private String promptForPin() throws Exception {
        return promptForPin(false);
    }

    private String promptForPin(boolean inputCheck) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> pin = new AtomicReference<>();
        AtomicReference<Exception> error = new AtomicReference<>();
        runOnUiThread(() -> {
            if (destroyed) {
                error.set(new InterruptedException("Page closed"));
                latch.countDown();
                return;
            }
            EditText input = new EditText(this);
            input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
            input.setHint("Six-digit PIN");
            pinDialog = new AlertDialog.Builder(this)
                    .setTitle(inputCheck ? "PIN input check (no authentication)" : "Enter PIN")
                    .setMessage(inputCheck ? "Enter any six digits. This input is discarded and is not sent to a card." : null)
                    .setView(input)
                    .setCancelable(false)
                    .setPositiveButton("OK", (dialog, which) -> {
                        String value = input.getText().toString().trim();
                        if (!value.matches("[0-9]{6}")) {
                            error.set(new IllegalArgumentException("PIN must contain exactly six digits."));
                        } else {
                            pin.set(value);
                        }
                        pinDialog = null;
                        latch.countDown();
                    })
                    .setNegativeButton("Cancel", (dialog, which) -> {
                        error.set(new IllegalStateException("PIN entry canceled."));
                        pinDialog = null;
                        latch.countDown();
                    }).show();
        });
        latch.await();
        if (error.get() != null) throw error.get();
        return pin.get();
    }

    public void updateStatus(String message) {
        runOnUiThread(() -> {
            if (!destroyed) statusText.append(message + "\n");
        });
    }

    @Override
    protected void onSaveInstanceState(Bundle state) {
        state.putString(SAVED_RESULT, resultText.getText().toString());
        state.putString(SAVED_STATUS, statusText.getText().toString());
        super.onSaveInstanceState(state);
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        if (protocolWorker != null) protocolWorker.interrupt();
        UsbCcidTransport transport = activeTransport;
        if (transport != null) transport.close();
        if (pinDialog != null) pinDialog.dismiss();
        retainRecordedKey(null);
        super.onDestroy();
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
