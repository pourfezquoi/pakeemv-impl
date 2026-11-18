# PAKE-EMV and PQ-BDH prototypes

This package contains the implementations for *Strengthening EMV Channel
Establishment by Integrating PIN Authentication into the Initial Key Exchange*.
The PQ-BDH baseline follows Figure 4 of Bettale, De Oliveira, and Dottax,
*Post-Quantum Protocols for Banking Applications* (CARDIS 2022), with the
separate encrypted PIN verification included in the measurements.

## Contents

| Directory | Contents |
| --- | --- |
| `PAKEBDH_7816/`, `PQBDH_7816/` | Android terminal applications and benchmarks |
| `Card_pakebdh/`, `Card_armcortex/` | Corresponding smart-card firmware and Keil projects |
| `protocol/pake_emv/` | PAKE-EMV encodings, key derivation, and tests |
| `third_party/chic/` | Pinned CHIC reference implementation and tests |
| `BOD_Terminal/app/src/main/cpp/` | Shared JNI and liboqs sources |
| `third_party/card_sdk_notices/` | Card SDK attribution |

Keep this directory structure unchanged.

## Build and run

The testbed uses an HSCTU SC300 board at 105 MHz, a USB contact reader, and
an Android terminal. The reader must be accessible to Android, including
through USB passthrough when using a virtual device.

1. Install Keil uVision 5, Arm Compiler 6.22, and `ARM.Cortex_DFP.1.1.0`.
   Open the corresponding card's `HSCTU_SCard_Demo.uvprojx`, select **Debug**,
   run **Rebuild all target files**, and program the board using
   **Flash > Download** with the board's programming interface configured.
   The project enables `PAKE_EMV_BENCHMARK=1` and
   `PAKE_EMV_SYSTICK_BENCHMARK=1`; firmware outputs are in `Build/Debug/`.
2. Install Gradle 8.13, JDK 21, Android SDK 36, Android NDK, and CMake 3.22.1
   or later.
   Configure `JAVA_HOME`, `ANDROID_HOME`, and the tools on `PATH`.
   With the terminal connected through ADB, run `gradle :app:installDebug`
   from the corresponding Android project directory.
3. Connect the reader, launch the application, select **Start test**, and enter
   the public test PIN `123456`.

## Measurements

Flash the matching card firmware before each experiment. Keep both terminal
builds in Debug and the card clock at 105 MHz; do not pause or single-step the
card during measurement. Grant Android USB permission before running the batch.

Run the following from the package root using Bash. Each batch performs 20
warm-up sessions followed by 50 measured sessions.

```bash
gradle -p PAKEBDH_7816 --no-daemon --max-workers=2 :app:connectedDebugAndroidTest \
  -Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true \
  -Pandroid.testInstrumentationRunnerArguments.class=com.example.pakebdh_7816.PakeEmvBenchmarkTest \
  -Pandroid.testInstrumentationRunnerArguments.runPakeEmvBenchmark=true \
  -Pandroid.testInstrumentationRunnerArguments.benchmarkWarmup=20 \
  -Pandroid.testInstrumentationRunnerArguments.benchmarkSamples=50

gradle -p PQBDH_7816 --no-daemon --max-workers=2 :app:connectedDebugAndroidTest \
  -Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true \
  -Pandroid.testInstrumentationRunnerArguments.class=com.example.pqbdh_7816.PqBdhBenchmarkTest \
  -Pandroid.testInstrumentationRunnerArguments.runPqBdhBenchmark=true \
  -Pandroid.testInstrumentationRunnerArguments.benchmarkIncludePin=true \
  -Pandroid.testInstrumentationRunnerArguments.benchmarkWarmup=20 \
  -Pandroid.testInstrumentationRunnerArguments.benchmarkSamples=50
```

Each run saves `samples.csv`, `summary.csv`, and `metadata.json`. Keep the apps
installed and export the reports with the following commands. On Windows, use
Command Prompt or Git Bash for binary redirection.

```sh
adb exec-out run-as com.example.pakebdh_7816 tar -C files -cf - pake-emv-benchmark > pake-emv-benchmark.tar
adb exec-out run-as com.example.pqbdh_7816 tar -C files -cf - pq-bdh-benchmark > pq-bdh-benchmark.tar
```

Extract the archives to access the per-run reports. Compare PAKE-EMV's `total`
with PQ-BDH's `authenticated_total`, which includes its separate PIN check.
Both measurements end before transaction authorization and exclude GenerateAC.

Third-party licenses and source provenance are retained in their respective
directories.
