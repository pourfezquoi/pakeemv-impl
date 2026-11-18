#!/usr/bin/env python3
"""Check that both experiments use the same clocks, accounting and transport.

Run from any directory with Python 3. This verifies source parity, not physical
performance. Protocol-specific session, PIN and profile code is tested separately.
"""

from pathlib import Path
import difflib
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
JAVA = Path("app/src/main/java/com/example")
COMMON_JAVA = (
    "TerminalDiagnostics.java",
    "TerminalCpuClock.java",
    "benchmark/ProtocolMeasurements.java",
    "benchmark/BenchmarkSupport.java",
    "benchmark/IsolatedIoExchange.java",
    "benchmark/BenchmarkCsv.java",
    "benchmark/CpuClockProbe.java",
    "apdu/ApduCodec.java",
    "apdu/CcidDescriptor.java",
    "apdu/CcidSlotStatus.java",
    "apdu/T1Channel.java",
    "UsbCcidTransport.java",
)


def normalized(path: Path) -> str:
    text = (path.read_text(encoding="utf-8")
            .replace("pakebdh_7816", "scheme_package")
            .replace("pqbdh_7816", "scheme_package")
            .replace("pakeCycles", "firstPhaseCycles")
            .replace("negotiateKemCycles", "firstPhaseCycles"))
    if path.name == "build.gradle.kts":
        # Versions identify different apps. PAKE's CMake wrapper includes the
        # shared native runtime and adds CHIC. Keep the remaining settings in the diff.
        text = re.sub(r'(?m)^(\s*versionCode = )\d+\s*$', r'\g<1>APP_VERSION_CODE', text)
        text = re.sub(r'(?m)^(\s*versionName = )"[^"\n]+"\s*$', r'\g<1>"APP_VERSION_NAME"', text)
        entry = ("src/main/cpp/CMakeLists.txt" if path.parts[-3] == "PAKEBDH_7816"
                 else "../../BOD_Terminal/app/src/main/cpp/CMakeLists.txt")
        text = text.replace(f'path = file("{entry}")', 'path = file("PROTOCOL_NATIVE_ENTRY")')
    return text


def matching_certificate_fixtures() -> bool:
    card_roots = [ROOT / name for name in ("Card_pakebdh", "Card_armcortex")]
    headers = [(root / "Demo/cert_blobs.h").read_text(encoding="utf-8") for root in card_roots]
    for name in ("certC", "certIS"):
        der = [(root / f"{name}.der").read_bytes() for root in card_roots]
        if der[0] != der[1]:
            return False
        for header, expected in zip(headers, der):
            array = re.search(rf"\b{name}_der\s*\[\s*\d*\s*\]\s*=\s*\{{([^}}]+)\}}", header)
            if array is None:
                return False
            embedded = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})\b", array[1]))
            if embedded != expected:
                return False
    return True


def main() -> int:
    pairs = [
        (ROOT / "PAKEBDH_7816" / JAVA / "pakebdh_7816" / name,
         ROOT / "PQBDH_7816" / JAVA / "pqbdh_7816" / name)
        for name in COMMON_JAVA
    ]
    pairs += [
        (ROOT / "PAKEBDH_7816" / name, ROOT / "PQBDH_7816" / name)
        for name in ("app/build.gradle.kts", "gradle.properties", "gradle/libs.versions.toml",
                     "gradle/wrapper/gradle-wrapper.properties")
    ]
    failed = False
    for left, right in pairs:
        a = normalized(left)
        b = normalized(right)
        if a != b:
            failed = True
            sys.stderr.writelines(difflib.unified_diff(
                a.splitlines(keepends=True), b.splitlines(keepends=True),
                fromfile=str(left.relative_to(ROOT)),
                tofile=str(right.relative_to(ROOT))))

    wrapper = (ROOT / "Card_armcortex/Demo/pq_benchmark.h").read_text(encoding="utf-8")
    if '#include "../../Card_pakebdh/Demo/pake_benchmark.h"' not in wrapper:
        print("PQ firmware must include the shared PAKE DWT/SysTick engine", file=sys.stderr)
        failed = True
    if not matching_certificate_fixtures():
        print("Both firmware projects must embed the same card and issuer DER fixtures.", file=sys.stderr)
        failed = True
    if failed:
        print("Benchmark parity failed; review the differences before comparing results.", file=sys.stderr)
        return 1
    print("PASS: common timing, accounting, transport and Android build settings match.")
    print("PASS: PQ firmware includes the same physical DWT/SysTick timing engine.")
    print("PASS: Both cards embed byte-identical card and issuer certificates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
