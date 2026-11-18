#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/../../.." && pwd)
test_root="$repo_root/protocol/pake_emv/tests"
build_dir="$repo_root/work/pake-emv-profile-tests"
javac_bin="${JAVA_HOME:+$JAVA_HOME/bin/}javac"
java_bin="${JAVA_HOME:+$JAVA_HOME/bin/}java"
if ! command -v "$javac_bin" >/dev/null 2>&1 && [[ -f /workspace/tooling/env.sh ]]; then
    source /workspace/tooling/env.sh
    javac_bin="$JAVA_HOME/bin/javac"
    java_bin="$JAVA_HOME/bin/java"
fi
mkdir -p "$build_dir/classes"
cc -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$repo_root/protocol/pake_emv" \
    "$repo_root/protocol/pake_emv/pake_emv.c" "$test_root/test_protocol.c" \
    -lcrypto -o "$build_dir/test_protocol"
"$build_dir/test_protocol" > "$build_dir/c-vectors.txt"
"$javac_bin" -d "$build_dir/classes" \
    "$repo_root/PAKEBDH_7816/app/src/main/java/com/example/pakebdh_7816/PakeEmvProtocol.java" \
    "$repo_root/PAKEBDH_7816/tests/PakeEmvProtocolTest.java"
"$java_bin" -cp "$build_dir/classes" com.example.pakebdh_7816.PakeEmvProtocolTest \
    > "$build_dir/java-vectors.txt"
python3 "$test_root/reference_vectors.py" "$test_root/vectors.json" \
    "$build_dir/c-vectors.txt" "$build_dir/java-vectors.txt"
