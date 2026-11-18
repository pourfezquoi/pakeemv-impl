#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
build_dir="$repo_root/work/chic-jni-host"
: "${JAVA_HOME:?Set JAVA_HOME to a JDK before running this test}"
mkdir -p "$build_dir/classes"
cmake -S "$repo_root/third_party/chic" -B "$build_dir/core" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir/core" --target chic_ref -j2
jni_source="$repo_root/PAKEBDH_7816/app/src/main/cpp"
cc -std=c11 -D_GNU_SOURCE -fPIC -shared -Wall -Wextra -Werror \
    -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -I"$repo_root/third_party/chic" \
    "$jni_source/chic_jni.c" "$jni_source/chic_randombytes.c" \
    "$build_dir/core/libchic_ref.a" -o "$build_dir/libchic-jni.so"
cc -std=c11 -D_GNU_SOURCE -fPIC -shared -Wall -Wextra -Werror \
    -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -I"$repo_root/third_party/chic" \
    "$repo_root/PAKEBDH_7816/tests/chic_test_peer.c" "$jni_source/chic_randombytes.c" \
    "$build_dir/core/libchic_ref.a" -o "$build_dir/libchic-test-peer.so"
"$JAVA_HOME/bin/javac" -d "$build_dir/classes" \
    "$repo_root/PAKEBDH_7816/app/src/main/java/com/example/pakebdh_7816/ChicPake.java" \
    "$repo_root/PAKEBDH_7816/tests/ChicJniIntegrationTest.java"
"$JAVA_HOME/bin/java" -Djava.library.path="$build_dir" -cp "$build_dir/classes" \
    com.example.pakebdh_7816.ChicJniIntegrationTest
