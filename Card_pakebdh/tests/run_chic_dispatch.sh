#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="$repo_root/work/chic-card-tests"
cmake -S "$repo_root/third_party/chic" -B "$build_dir" -DCMAKE_BUILD_TYPE=Debug
cmake --build "$build_dir" --target chic_ref -j2
cc -std=c99 -Wall -Wextra -Wno-unused-function -Wno-unused-variable \
  -Wno-type-limits -DPAKE_EMV_BENCHMARK=0 \
  -I"$repo_root/Card_pakebdh/Demo" -I"$repo_root/Card_pakebdh/Source" \
  -I"$repo_root/Card_pakebdh/Library" -I"$repo_root/Card_pakebdh/ml-kem/h" \
  -I"$repo_root/Card_pakebdh/aes/h" -I"$repo_root/third_party/chic" \
  "$repo_root/Card_pakebdh/tests/test_chic_dispatch.c" \
  "$repo_root/protocol/pake_emv/pake_emv.c" \
  "$repo_root/Card_pakebdh/Demo/pake_emv_crypto.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/kem.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/indcpa.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/polyvec.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/poly.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/ntt.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/cbd.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/reduce.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/verify.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/fips202.c" \
  "$repo_root/Card_pakebdh/ml-kem/c/symmetric-shake.c" \
  "$build_dir/libchic_ref.a" -lcrypto -o "$build_dir/test_chic_dispatch"
"$build_dir/test_chic_dispatch"
