#!/bin/sh
# Host correctness checks only; no physical card performance is measured.
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"
compiler=${CC:-cc}
test_dir=$(mktemp -d /tmp/pq-card-tests.XXXXXX)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

# Reuse the original shared engine fixtures instead of maintaining timer forks.
for fixture in test_pake_benchmark test_systick_benchmark; do
    "$compiler" -std=c99 -Wall -Wextra -Werror \
        -fsanitize=undefined -fno-sanitize-recover=all \
        "Card_pakebdh/tests/$fixture.c" -o "$test_dir/$fixture"
    "$test_dir/$fixture"
done

# Exercise the actual PQ dispatcher and linked SysTick vector in all builds.
for mode in disabled dwt systick; do
    benchmark=1
    fallback=0
    if [ "$mode" = disabled ]; then benchmark=0; fi
    if [ "$mode" = systick ]; then fallback=1; fi
    "$compiler" -std=c99 -Wall -Wextra -Werror \
        -Wno-unused-function -Wno-unused-variable -Wno-type-limits \
        -fsanitize=undefined -fno-sanitize-recover=all \
        -DPAKE_EMV_BENCHMARK="$benchmark" \
        -DPAKE_EMV_SYSTICK_BENCHMARK="$fallback" \
        -ICard_armcortex/Demo -ICard_armcortex/Source -ICard_armcortex/Library \
        -ICard_armcortex/ml-kem/h -ICard_armcortex/aes/h \
        Card_armcortex/tests/test_t1_dispatch.c -o "$test_dir/dispatch-$mode"
    "$test_dir/dispatch-$mode"
done
