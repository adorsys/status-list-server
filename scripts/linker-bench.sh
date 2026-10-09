#!/usr/bin/env bash
# Measure Rust link time for this workspace with each candidate Linux linker.
#
#   scripts/linker-bench.sh [--linkers bfd,lld,mold,wild] [--scenarios LIST]
#                           [--runs N] [--out DIR]
#
# Scenarios (default: all):
#   clean-debug     cargo build --workspace --all-targets --all-features from an
#                   empty target directory (every build script, test and binary)
#   edit-bin        touch src/main.rs, rebuild the server binary (edit-run loop)
#   edit-lib-tests  touch src/lib.rs, rebuild all targets (edit-test loop: relinks
#                   the binary, unit tests and every integration test)
#   clean-release   cargo build --release with the release image feature set
#                   (lto = true, codegen-units = 1, strip = true)
#
# Each candidate builds into its own target directory under --out, so no artifact
# is shared between linkers. The linker is wrapped by a timer, so the report shows
# time spent inside the linker separately from compile time, which dominates the
# wall clock and varies more between runs.
#
# Candidates:
#   bfd   GNU ld. On x86_64 this is the opt-out from Rust's default
#         (-C linker-features=-lld); on other architectures it is the default.
#   lld   On x86_64-unknown-linux-gnu, the rust-lld shipped with the toolchain, which
#         is the default since Rust 1.90. Elsewhere, the system ld.lld (-fuse-ld=lld).
#   mold  mold on PATH (scripts/install-linker.sh mold), driven by cc -fuse-ld=mold.
#   wild  wild on PATH (scripts/install-linker.sh wild), driven by clang --ld-path.
#
# Candidate flags are passed as RUSTFLAGS and replace any inherited value.
# Linux only. Results are written to --out as results.tsv, environment.md and
# summary.md; summary.md is also appended to $GITHUB_STEP_SUMMARY when set.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

LINKERS="bfd,lld,mold,wild"
SCENARIOS="clean-debug,edit-bin,edit-lib-tests,clean-release"
RUNS=5
OUT="target/linker-bench"
KEEP=0
RELEASE_FEATURES=$(sed -nE 's/^ARG FEATURES="([^"]+)".*/\1/p' Dockerfile)

while [ "$#" -gt 0 ]; do
    case "$1" in
        --linkers) LINKERS=${2:?}; shift ;;
        --scenarios) SCENARIOS=${2:?}; shift ;;
        --runs) RUNS=${2:?}; shift ;;
        --out) OUT=${2:?}; shift ;;
        --keep) KEEP=1 ;;
        -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

[ "$(uname -s)" = Linux ] || { echo "linker-bench.sh measures Linux linkers; run it on Linux" >&2; exit 1; }
[[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || { echo "--runs must be a positive integer, got '$RUNS'" >&2; exit 2; }
[ -n "$RELEASE_FEATURES" ] ||{ echo "could not read ARG FEATURES from Dockerfile" >&2; exit 1; }

ARCH=$(uname -m)
HOST=$(rustc -vV | sed -n 's/^host: //p')
HOST_ENV=$(printf '%s' "$HOST" | tr '[:lower:]-' '[:upper:]_')
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
RESULTS="$OUT/results.tsv"
WRAPPER="$OUT/link-timer"

# The timer is the configured linker; it runs the real compiler driver and appends
# "<nanoseconds>\t<exit status>\t<output file>" per link to $LINK_BENCH_LOG.
cat >"$WRAPPER" <<'SH'
#!/usr/bin/env bash
start=$(date +%s%N)
"${LINK_BENCH_CC:-cc}" "$@"
status=$?
end=$(date +%s%N)
output=; previous=
for arg in "$@"; do [ "$previous" = -o ] && output=$arg; previous=$arg; done
printf '%s\t%s\t%s\n' "$((end - start))" "$status" "${output##*/}" >>"$LINK_BENCH_LOG"
exit "$status"
SH
chmod +x "$WRAPPER"

# Sets CANDIDATE_FLAGS (rustflags) and CANDIDATE_CC (compiler driver) for a candidate.
select_candidate() {
    CANDIDATE_CC=cc
    local opt_out=""
    # Only x86_64-unknown-linux-gnu defaults to rust-lld, and only there is the
    # opt-out flag stable; passing it on another target is an error.
    [ "$HOST" = x86_64-unknown-linux-gnu ] && opt_out="-C linker-features=-lld"
    case "$1" in
        bfd) CANDIDATE_FLAGS=$opt_out ;;
        lld)
            CANDIDATE_FLAGS=""
            [ "$HOST" = x86_64-unknown-linux-gnu ] || CANDIDATE_FLAGS="-C link-arg=-fuse-ld=lld"
            ;;
        mold) CANDIDATE_FLAGS="$opt_out -C link-arg=-fuse-ld=mold" ;;
        wild)
            CANDIDATE_CC=clang
            CANDIDATE_FLAGS="$opt_out -C link-arg=--ld-path=$(command -v wild)"
            ;;
        *) echo "unknown linker: $1" >&2; exit 2 ;;
    esac
}

require_candidate() {
    case "$1" in
        lld) [ "$HOST" = x86_64-unknown-linux-gnu ] || command -v ld.lld >/dev/null ;;
        mold) command -v ld.mold >/dev/null ;;
        wild) command -v wild >/dev/null && command -v clang >/dev/null ;;
        *) true ;;
    esac || { echo "linker '$1' is not installed; see scripts/install-linker.sh" >&2; exit 1; }
}

linker_marker() {
    readelf -p .comment "$1" 2>/dev/null |
        grep -oiE 'mold [0-9][^ ]*|Linker: [A-Za-z]+ [0-9][^ )]*|wild[^]]*' | head -n 1 ||
        true
}

now_ns() { date +%s%N; }

# Runs one measured cargo command; appends one row to results.tsv.
measure() {
    local linker=$1 scenario=$2 run=$3
    shift 3
    local log="$OUT/$linker/link-$scenario-$run.log"
    : >"$log"
    local start end
    start=$(now_ns)
    LINK_BENCH_LOG="$log" "$@" >"$OUT/$linker/cargo-$scenario-$run.log" 2>&1 || {
        tail -n 40 "$OUT/$linker/cargo-$scenario-$run.log" >&2
        echo "$linker/$scenario run $run failed" >&2
        return 1
    }
    end=$(now_ns)
    local link_ns links failed
    link_ns=$(awk -F'\t' '{ s += $1 } END { printf "%d", s }' "$log")
    links=$(wc -l <"$log" | tr -d ' ')
    failed=$(awk -F'\t' '$2 != 0' "$log" | wc -l | tr -d ' ')
    [ "$failed" -eq 0 ] || { echo "$linker/$scenario: $failed link(s) failed" >&2; return 1; }
    printf '%s\t%s\t%s\t%d\t%d\t%s\n' "$linker" "$scenario" "$run" \
        "$(((end - start) / 1000000))" "$((link_ns / 1000000))" "$links" | tee -a "$RESULTS"
}

printf 'linker\tscenario\trun\twall_ms\tlink_ms\tlinks\n' >"$RESULTS"
: >"$OUT/markers.tsv"

IFS=, read -r -a linkers <<<"$LINKERS"
IFS=, read -r -a scenarios <<<"$SCENARIOS"
for linker in "${linkers[@]}"; do require_candidate "$linker"; done

for linker in "${linkers[@]}"; do
    select_candidate "$linker"
    mkdir -p "$OUT/$linker"
    target_dir="$OUT/$linker/target"
    rm -rf "$target_dir"
    echo "== $linker: RUSTFLAGS='${CANDIDATE_FLAGS}' driver=$CANDIDATE_CC"

    cargo_env=(
        # RUSTFLAGS, not target.<triple>.rustflags: an inherited RUSTFLAGS (CI's
        # setup-rust-toolchain exports `-D warnings`) replaces every config-file
        # rustflags source, so a lower-precedence setting would be silently dropped
        # and every candidate would measure the default linker.
        env -u CARGO_ENCODED_RUSTFLAGS
        "RUSTFLAGS=$CANDIDATE_FLAGS"
        "CARGO_TARGET_DIR=$target_dir"
        "CARGO_TARGET_${HOST_ENV}_LINKER=$WRAPPER"
        "LINK_BENCH_CC=$CANDIDATE_CC"
        "CARGO_TERM_COLOR=never"
    )
    debug_all=("${cargo_env[@]}" cargo build --locked --workspace --all-targets --all-features)
    debug_bin=("${cargo_env[@]}" cargo build --locked --bin status-list-server --all-features)

    for scenario in "${scenarios[@]}"; do
        case "$scenario" in
            clean-debug) measure "$linker" "$scenario" 1 "${debug_all[@]}" ;;
            edit-bin | edit-lib-tests)
                [ -d "$target_dir/debug" ] || measure "$linker" warmup 1 "${debug_all[@]}"
                file=src/main.rs command=("${debug_bin[@]}")
                [ "$scenario" = edit-lib-tests ] && file=src/lib.rs command=("${debug_all[@]}")
                # One unmeasured run first, so every measured run starts from the same
                # state: incremental caches warm for exactly the touched file.
                touch "$file"
                LINK_BENCH_LOG=/dev/null "${command[@]}" >/dev/null 2>&1
                for run in $(seq 1 "$RUNS"); do
                    touch "$file"
                    measure "$linker" "$scenario" "$run" "${command[@]}"
                done
                ;;
            clean-release)
                measure "$linker" "$scenario" 1 "${cargo_env[@]}" cargo build --locked --release \
                    --bin status-list-server --features "$RELEASE_FEATURES"
                ;;
            *) echo "unknown scenario: $scenario" >&2; exit 2 ;;
        esac
    done

    for profile in debug release; do
        binary="$target_dir/$profile/status-list-server"
        [ -x "$binary" ] || continue
        printf '%s\t%s\t%s\t%s\n' "$linker" "$profile" "$(linker_marker "$binary")" \
            "$(stat -c %s "$binary")" >>"$OUT/markers.tsv"
    done
    [ "$KEEP" = 1 ] || rm -rf "$target_dir"
done

{
    echo "## Environment"
    echo
    echo '```text'
    echo "date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "runner:      ${ImageOS:-local} ${ImageVersion:-}"
    echo "os:          $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "kernel:      $(uname -r) ($ARCH)"
    echo "cpu:         $(nproc) x $(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -n 1)"
    echo "memory:      $(awk '/MemTotal/ { printf "%.1f GiB", $2 / 1048576 }' /proc/meminfo)"
    echo "rustc:       $(rustc -V)"
    echo "cargo:       $(cargo -V)"
    echo "cc:          $(cc --version | head -n 1)"
    echo "GNU ld:      $(ld.bfd --version | head -n 1)"
    if [ "$HOST" = x86_64-unknown-linux-gnu ]; then
        echo "lld:         rust-lld $("$(rustc --print sysroot)/lib/rustlib/$HOST/bin/rust-lld" -flavor gnu --version)"
    else
        echo "lld:         $(ld.lld --version 2>/dev/null || echo 'not installed')"
    fi
    echo "mold:        $(mold --version 2>/dev/null || echo 'not installed')"
    echo "wild:        $(wild --version 2>/dev/null || echo 'not installed')"
    echo "clang:       $(clang --version 2>/dev/null | head -n 1 || echo 'not installed')"
    echo "commit:      $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "runs:        $RUNS per incremental scenario (median reported)"
    echo '```'
} >"$OUT/environment.md"

{
    cat "$OUT/environment.md"
    echo
    echo "## Results"
    echo
    echo "Median wall time and time spent in the linker, in seconds. *Links* is the number"
    echo "of link invocations in one run; *vs bfd* is link-time speed-up over GNU ld."
    echo
    awk -F'\t' -v order="$SCENARIOS" -v linkers="$LINKERS" '
        NR == 1 { next }
        { key = $2 SUBSEP $1; n[key]++; wall[key, n[key]] = $4; link[key, n[key]] = $5; links[key] = $6 }
        function median(arr, key, count,   i, j, t, v) {
            for (i = 1; i <= count; i++) v[i] = arr[key, i]
            for (i = 1; i <= count; i++) for (j = i + 1; j <= count; j++) if (v[j] < v[i]) { t = v[i]; v[i] = v[j]; v[j] = t }
            return count % 2 ? v[(count + 1) / 2] : (v[count / 2] + v[count / 2 + 1]) / 2
        }
        END {
            ns = split(order, sc, ","); nl = split(linkers, ln, ",")
            print "| Scenario | Linker | Wall (s) | Link (s) | Links | Link vs bfd |"
            print "| --- | --- | ---: | ---: | ---: | ---: |"
            for (s = 1; s <= ns; s++) {
                base = ""
                for (l = 1; l <= nl; l++) {
                    key = sc[s] SUBSEP ln[l]
                    if (!(key in n)) continue
                    w = median(wall, key, n[key]) / 1000; k = median(link, key, n[key]) / 1000
                    if (ln[l] == "bfd") base = k
                    ratio = (base != "" && k > 0) ? sprintf("%.2fx", base / k) : "-"
                    printf "| %s | %s | %.1f | %.2f | %d | %s |\n", sc[s], ln[l], w, k, links[key], ratio
                }
            }
        }' "$RESULTS"
    echo
    echo "Linker identification read back from the server binary's \`.comment\` section:"
    echo
    echo "| Linker | Profile | .comment marker | Size (bytes) |"
    echo "| --- | --- | --- | ---: |"
    awk -F'\t' '{ printf "| %s | %s | %s | %s |\n", $1, $2, ($3 == "" ? "(none: GNU ld writes no marker)" : $3), $4 }' "$OUT/markers.tsv"
} >"$OUT/summary.md"

cat "$OUT/summary.md"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$OUT/summary.md" >>"$GITHUB_STEP_SUMMARY"; fi
