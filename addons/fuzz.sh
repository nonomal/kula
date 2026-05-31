#!/usr/bin/env bash
# addons/fuzz.sh — Run Go's native fuzzing engine against every Fuzz* target.
#
# Go can only *actively* fuzz one target per `go test` invocation, so this
# discovers all FuzzXxx functions across the module and runs them one at a time.
# (Each target's committed seed corpus already runs under plain `go test` and
# addons/check.sh — this script does the mutation-based fuzzing that hunts for
# new crashers.)
#
# Usage:
#   bash addons/fuzz.sh [options] [duration] [filter]
#
# Options:
#   -t DURATION   Time to fuzz each target (default: 30s). Same as the bare
#                 duration positional arg.
#   -r            Run with the race detector (slower, finds data races).
#   -l            List the discovered fuzz targets and exit.
#   -h            Show this help.
#
# Positional args (order-independent):
#   duration      Anything matching <n>[s|m|h] sets the per-target fuzz time.
#   filter        Any other word is a regexp; only targets whose "pkg Name"
#                 matches are run (e.g. "Decode", "web", "ValidateOrigin").
#
# Examples:
#   bash addons/fuzz.sh                 # 30s per target, all targets
#   bash addons/fuzz.sh 2m              # 2 minutes per target
#   bash addons/fuzz.sh 1m Decode       # only targets matching "Decode", 1m each
#   bash addons/fuzz.sh -r 1m           # 1m each, with the race detector
#   bash addons/fuzz.sh -l              # just list the targets
#
# Crashers found by a run are written by Go to the package's
# testdata/fuzz/<FuzzName>/ directory; commit them — they then run on every
# `go test` as permanent regression seeds. The growing corpus of "interesting"
# inputs lives in $GOCACHE/fuzz and is NOT added to the repo.

set -euo pipefail

# ── defaults ─────────────────────────────────────────────────────────────────
FUZZTIME="30s"
FILTER=""
RACE=""
LIST_ONLY=0

# ── colours ──────────────────────────────────────────────────────────────────
BOLD="\033[1m"
DIM="\033[2m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

usage() { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'; }

# ── parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) FUZZTIME="$2"; shift 2 ;;
        -r) RACE="-race"; shift ;;
        -l) LIST_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            if [[ "$1" =~ ^[0-9]+(\.[0-9]+)?(s|m|h)$ ]]; then
                FUZZTIME="$1"
            else
                FILTER="$1"
            fi
            shift
            ;;
    esac
done

cd "$(dirname "$0")/.."

# ── discover fuzz targets ────────────────────────────────────────────────────
# `go test -list` prints matching function names for each package followed by
# its "ok <pkg>" summary line. Buffer the names and attribute them to the
# package named on the next ok line. A build failure here aborts (set -e), with
# the compiler error left visible on stderr.
echo -e "${CYAN}Discovering fuzz targets...${RESET}"
LIST="$(go test -list '^Fuzz' ./...)"
PAIRS="$(awk '
    /^ok[ \t]/ { for (i = 1; i <= n; i++) print $2 "\t" buf[i]; n = 0; next }
    /^Fuzz/    { buf[++n] = $1 }
' <<<"$LIST")"

declare -a TARGETS=()
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ -n "$FILTER" ]] && ! [[ "$line" =~ $FILTER ]]; then
        continue
    fi
    TARGETS+=("$line")
done <<<"$PAIRS"

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    if [[ -n "$FILTER" ]]; then
        echo -e "${RED}No fuzz targets match filter '${FILTER}'.${RESET}" >&2
    else
        echo -e "${RED}No fuzz targets found.${RESET}" >&2
    fi
    exit 1
fi

echo -e "${DIM}Found ${#TARGETS[@]} target(s):${RESET}"
for line in "${TARGETS[@]}"; do
    printf "  %b%s%b  %s\n" "$BOLD" "${line##*$'\t'}" "$RESET" "${line%%$'\t'*}"
done

if [[ "$LIST_ONLY" -eq 1 ]]; then
    exit 0
fi

# ── run ──────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}Fuzzing ${#TARGETS[@]} target(s), ${FUZZTIME} each${RACE:+ (race detector on)}...${RESET}"

fail=0
declare -a FAILED=()
i=0
total=${#TARGETS[@]}

for line in "${TARGETS[@]}"; do
    pkg="${line%%$'\t'*}"
    name="${line##*$'\t'}"
    i=$((i + 1))

    echo -e "\n${CYAN}[${i}/${total}] ${BOLD}${name}${RESET}${CYAN} — ${pkg}${RESET}"
    start=$(date +%s)
    # -run '^$' skips the package's unit tests so only the fuzz target runs.
    if go test ${RACE} "$pkg" -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME"; then
        echo -e "${GREEN}  ✓ ${name} survived ${FUZZTIME} ($(( $(date +%s) - start ))s)${RESET}"
    else
        echo -e "${RED}  ✗ ${name} FAILED — see the crasher under ${pkg#kula/}/testdata/fuzz/${name}/${RESET}"
        fail=$((fail + 1))
        FAILED+=("$name")
    fi
done

# ── summary ──────────────────────────────────────────────────────────────────
if [[ "$fail" -eq 0 ]]; then
    echo -e "\n🎉 All ${total} fuzz targets ${GREEN}passed${RESET} (${FUZZTIME} each)."
else
    echo -e "\n❌ ${fail}/${total} fuzz targets ${RED}failed${RESET}: ${FAILED[*]}"
    echo -e "${YELLOW}Re-run a single crasher with:${RESET} go test ./<pkg>/ -run '^${FAILED[0]}\$'"
    exit 1
fi
