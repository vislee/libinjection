#!/bin/sh
#
# Measure line coverage of the library (libinjection_sqli.c,
# libinjection_html5.c, libinjection_xss.c) over the full test
# suite: unit tests, data-driven tests and the sample corpora.
#
# Fails when total line coverage is below 95%.
#
set -e

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

# llvm tools: macOS wraps them in xcrun, Linux installs them directly
if command -v xcrun > /dev/null 2>&1 && xcrun -f llvm-profdata > /dev/null 2>&1; then
    LLVM() { xcrun "$@"; }
else
    LLVM() { "$@"; }
fi

PROFDIR=src/coverage-data
PROFDATA=$ROOT/$PROFDIR/libinjection.profdata
TARGET=95

rm -rf "$ROOT/$PROFDIR"
mkdir -p "$ROOT/$PROFDIR"

echo "== building instrumented binaries"
./configure-coverage.sh

echo "== running test suite"
export LLVM_PROFILE_FILE="$ROOT/$PROFDIR/full-%p.profraw"
(
  cd src
  ./test_unit > /dev/null
  (cd ../tests && find . -name 'test*.txt' | xargs ../src/testdriver -q > /dev/null)
  ./reader -q ../data/sqli-*.txt > /dev/null 2>&1
  ./reader -q -x ../data/xss-*.txt > /dev/null 2>&1
  ./reader -q ../data/false_positives.txt > /dev/null 2>&1
  ./reader -q ../data/redteam-*.txt > /dev/null 2>&1
)

LLVM llvm-profdata merge -sparse "$ROOT/$PROFDIR"/full-*.profraw \
    -o "$PROFDATA"

COVERAGE_SOURCES="src/libinjection_sqli.c src/libinjection_html5.c src/libinjection_xss.c src/libinjection_normalize.c src/libinjection_classify.c src/libinjection_trav.c src/libinjection_ssrf.c src/libinjection_deser.c src/libinjection_crlf.c src/libinjection_cmd.c src/libinjection_ssti.c src/libinjection_nosql.c src/libinjection_ldap.c src/libinjection_code.c src/libinjection_recon.c src/libinjection_redirect.c"

echo "== coverage report (library sources)"
LLVM llvm-cov report src/test_unit -instr-profile="$PROFDATA" \
    $COVERAGE_SOURCES

TOTAL=$(LLVM llvm-cov report src/test_unit -instr-profile="$PROFDATA" \
    $COVERAGE_SOURCES \
    | awk '/^TOTAL/ {print $10}')

# emit an annotated copy for uncovered-code analysis
LLVM llvm-cov show src/test_unit -instr-profile="$PROFDATA" \
    $COVERAGE_SOURCES \
    > "$ROOT/$PROFDIR/coverage-show.txt" 2>/dev/null || true

echo
echo "Total line coverage: $TOTAL (target: $TARGET%)"

if [ "$TOTAL" = "" ]; then
  echo "ERROR: could not parse coverage total" >&2
  exit 1
fi

passing=$(awk -v t="$TOTAL" -v g="$TARGET" 'BEGIN {print (t+0 >= g+0) ? 1 : 0}')
if [ "$passing" != "1" ]; then
  echo "FAIL: coverage $TOTAL% is below target $TARGET%" >&2
  exit 1
fi
echo "PASS: coverage meets target"
