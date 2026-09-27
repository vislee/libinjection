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

xcrun llvm-profdata merge -sparse "$ROOT/$PROFDIR"/full-*.profraw \
    -o "$PROFDATA"

echo "== coverage report (library sources)"
xcrun llvm-cov report src/test_unit -instr-profile="$PROFDATA" \
    src/libinjection_sqli.c src/libinjection_html5.c src/libinjection_xss.c src/libinjection_normalize.c src/libinjection_classify.c src/libinjection_trav.c src/libinjection_ssrf.c src/libinjection_deser.c src/libinjection_crlf.c src/libinjection_cmd.c src/libinjection_ssti.c src/libinjection_nosql.c src/libinjection_ldap.c src/libinjection_code.c

TOTAL=$(xcrun llvm-cov report src/test_unit -instr-profile="$PROFDATA" \
    src/libinjection_sqli.c src/libinjection_html5.c src/libinjection_xss.c src/libinjection_normalize.c src/libinjection_classify.c src/libinjection_trav.c src/libinjection_ssrf.c src/libinjection_deser.c src/libinjection_crlf.c src/libinjection_cmd.c src/libinjection_ssti.c src/libinjection_nosql.c src/libinjection_ldap.c src/libinjection_code.c \
    | awk '/^TOTAL/ {print $10}')

# emit an annotated copy for uncovered-code analysis
xcrun llvm-cov show src/test_unit -instr-profile="$PROFDATA" \
    src/libinjection_sqli.c src/libinjection_html5.c src/libinjection_xss.c src/libinjection_normalize.c src/libinjection_classify.c src/libinjection_trav.c src/libinjection_ssrf.c src/libinjection_deser.c src/libinjection_crlf.c src/libinjection_cmd.c src/libinjection_ssti.c src/libinjection_nosql.c src/libinjection_ldap.c src/libinjection_code.c \
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
