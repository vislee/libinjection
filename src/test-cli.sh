#!/bin/sh
#
# smoke tests for the unified `injection` CLI
#
set -e
INJ=./injection
fail=0

assert_out() {
    # $1 expected-prefix, $2 exit-code, rest: args
    want_prefix=$1
    want_code=$2
    shift 2
    code=0
    out=$("$INJ" "$@" </dev/null) || code=$?
    if [ "$code" != "$want_code" ]; then
        echo "FAIL: exit code $code != $want_code for: $*" >&2
        fail=1
    fi
    case "$out" in
        "$want_prefix"*) ;;
        *)
            echo "FAIL: got '$out', want prefix '$want_prefix'" >&2
            fail=1
            ;;
    esac
}

assert_out "sqli" 1 '1 union select x--'
assert_out "ssti" 1 '{{7*7}}'
assert_out "ok" 0 'hello world'
assert_out "cmd" 1 -c cmd ';cat /etc/passwd'
assert_out "ok" 0 -c nosql ';cat /etc/passwd'
assert_out "ok" 0 -c cmd,code 'hello'

# decode mode: encoded xss only visible after URL decoding
assert_out "xss" 1 -d '%3Cscript%3Ealert(1)%3C/script%3E'
assert_out "ok" 0 '%3Cscript%3Ealert(1)%3C/script%3E'

# stdin mode
code=0
out=$(printf 'hello\n{{7*7}}\n' | "$INJ" -q) || code=$?
if [ "$code" != "1" ] || [ "$out" != "ssti	{{7*7}}" ]; then
    echo "FAIL: stdin mode got '$out' code=$code" >&2
    fail=1
fi

# json mode
code=0
out=$("$INJ" -j ';cat /etc/passwd') || code=$?
case "$out" in
    '{"input":";cat /etc/passwd","classes":['*']}'*) ;;
    *)
        echo "FAIL: json got '$out'" >&2
        fail=1
        ;;
esac

# fingerprint mode
code=0
out=$("$INJ" -F '1 union select x--') || code=$?
case "$out" in
    sqli*1UEn*) ;;
    *)
        echo "FAIL: fingerprint got '$out'" >&2
        fail=1
        ;;
esac

# unknown class -> exit 2
"$INJ" -c bogus x >/dev/null 2>&1 && { echo "FAIL: bad class should fail" >&2; fail=1; } || true

if [ "$fail" != "0" ]; then
    echo "FAIL: test-cli.sh" >&2
    exit 1
fi
echo "PASS: test-cli.sh"
