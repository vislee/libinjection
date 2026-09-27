#!/bin/sh
#
# Detection benchmark: recall on attack corpora, false positives on
# benign corpora.  Verifies the >=95% precision/recall targets from
# docs/OPTIMIZATION_PLAN.md.
#
# With --check, exits non-zero when any release gate is violated
# (used by CI; mirrors docs/RELEASE_GATES.md).
#
set -e
cd "$(dirname "$0")"
READER=src/reader

CHECK=0
if [ "${1:-}" = "--check" ]; then
    CHECK=1
fi

GATE_FAIL=0

gate_recall() {
    label=$1
    minrate=$2
    shift 2
    res=$(counts "$@")
    det=${res%% *}
    tot=${res##* }
    if [ "$tot" -eq 0 ]; then
        echo "GATE FAIL: no samples for '$label'" >&2
        GATE_FAIL=1
        return
    fi
    rate=$(awk -v a="$det" -v t="$tot" 'BEGIN {printf "%.2f", 100*a/t}')
    ok=$(awk -v r="$rate" -v m="$minrate" 'BEGIN {print (r+0 >= m+0) ? 1 : 0}')
    if [ "$ok" -eq 1 ]; then
        printf "GATE ok   %-38s %s%% (>= %s%%)\n" "$label" "$rate" "$minrate"
    else
        printf "GATE FAIL %-38s %s%% (>= %s%%)\n" "$label" "$rate" "$minrate" >&2
        GATE_FAIL=1
    fi
}

gate_fp() {
    label=$1
    maxfp=$2
    shift 2
    res=$(counts "$@")
    det=${res%% *}
    tot=${res##* }
    if [ "$det" -gt "$maxfp" ]; then
        printf "GATE FAIL %-38s %s FP (<= %s)\n" "$label" "$det" "$maxfp" >&2
        GATE_FAIL=1
    else
        printf "GATE ok   %-38s %s FP (<= %s)\n" "$label" "$det" "$maxfp"
    fi
}

# counts READER-ARGS... : prints "detected total" from reader stats
counts() {
    out=$($READER "$@" 2>/dev/null | grep -E '^(SQLI|SAFE)  :' | tr -dc '0-9\n')
    sqli=$(echo "$out" | sed -n 's/^\([0-9]*\).*/\1/p' | head -1)
    safe=$(echo "$out" | sed -n '2p')
    echo "$sqli $((sqli + safe))"
}

row() {
    label=$1
    shift
    res=$(counts "$@")
    det=${res%% *}
    tot=${res##* }
    miss=$((tot - det))
    if [ "$tot" -gt 0 ]; then
        rate=$(awk -v a="$det" -v t="$tot" 'BEGIN {printf "%.2f", 100*a/t}')
    else
        rate="n/a"
        echo "ERROR: no samples for '$label'" >&2
        exit 1
    fi
    printf "%-42s %9d %8d %8d %9s%%\n" "$label" "$det" "$miss" "$tot" "$rate"
}

echo "===================================================================="
echo "corpus                                 detected   missed    total    rate"
echo "--------------------------------------------------------------------"
row "SQLi recall: official corpus"   -i -m 999999 data/sqli-*.txt
row "XSS recall:  official corpus"   -i -m 999999 -x data/xss-*.txt
row "SQLi recall: red-team corpus"   data/redteam-sqli.txt
row "XSS recall:  red-team corpus"   -x data/redteam-xss.txt
row "TRAV recall: red-team corpus"   --trav data/redteam-trav.txt
row "SSRF recall: red-team corpus"   --ssrf data/redteam-ssrf.txt
row "DESER recall: red-team corpus"  --deser data/redteam-deser.txt
row "CRLF recall: red-team corpus"   --crlf data/redteam-crlf.txt
row "CMD recall: red-team corpus"    --cmd data/redteam-cmd.txt
row "SSTI recall: red-team corpus"   --ssti data/redteam-ssti.txt
row "NOSQL recall: red-team corpus"  --nosql data/redteam-nosql.txt
row "LDAP recall: red-team corpus"   --ldap data/redteam-ldap.txt
row "CODE recall: red-team corpus"   --code data/redteam-code.txt
row "RECON recall: red-team corpus"  --recon data/redteam-recon.txt
row "REDIRECT recall: red-team corpus" --redirect data/redteam-redirect.txt
echo "--------------------------------------------------------------------"
echo "benign corpus                          detected  benign    total  FP-rate"
echo "--------------------------------------------------------------------"

fp_row() {
    label=$1
    shift
    res=$(counts "$@")
    det=${res%% *}
    tot=${res##* }
    if [ "$tot" -gt 0 ]; then
        rate=$(awk -v a="$det" -v t="$tot" 'BEGIN {printf "%.2f", 100*a/t}')
        printf "%-42s %9d %8d %8d %9s%%\n" "$label" "$det" "$((tot - det))" "$tot" "$rate"
    fi
}
fp_row "SQLi FP: false_positives.txt"    data/false_positives.txt
fp_row "XSS FP:  false_positives.txt"    -x data/false_positives.txt
fp_row "SQLi FP: redteam-benign.txt"     data/redteam-benign.txt
fp_row "XSS FP:  redteam-benign.txt"     -x data/redteam-benign.txt
fp_row "TRAV FP: benign-p1.txt"          --trav data/benign-p1.txt
fp_row "SSRF FP: benign-p1.txt"          --ssrf data/benign-p1.txt
fp_row "DESER FP: benign-p1.txt"         --deser data/benign-p1.txt
fp_row "CRLF FP: benign-p1.txt"          --crlf data/benign-p1.txt
fp_row "CMD FP: benign-p23.txt"          --cmd data/benign-p23.txt
fp_row "SSTI FP: benign-p23.txt"         --ssti data/benign-p23.txt
fp_row "NOSQL FP: benign-p23.txt"        --nosql data/benign-p23.txt
fp_row "LDAP FP: benign-p23.txt"         --ldap data/benign-p23.txt
fp_row "CODE FP: benign-p23.txt"         --code data/benign-p23.txt
fp_row "RECON FP: benign-p23.txt"        --recon data/benign-p23.txt
fp_row "REDIRECT FP: benign-p23.txt"     --redirect data/benign-p23.txt
fp_row "RECON FP: false_positives.txt"   --recon data/false_positives.txt
fp_row "RECON FP: benign-recon.txt"      --recon data/benign-recon.txt
fp_row "REDIRECT FP: benign-redirect.txt" --redirect data/benign-redirect.txt
echo "===================================================================="

if [ "$CHECK" -eq 1 ]; then
    echo ""
    echo "release gates (docs/RELEASE_GATES.md):"
    gate_recall "sqli official recall"      99.5  -i -m 999999 data/sqli-*.txt
    gate_recall "xss official recall"       98.0  -i -m 999999 -x data/xss-*.txt
    gate_recall "redteam sqli recall"       95.0  data/redteam-sqli.txt
    gate_recall "redteam xss recall"        99.0  -x data/redteam-xss.txt
    gate_recall "redteam trav recall"       100   --trav  data/redteam-trav.txt
    gate_recall "redteam ssrf recall"       100   --ssrf  data/redteam-ssrf.txt
    gate_recall "redteam deser recall"      100   --deser data/redteam-deser.txt
    gate_recall "redteam crlf recall"       100   --crlf  data/redteam-crlf.txt
    gate_recall "redteam cmd recall"        100   --cmd   data/redteam-cmd.txt
    gate_recall "redteam ssti recall"       100   --ssti  data/redteam-ssti.txt
    gate_recall "redteam nosql recall"      100   --nosql data/redteam-nosql.txt
    gate_recall "redteam ldap recall"       100   --ldap  data/redteam-ldap.txt
    gate_recall "redteam code recall"       100   --code  data/redteam-code.txt
    gate_recall "redteam recon recall"      100   --recon data/redteam-recon.txt
    gate_recall "redteam redirect recall"   100   --redirect data/redteam-redirect.txt
    gate_fp "sqli fp corpus"                17    data/false_positives.txt
    gate_fp "redteam-benign (all classes)"  0     data/redteam-benign.txt
    gate_fp "benign-p1"                     0     data/benign-p1.txt
    gate_fp "benign-p23"                    0     data/benign-p23.txt
    gate_fp "benign-recon"                  0     --recon data/benign-recon.txt
    gate_fp "benign-redirect"               0     --redirect data/benign-redirect.txt
    if [ "$GATE_FAIL" -ne 0 ]; then
        echo "RELEASE GATES: FAILED" >&2
        exit 1
    fi
    echo "RELEASE GATES: PASSED"
fi
