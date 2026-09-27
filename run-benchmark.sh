#!/bin/sh
#
# Detection benchmark: recall on attack corpora, false positives on
# benign corpora.  Verifies the >=95% precision/recall targets from
# docs/OPTIMIZATION_PLAN.md.
#
set -e
cd "$(dirname "$0")"
READER=src/reader

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
echo "===================================================================="
