#!/bin/sh
#
# Fetch the public datasets used by scripts/eval_public_datasets.py.
# Downloads into /tmp/public-datasets (not the repo: the CSIC files
# are ~36MB).
#
set -e
DS=${1:-/tmp/public-datasets}
mkdir -p "$DS"
cd "$DS"

clone() {
    [ -d "$2" ] || git clone -q --depth 1 "https://github.com/$1" "$2"
}

clone payload-box/sql-injection-payload-list sql-injection-payload-list
clone payload-box/xss-payload-list        xss-payload-list
clone RenwaX23/XSS-Payloads               XSS-Payloads
clone Monkey-D-Groot/Machine-Learning-on-CSIC-2010 csic

for f in Generic-SQLi.txt quick-SQLi.txt sqli.auth.bypass.txt \
         SQLi-Polyglots.txt MySQL-SQLi-Login-Bypass.fuzzdb.txt; do
    if [ ! -s "seclists-sqli-$f" ]; then
        curl -sS --max-time 60 -o "seclists-sqli-$f" \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/$f"
    fi
done

if [ ! -s "seclists-trav-LFI-Jhaddix.txt" ]; then
    curl -sS --max-time 60 -o "seclists-trav-LFI-Jhaddix.txt" \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt"
fi


fetch_seclists() {
    # $1 remote name, $2 local name
    if [ ! -s "$2" ]; then
        curl -sS --max-time 60 -o "$2" \
            "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Fuzzing/$1" \
        || curl -sS --max-time 60 -o "$2" \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/$1" \
        || rm -f "$2"
    fi
}

fetch_seclists command-injection-commix.txt seclists-cmd-commix.txt
fetch_seclists template-engines-special-vars.txt seclists-ssti-special-vars.txt
fetch_seclists template-engines-expression.txt seclists-ssti-expressions.txt
fetch_seclists Databases/SQLi/NoSQL.txt seclists-nosql.txt

J="https://cdn.jsdelivr.net/gh/swisskyrepo/PayloadsAllTheThings@master"
[ -s "pat-ldap-fuzz.txt" ] || curl -sS --max-time 60 -o pat-ldap-fuzz.txt \
    "$J/LDAP%20Injection/Intruder/LDAP_FUZZ.txt" || true
[ -s "pat-ssrf-cloud.md" ] || curl -sS --max-time 60 -o pat-ssrf-cloud.md \
    "$J/Server%20Side%20Request%20Forgery/SSRF-Cloud-Instances.md" || true
[ -s "pat-crlf-readme.md" ] || curl -sS --max-time 60 -o pat-crlf-readme.md \
    "$J/CRLF%20Injection/README.md" || true
[ -s "log4j-scan.py" ] || curl -sS --max-time 60 -o log4j-scan.py \
    "https://cdn.jsdelivr.net/gh/fullhunt/log4j-scan@master/log4j-scan.py" || true

python3 "$(dirname "$0")/extract_public_payloads.py" fencedjoin pat-crlf-readme.md pat-crlf.txt || true
python3 "$(dirname "$0")/extract_public_payloads.py" fenced pat-ssrf-cloud.md pat-ssrf-cloud.txt || true
python3 "$(dirname "$0")/extract_public_payloads.py" pyjndi log4j-scan.py log4j-payloads.txt || true

echo "datasets ready under $DS"
