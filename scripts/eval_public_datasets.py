#!/usr/bin/env python3
"""
Evaluate libinjection against PUBLIC datasets.

Corpora (see scripts/fetch_public_datasets.sh):
  SQLi attacks
    - payload-box/sql-injection-payload-list   (mysql/mssql/oracle/postgresql/sqlite/burp)
    - SecLists Fuzzing/Databases/SQLi          (5 curated files)
    - HTTP CSIC 2010 anomalousTrafficTest.txt  (attack HTTP requests, subset is SQLi)
  XSS attacks
    - payload-box/xss-payload-list All-In-One.txt
    - RenwaX23/XSS-Payloads Payloads.txt
    - HTTP CSIC 2010 anomalousTrafficTest.txt  (subset is XSS)
  Benign
    - HTTP CSIC 2010 normalTrafficTraining.txt (normal HTTP requests)

Both the optimized working tree binary and a pristine HEAD (baseline)
binary are evaluated on identical normalized corpora, so the table is
a true before/after comparison.

Usage: scripts/eval_public_datasets.py [--datasets DIR] [--baseline BIN] [--optimized BIN]
"""

import argparse
import glob
import os
import subprocess
import sys
import tempfile
import urllib.parse

TRAVERSAL_FILES = [
    "seclists-trav-LFI-Jhaddix.txt",
]

CMD_FILES = ["seclists-cmd-commix.txt"]
SSTI_FILES = ["seclists-ssti-expressions.txt"]
NOSQL_FILES = ["seclists-nosql.txt"]
LDAP_FILES = ["pat-ldap-fuzz.txt"]
SSRF_FILES = ["pat-ssrf-cloud.txt"]
DESER_FILES = ["log4j-payloads.txt"]
CRLF_FILES = ["pat-crlf.txt"]
# identification dictionary: the file itself says to wrap each term in
# the engine's expression syntax ({{ ... }})
SSTI_WRAP_FILES = ["seclists-ssti-special-vars.txt"]

SQLI_FILES = [
    "sql-injection-payload-list/mysql-payloads.txt",
    "sql-injection-payload-list/mssql-payloads.txt",
    "sql-injection-payload-list/oracle-payloads.txt",
    "sql-injection-payload-list/postgresql-payloads.txt",
    "sql-injection-payload-list/sqlite-payloads.txt",
    "sql-injection-payload-list/burp-intruder-payloads.txt",
    "seclists-sqli-Generic-SQLi.txt",
    "seclists-sqli-quick-SQLi.txt",
    "seclists-sqli-sqli.auth.bypass.txt",
    "seclists-sqli-SQLi-Polyglots.txt",
    "seclists-sqli-MySQL-SQLi-Login-Bypass.fuzzdb.txt",
]

XSS_FILES = [
    "xss-payload-list/Payloads/All-In-One.txt",
    "XSS-Payloads/Payloads.txt",
]

SQL_MARKERS = [
    "' or '", "or 1=1", "' and ", "union select", "union all select",
    "select ", "insert ", "drop table", "drop database", "update set",
    "waitfor delay", "benchmark(", "sleep(", "load_file", "into outfile",
    "information_schema", "concat(", "xp_cmdshell", "'--", "';", "1=1",
]

XSS_MARKERS = [
    "<script", "onerror", "onload", "onmouseover", "javascript:",
    "alert(", "prompt(", "confirm(", "<img", "<svg", "<iframe", "<embed",
    "<body", "<video", "<object", "expression(", "vbscript:",
]

OTHER_MARKERS = [
    "../", "..%2f", "..\\", "%2e%2e", "/etc/passwd", "cmd.exe", "boot.ini",
    "win.ini", "http://", "https://", "~", "%00", ".exe", "nc -l",
]


def load_payload_file(path):
    """Plain payload list: skip blanks, '#' comments and separators."""
    items = []
    seen = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            s = line.strip()
            if not s or s.startswith("#") or set(s) in ({"-"}, {"="}, {"#"}):
                continue
            if line not in seen:
                seen.add(line)
                items.append(line)
    return items


def extract_csic(path, max_len=8192):
    """Extract GET request-targets (path?query, host stripped)."""
    items = []
    with open(path, encoding="latin-1") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if line.startswith("GET ") or line.startswith("POST "):
                parts = line.split()
                if len(parts) < 2:
                    continue
                uri = parts[1]
                if "://" in uri:
                    uri = uri.split("://", 1)[1]
                    uri = uri[uri.find("/"):] if "/" in uri else "/"
                if len(uri) <= max_len:
                    items.append(uri)
    return items


def classify_csic(line):
    """Rough ground-truth buckets for CSIC anomalous requests."""
    q = urllib.parse.unquote_plus(line).lower()
    if any(m in q for m in SQL_MARKERS):
        return "sqli"
    if any(m in q for m in XSS_MARKERS):
        return "xss"
    if any(m in q for m in OTHER_MARKERS):
        return "other-attack"
    return "ambiguous"


# reader flags per class; baseline 3.9.2 only knows sqli/xss
MODE_FLAGS = {
    "sqli": [],
    "xss": ["-x"],
    "trav": ["--trav"],
    "cmd": ["--cmd"],
    "ssti": ["--ssti"],
    "nosql": ["--nosql"],
    "ldap": ["--ldap"],
    "code": ["--code"],
    "ssrf": ["--ssrf"],
    "deser": ["--deser"],
    "crlf": ["--crlf"],
}
BASELINE_MODES = {"sqli", "xss"}


def run_reader(reader_bin, corpus_path, mode="sqli"):
    """Return (detected, total, missed_payloads)."""
    with open(corpus_path, "rb") as fh:
        content = fh.read()
    cmd = [reader_bin] + MODE_FLAGS.get(mode, []) + [corpus_path]
    proc = subprocess.run(cmd, input=content, capture_output=True, timeout=900)
    lines = proc.stdout.decode("utf-8", errors="replace").splitlines()
    detected = 0
    total = 0
    missed = []
    payload_col = 4 if mode == "sqli" else 3
    for row in lines:
        cols = row.split("\t")
        if len(cols) < 3 or cols[2] not in ("True", "False"):
            continue
        total += 1
        if cols[2] == "True":
            detected += 1
        else:
            missed.append(cols[payload_col] if len(cols) > payload_col else "")
    return detected, total, missed


def write_corpus(items, path):
    with open(path, "w", encoding="utf-8") as fh:
        for item in items:
            fh.write(item + "\n")


def corpus_mode(label):
    """detection mode for a corpus label"""
    if label.startswith("xss:") or label == "csic2010-xss":
        return "xss"
    if label.startswith("trav:") or label == "csic2010-other-attack":
        return "trav"
    if label.startswith("cmd:"):
        return "cmd"
    if label.startswith("ssti:"):
        return "ssti"
    if label.startswith("nosql:"):
        return "nosql"
    if label.startswith("ldap:"):
        return "ldap"
    if label.startswith("code:"):
        return "code"
    if label.startswith("ssrf:"):
        return "ssrf"
    if label.startswith("deser:"):
        return "deser"
    if label.startswith("crlf:"):
        return "crlf"
    if label == "csic2010-sqli" or label.startswith("sqli:") or \
            label.startswith("benign:"):
        return "sqli"
    return "sqli"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", default="/tmp/public-datasets")
    ap.add_argument("--baseline", default="/tmp/libinj-baseline/src/reader")
    ap.add_argument("--optimized", default="src/reader")
    args = ap.parse_args()

    ds = args.datasets
    corpora = []  # (label, items)

    for rel in SQLI_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("sqli:" + os.path.basename(rel), load_payload_file(p)))
    for rel in XSS_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("xss:" + os.path.basename(rel), load_payload_file(p)))
    for rel in TRAVERSAL_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("trav:" + os.path.basename(rel), load_payload_file(p)))
    for rel in CMD_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("cmd:" + os.path.basename(rel), load_payload_file(p)))
    for rel in SSTI_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("ssti:" + os.path.basename(rel), load_payload_file(p)))
    for rel in SSTI_WRAP_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            wrapped = ["{{%s}}" % x for x in load_payload_file(p)]
            corpora.append(("ssti:" + os.path.basename(rel) + "[wrapped]", wrapped))
    for rel in NOSQL_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("nosql:" + os.path.basename(rel), load_payload_file(p)))
    for rel in LDAP_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("ldap:" + os.path.basename(rel), load_payload_file(p)))
    for rel in SSRF_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("ssrf:" + os.path.basename(rel), load_payload_file(p)))
    for rel in DESER_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("deser:" + os.path.basename(rel), load_payload_file(p)))
    for rel in CRLF_FILES:
        p = os.path.join(ds, rel)
        if os.path.exists(p):
            corpora.append(("crlf:" + os.path.basename(rel), load_payload_file(p)))

    anomalous = os.path.join(ds, "csic/anomalousTrafficTest.txt")
    normal = os.path.join(ds, "csic/normalTrafficTraining.txt")

    csic_bucket = {}
    if os.path.exists(anomalous):
        reqs = extract_csic(anomalous)
        bucket = {"sqli": [], "xss": [], "other-attack": [], "ambiguous": []}
        for req in reqs:
            bucket[classify_csic(req)].append(req)
        for name, items in bucket.items():
            if items:
                csic_bucket[name] = items
    if os.path.exists(normal):
        csic_bucket["_normal"] = extract_csic(normal)

    for name, items in csic_bucket.items():
        key = "benign:csic2010-normal" if name == "_normal" else "csic2010-" + name
        corpora.append((key, items))

    if not corpora:
        print("No corpora found under %s" % ds, file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        paths = {}
        for label, items in corpora:
            path = os.path.join(tmp, label.replace("/", "_") + ".txt")
            write_corpus(items, path)
            paths[label] = (path, len(items))

        results = {}
        for tag, binary in (("baseline", args.baseline), ("optimized", args.optimized)):
            if not os.path.exists(binary):
                print("missing binary: %s" % binary, file=sys.stderr)
                return 1
            for label, (path, n) in paths.items():
                mode = corpus_mode(label)
                results.setdefault(label, {})[tag + ":mode"] = mode
                if tag == "baseline" and mode not in BASELINE_MODES:
                    continue
                det, tot, missed = run_reader(binary, path, mode)
                results.setdefault(label, {})[tag] = (det, tot, missed)

        print("=" * 88)
        print("%-44s %9s %14s %14s" % ("public corpus", "lines",
                                       "baseline 3.9.2", "optimized 3.10.0"))
        print("%-44s %9s %6s %7s %6s %7s" % ("", "", "det", "recall",
                                             "det", "recall"))
        print("-" * 88)
        for label, (path, n) in paths.items():
            o = results[label]["optimized"]
            ort = 100.0 * o[0] / o[1] if o[1] else 0.0
            if "baseline" in results[label]:
                b = results[label]["baseline"]
                br = 100.0 * b[0] / b[1] if b[1] else 0.0
                print("%-44s %9d %6d %6.2f%% %6d %6.2f%%" %
                      (label, n, b[0], br, o[0], ort))
            else:
                print("%-44s %9d %6s %6s    %6d %6.2f%%" %
                      (label, n, "-", "-", o[0], ort))
        print("=" * 88)

        # dump missed payloads of the optimized build for analysis
        miss_dir = os.environ.get("MISS_DIR", "")
        if miss_dir:
            os.makedirs(miss_dir, exist_ok=True)
            for label, (path, n) in paths.items():
                for tag in ("baseline", "optimized"):
                    if tag not in results[label]:
                        continue
                    missed = results[label][tag][2]
                    with open(os.path.join(
                            miss_dir, "%s.%s.miss.txt" % (
                                label.replace("/", "_"), tag)),
                            "w", encoding="utf-8") as fh:
                        fh.write("\n".join(missed))
            print("misses written to %s" % miss_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
