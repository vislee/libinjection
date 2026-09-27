libinjection
============

**libinjection** is a small, fast, zero-dependency C library that detects
injection attacks inside a single string (typically one HTTP parameter
value).  This fork extends the original SQLi/XSS engine to
**11 attack classes** covering the input-detectable subset of
[OWASP Top 10](https://owasp.org/Top10/).

Supported attack classes
------------------------

| class  | enum                          | detects                                             | OWASP |
|--------|-------------------------------|-----------------------------------------------------|-------|
| sqli   | `LIBINJECTION_CLASS_SQLI`     | SQL injection (fingerprint engine, all main dialects)| A03   |
| xss    | `LIBINJECTION_CLASS_XSS`      | cross-site scripting (HTML5 state machine)           | A03   |
| trav   | `LIBINJECTION_CLASS_TRAV`     | path traversal / LFI / wrappers (`php://filter`...)  | A01   |
| ssrf   | `LIBINJECTION_CLASS_SSRF`     | SSRF targets (cloud metadata, loopback, private IPs) | A10   |
| deser  | `LIBINJECTION_CLASS_DESER`    | insecure deserialization + JNDI/Log4Shell            | A08   |
| crlf   | `LIBINJECTION_CLASS_CRLF`     | CRLF / HTTP response splitting                       | A05   |
| cmd    | `LIBINJECTION_CLASS_CMD`      | OS command injection (POSIX + Windows)               | A03   |
| ssti   | `LIBINJECTION_CLASS_SSTI`     | server-side template injection                       | A03   |
| nosql  | `LIBINJECTION_CLASS_NOSQL`    | MongoDB operator / boolean injection                 | A03   |
| ldap   | `LIBINJECTION_CLASS_LDAP`     | LDAP filter and XPath injection                      | A03   |
| code   | `LIBINJECTION_CLASS_CODE`     | server-side code probes (`<?php`, `eval("...")`)     | A03   |

API
---

```c
/* single class */
int   libinjection_sqli  (const char* s, size_t len, char fingerprint[8+]);
int   libinjection_xss   (const char* s, size_t len);
int   libinjection_trav  (const char* s, size_t len);
int   libinjection_ssrf  (const char* s, size_t len);
int   libinjection_deser (const char* s, size_t len);
int   libinjection_crlf  (const char* s, size_t len);
int   libinjection_cmd   (const char* s, size_t len);
int   libinjection_ssti  (const char* s, size_t len);
int   libinjection_nosql (const char* s, size_t len);
int   libinjection_ldap  (const char* s, size_t len);
int   libinjection_code  (const char* s, size_t len);

/* all classes in one call, one bitmask back */
libinjection_class_mask_t
libinjection_classify(const char* s, size_t len,
                      libinjection_class_mask_t want_mask);

/* same, but every detector also runs on up to three rounds of
 * URL decoding (defeats double/triple encoding) */
libinjection_class_mask_t
libinjection_classify_url(const char* s, size_t len,
                          libinjection_class_mask_t want_mask);

/* helpers */
size_t libinjection_urldecode(char* buf, size_t len);  /* in-place, one pass */
int    libinjection_urldecode_has_encoded(const char* buf, size_t len);
int    libinjection_sqli_url(const char* s, size_t len, char fp[8+]);
int    libinjection_xss_url (const char* s, size_t len);
```

The classic `libinjection_sqli()` / `libinjection_xss()` behaviour is
unchanged from upstream 3.9.2 apart from added fingerprints and
false-positive suppressors (see `docs/OPTIMIZATION_PLAN.md`).

Quick start
-----------

```c
#include <stdio.h>
#include <string.h>
#include "libinjection_classify.h"

int main(void)
{
    const char* input = "x\" style=\"background:url(javascript:alert(1))";
    libinjection_class_mask_t found =
        libinjection_classify_url(input, strlen(input),
                                  LIBINJECTION_CLASS_ALL);
    if (found & LIBINJECTION_CLASS_XSS)  puts("xss");
    if (found & LIBINJECTION_CLASS_SQLI) puts("sqli");
    /* ... */
    return 0;
}
```

Command line
------------

The unified detection CLI is `src/injection` (built by `make -C src injection`
or `make -C src samples`):

```sh
$ ./src/injection '1 union select x--'
sqli	1 union select x--

$ ./src/injection -c cmd ';cat /etc/passwd'
cmd	;cat /etc/passwd

$ ./src/injection -d '%3Cscript%3Ealert(1)%3C/script%3E'   # URL-decode aware
xss	%3Cscript%3Ealert(1)%3C/script%3E

$ ./src/injection -j -F ';cat /etc/passwd'
{"input":";cat /etc/passwd","classes":["trav","cmd"]}

$ echo '{{7*7}}' | ./src/injection -q      # stdin, matches only
ssti	{{7*7}}
```

Options: `-c/--classes` pick classes (comma list), `-d/--decode` scan
URL-decoded input too, `-j/--json` JSON-lines output, `-q/--quiet`
print matches only, `-F/--fingerprint` include the SQLi fingerprint.
Exit codes: `0` no detection, `1` detection found, `2` usage error.

Note: with `-d`, the detection verdict may come from a decoded layer,
while the `-F` fingerprint is always computed on the raw input — if
the raw layer does not match on its own, the class is reported without
a fingerprint.

For bulk corpus scanning use `src/reader` (`--trav`, `--ssrf`, `--deser`,
`--crlf`, `--cmd`, `--ssti`, `--nosql`, `--ldap`, `--code`, `-x`).

Build and test
--------------

```sh
make                # builds libinjection.a, libinjection.so, samples in src/
make -C src check   # 450 API checks + 520 data fixtures + 4 sample corpora
make benchmark      # recall / false-positive report over all corpora
make coverage       # clang coverage report, fails below 95% lines
make clean          # also removes src/coverage-data/

# optional public-corpus blind test (payload-box / SecLists / CSIC 2010)
./scripts/fetch_public_datasets.sh       # fetch (~40MB)
python3 scripts/eval_public_datasets.py  # baseline 3.9.2 vs current
```

`make check` runs, in order: the `injection` CLI smoke test
(`src/test-cli.sh`), the API unit tests (`src/test_unit.c`, prints
"450 checks, 0 failures"), the data-driven fixtures in `tests/`
(`--INPUT--`/`--EXPECTED--` format via `src/testdriver`), and the
upstream sample corpora in `data/`.  `make coverage` needs clang plus
`llvm-profdata`/`llvm-cov` (macOS: Xcode toolchain; Linux: install
`llvm` and adjust the `xcrun` calls in `run-coverage.sh`).

Detection design
----------------

The eleven modules are built from three kinds of rules:

* **Tokenizer engines** — `sqli` folds the input into at most five
  tokens and matches a fingerprint grammar (`libinjection_sqli_data.h`);
  `xss` walks an HTML5 state machine (`libinjection_html5.c`).
  False positives are handled inside `libinjection_sqli_not_whitelist()`
  and the style-attribute content check with shape-specific
  suppressors, each anchored by a regression fixture in `tests/`.
* **Needle + context rules** — `trav`, `ssrf`, `deser`, `crlf`,
  `ldap`, `code`, `ssti`, `nosql`.  A payload word only fires in an
  attack-shaped position (URL shape, `)(` LDAP filter boundary, header
  marker after CRLF, `{{`/`${` marker window, ...), which keeps normal
  prose and ordinary query strings quiet.
* **Adjacency rules** — `cmd` fires only when a shell metacharacter is
  directly adjacent (through quote/brace filler) to a known command
  word, or the word sits inside `$( )` / backticks.  `&key=value`
  pairs after a metacharacter are treated as query-string syntax, not
  shell input.

Single-class detectors are allocation-free; the `_url` /
`classify_url` variants use one malloc'd buffer for decode rounds and
stop as soon as a class matches.  Everything is C90 (`-ansi -pedantic`
build is part of `make check`).

Evaluation results
------------------

Reproduce with `make benchmark` (corpora shipped in this repo,
version 4.0.0):

| corpus (attack) | recall |
|---|---|
| SQLi official (`data/sqli-*.txt`) | 99.98% |
| XSS official (`data/xss-*.txt`) | 99.10% |
| SQLi / XSS red-team (`data/redteam-*.txt`) | 96.7% / 100% |
| TRAV, SSRF, DESER, CRLF, CMD, SSTI, NOSQL, LDAP, CODE red-team | 100% each |

| corpus (benign) | false positives |
|---|---|
| `data/false_positives.txt`, SQLi | 3.80% (known, quoted prose — see limitations) |
| `data/false_positives.txt`, XSS | 0 |
| `data/redteam-benign.txt`, `data/benign-p1.txt`, `data/benign-p23.txt`, all 11 classes | 0 |

Public blind tests (payload-box, SecLists, HTTP CSIC 2010 — including
36k benign requests, 0 FP across all eleven classes) are documented in
`docs/PUBLIC_DATASET_EVAL.md`.

Known limitations
-----------------

* **SSRF private-range prefixes** (`10.`, `192.168.`, `172.16.`–
  `172.31.`) currently match when just a digit follows in a
  key/value position, so plain decimals like `price=10.5` or a
  version string `version=10.04` can be flagged.  Known issue; the
  fix should require the full two-octet shape (`10.x.`).
* **SQLi unquoted weak probes** (`select x from y where`, `1,1--`)
  are intentionally whitelisted — upstream considers them
  inseparable from ordinary prose.
* **LFI path-dictionary corpora** (bare sensitive-path word lists
  without traversal context) are not signature targets; the public
  Jhaddix dict measures ~27% by design
  (see `docs/PUBLIC_DATASET_EVAL.md`).
* Detectors assume **parameter values**, not free-form text.  `cmd`
  reads `q=;cat /etc/passwd` well; English prose around words like
  "sleep" after a semicolon stays a residual risk.

Repository layout
-----------------

    src/                     library sources + drivers
      libinjection_*.c/.h    eleven detectors + normalize/classify layers
      injection_cli.c        unified CLI (built as src/injection)
      reader.c               corpus scanner used by benchmark/coverage
      test_unit.c            API unit tests (450 checks)
      test-cli.sh            CLI smoke tests
    tests/                   data-driven fixtures (--INPUT--/--EXPECTED--)
    data/                    upstream samples + red-team + benign corpora
    docs/                    evaluation & implementation reports
    scripts/                 public-dataset fetch / eval tooling
    run-benchmark.sh         target of `make benchmark`
    run-coverage.sh          target of `make coverage`

Embedding
---------

Copy into your source tree:

* `src/libinjection.h`
* `src/libinjection_classify.h`, `src/libinjection_normalize.h`
* `src/libinjection_sqli.h`, `src/libinjection_sqli_data.h`
* `src/libinjection_html5.h`, `src/libinjection_xss.h`
* `src/libinjection_trav.h`, `src/libinjection_ssrf.h`,
  `src/libinjection_deser.h`, `src/libinjection_crlf.h`,
  `src/libinjection_cmd.h`, `src/libinjection_ssti.h`,
  `src/libinjection_nosql.h`, `src/libinjection_ldap.h`,
  `src/libinjection_code.h`
* the matching `.c` files
* [COPYING](/COPYING)

Documentation
-------------

* `docs/OPTIMIZATION_PLAN.md` — SQLi/XSS optimization: evaluation,
  plan, implementation record (3.9.2 -> 3.10.0)
* `docs/PUBLIC_DATASET_EVAL.md` — public blind-test report
  (payload-box, SecLists, HTTP CSIC 2010)
* `docs/OWASP_EXPANSION_PLAN.md` — OWASP Top 10 expansion plan and
  P0-P3 implementation records (3.11.0 -> 3.13.0)
* `docs/FINAL_REPORT.md` — full 3.9.2 -> 4.0.0 report

Upstream
--------

Original libinjection by Nick Galbreath
([client9](https://www.client9.com/)), version 3.9.2:
SQL tokenizer/parser for C/C++, PHP, Python, Lua and Java.
See [CHANGELOG](/CHANGELOG) for version history.

LICENSE
=============

Copyright (c) 2012-2016 Nick Galbreath

Licensed under the standard [BSD 3-Clause](http://opensource.org/licenses/BSD-3-Clause) open source
license.  See [COPYING](/COPYING) for details.
