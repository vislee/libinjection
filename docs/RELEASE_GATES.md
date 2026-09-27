# Release gates

Every push (CI) and every release must pass all gates below.  The
numeric thresholds are enforced by `./run-benchmark.sh --check` (CI:
`.github/workflows/ci.yml`).  Tighten a gate by editing both places in
the same commit.

## Detection quality

| gate | threshold | rationale |
|---|---|---|
| SQLi official recall | >= 99.5% | upstream engine, large corpus |
| XSS official recall  | >= 98.0%  | upstream engine, large corpus |
| SQLi red-team recall | >= 95%    | new probes, allow tuning room |
| XSS red-team recall  | >= 99%    | new probes |
| TRAV/SSRF/DESER/CRLF/CMD/SSTI/NOSQL/LDAP/CODE/RECON/REDIRECT red-team recall | 100% | small purpose-built corpora; a miss means the table needs a new needle before release |
| SQLi FP on `data/false_positives.txt` | <= 17 lines | known quoted-prose baseline (16/421 at 4.1.0) |
| FP on all other benign corpora | 0 | redteam-benign, benign-p1, benign-p23, benign-recon, benign-redirect |

Raising any benign-corpus FP above zero requires: a fixture reproducing
the false positive, a suppressor or gating change, and a note in the
release notes.

## Correctness / portability

| gate | where |
|---|---|
| `-Wall -Wextra -Werror -pedantic -ansi` clean, gcc + clang, Linux + macOS | ci: strict-build-and-tests |
| `make check` (482 API checks + 536 fixtures + sample corpora) | ci: strict-build-and-tests |
| full suite + corpora under ASan + UBSan, zero reports | ci: sanitizers |
| fuzz corpus driver (all corpora + 20k mutations) zero crashes | ci: sanitizers (via make check) and local `tests-fuzz/` |
| libFuzzer smoke 120s zero crashes | ci: fuzz-smoke |
| shared library builds with soname/install_name and `make install` lands static + shared + headers | ci: strict-build-and-tests |

## Release checklist

1. update `LIBINJECTION_VERSION` in `src/libinjection_sqli.c`
   (single source of truth) and the unit-test assertion
2. `make -C src check && ./run-benchmark.sh --check` locally
3. bump `LIBRARY_VERSION` in `src/Makefile` only if ABI broke
4. `git tag -s v<X.Y.Z> && git push --tags`
5. draft release notes: recall/FP table from `run-benchmark.sh`,
   new needles/tables, fixed false positives
