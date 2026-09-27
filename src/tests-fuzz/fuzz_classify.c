/**
 * Fuzz harness for the multi-class API (libFuzzer / AFL++).
 *
 * Builds with:
 *   clang -g -O1 -fsanitize=fuzzer,address -I. \
 *       ../src/libinjection_*.c fuzz_classify.c -o fuzz_classify
 * (see .github/workflows/ci.yml for the canonical invocation)
 *
 * Exercises the full pipeline: classify on raw input, classify_url
 * with iterative decoding (malloc paths) and each single-class
 * detector.  Deterministic per input, no globals mutated.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "libinjection_classify.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    const char* s = (const char*) data;

    if (size > 4096) {
        return 0; /* keep corpus sane; no artificial complexity */
    }

    (void) libinjection_classify(s, size, LIBINJECTION_CLASS_ALL);
    (void) libinjection_classify_url(s, size, LIBINJECTION_CLASS_ALL);

    return 0;
}
