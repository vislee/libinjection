/**
 * Deterministic corpus driver for the fuzz harness (no libFuzzer
 * runtime required).  Feeds every corpus file, stdin lines and a
 * bounded pseudo-random mutation loop through the same
 * LLVMFuzzerTestOneInput() entry point, under ASan/UBSan.
 *
 *   clang -g -O1 -fsanitize=address,undefined -I. \
 *       ../src/libinjection_*.c fuzz_classify.c fuzz_corpus_main.c \
 *       -o fuzz_corpus
 *   ./fuzz_corpus /tmp/fuzz-corpus
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#define MAX_LEN 4096

/* xorshift32: deterministic, no platform rand() differences */
static uint32_t rng_state = 0x25062119u;

static uint32_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static void feed_file(const char* path)
{
    FILE* f = fopen(path, "rb");
    uint8_t buf[MAX_LEN];
    size_t n;

    if (f == NULL) {
        return;
    }
    n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    (void) LLVMFuzzerTestOneInput(buf, n);
}

static void mutate_feed(const uint8_t* base, size_t n)
{
    uint8_t buf[MAX_LEN];
    size_t len;
    int flips;

    if (n > MAX_LEN) {
        n = MAX_LEN;
    }
    memcpy(buf, base, n);
    len = n;
    flips = (int) (rng() % 8u) + 1;
    while (flips-- > 0 && len > 0) {
        size_t pos = rng() % len;
        switch (rng() % 3u) {
        case 0: buf[pos] = (uint8_t) rng(); break;
        case 1: buf[pos] ^= (uint8_t) (1u << (rng() % 8u)); break;
        default:
            if (len < MAX_LEN) {
                memmove(buf + pos + 1, buf + pos, len - pos);
                buf[pos] = (uint8_t) rng();
                len += 1;
            }
            break;
        }
    }
    (void) LLVMFuzzerTestOneInput(buf, len);
}

int main(int argc, char** argv)
{
    static uint8_t base[MAX_LEN];
    size_t baselen = 0;
    int i;
    int round;

    /* 1. corpus files passed as arguments */
    for (i = 1; i < argc; ++i) {
        feed_file(argv[i]);
    }

    /* 2. every line of every corpus file as one input */
    for (i = 1; i < argc; ++i) {
        FILE* f = fopen(argv[i], "r");
        char line[1024];
        if (f == NULL) {
            continue;
        }
        while (fgets(line, sizeof(line), f) != NULL) {
            (void) LLVMFuzzerTestOneInput((const uint8_t*) line,
                                          strlen(line));
        }
        fclose(f);
    }

    /* 3. build a mixed seed base, then mutate around it */
    for (i = 1; i < argc && baselen < MAX_LEN; ++i) {
        FILE* f = fopen(argv[i], "rb");
        size_t n;
        if (f == NULL) {
            continue;
        }
        n = fread(base + baselen, 1, MAX_LEN - baselen, f);
        fclose(f);
        baselen += n;
    }

    for (round = 0; round < 20000; ++round) {
        mutate_feed(base, baselen);
    }

    printf("fuzz_corpus: no crashes\n");
    return 0;
}
