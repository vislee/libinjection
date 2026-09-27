/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Unified detection CLI: scans a string (argument) or stdin (one
 * input per line) for all 11 supported attack classes.
 *
 * Exit codes: 0 = no detection, 1 = at least one detection,
 * 2 = usage error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libinjection.h"
#include "libinjection_sqli.h"
#include "libinjection_classify.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define LINE_MAX_LEN 8192

struct class_def {
    const char* name;
    libinjection_class_mask_t bit;
};

static const struct class_def CLASSES[] = {
    { "sqli", LIBINJECTION_CLASS_SQLI }
    , { "xss", LIBINJECTION_CLASS_XSS }
    , { "trav", LIBINJECTION_CLASS_TRAV }
    , { "ssrf", LIBINJECTION_CLASS_SSRF }
    , { "deser", LIBINJECTION_CLASS_DESER }
    , { "crlf", LIBINJECTION_CLASS_CRLF }
    , { "cmd", LIBINJECTION_CLASS_CMD }
    , { "ssti", LIBINJECTION_CLASS_SSTI }
    , { "nosql", LIBINJECTION_CLASS_NOSQL }
    , { "ldap", LIBINJECTION_CLASS_LDAP }
    , { "code", LIBINJECTION_CLASS_CODE }
    , { "recon", LIBINJECTION_CLASS_RECON }
    , { "redirect", LIBINJECTION_CLASS_REDIRECT }
    , { NULL, 0 }
};

static const char* g_progname = "injection";

static void usage(int code)
{
    fprintf(stdout, "usage: %s [options] [string ...]\n\n", g_progname);
    fputs("detect injection attacks in a string, or on stdin (one input\n"
          "per line) when no string arguments are given\n\n", stdout);
    fputs("options:\n", stdout);
    fputs("  -c, --classes LIST   comma-separated classes to enable\n"
          "                       (default: all)\n", stdout);
    fputs("                       classes: sqli,xss,trav,ssrf,deser,crlf,\n"
          "                       cmd,ssti,nosql,ldap,code,recon,redirect,\n"
          "                       all\n", stdout);
    fputs("  -d, --decode         also scan URL-decoded input (up to 3\n"
          "                       rounds: defeats double/triple encoding)\n", stdout);
    fputs("  -j, --json           JSON-lines output\n", stdout);
    fputs("  -q, --quiet          only print inputs that match\n", stdout);
    fputs("  -F, --fingerprint    include the SQLi fingerprint when matched\n", stdout);
    fputs("  -h, --help           this page\n\n", stdout);
    fputs("exit codes: 0 no detection, 1 detection, 2 usage error\n", stdout);
    exit(code);
}

static void usage_error(const char* msg)
{
    fprintf(stderr, "%s: %s (try --help)\n", g_progname, msg);
    exit(2);
}

static libinjection_class_mask_t parse_classes(char* arg)
{
    libinjection_class_mask_t mask = 0;
    char* tok;

    if (arg == NULL) {
        return LIBINJECTION_CLASS_ALL;
    }
    tok = strtok(arg, ",");
    while (tok != NULL) {
        int known = FALSE;
        const struct class_def* def;
        if (strcmp(tok, "all") == 0) {
            mask |= LIBINJECTION_CLASS_ALL;
            known = TRUE;
        }
        for (def = CLASSES; def->name != NULL && ! known; ++def) {
            if (strcmp(tok, def->name) == 0) {
                mask |= def->bit;
                known = TRUE;
            }
        }
        if (! known) {
            fprintf(stderr, "%s: unknown class '%s'\n", g_progname, tok);
            exit(2);
        }
        tok = strtok(NULL, ",");
    }
    return mask;
}

/*
 * writes class names for the found bits, '+' separated; returns the
 * number of names written
 */
static int format_classes(libinjection_class_mask_t found, char* buf,
                          size_t buflen)
{
    const struct class_def* def;
    size_t pos = 0;
    int count = 0;

    buf[0] = '\0';
    for (def = CLASSES; def->name != NULL; ++def) {
        if (found & def->bit) {
            size_t nlen = strlen(def->name);
            if (count > 0 && pos + 1 < buflen) {
                buf[pos++] = '+';
            }
            if (pos + nlen >= buflen) {
                break;
            }
            memcpy(buf + pos, def->name, nlen);
            pos += nlen;
            buf[pos] = '\0';
            count += 1;
        }
    }
    return count;
}

static void json_escape(const char* s, size_t len)
{
    size_t i;

    for (i = 0; i < len; ++i) {
        unsigned char c = (unsigned char) s[i];
        switch (c) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (c < 0x20) {
                fprintf(stdout, "\\u%04x", (unsigned) c);
            } else {
                putchar(c);
            }
        }
    }
}

static int process(const char* input, size_t len,
                   libinjection_class_mask_t want, int decode,
                   int as_json, int quiet, int want_fp,
                   int* any_match)
{
    libinjection_class_mask_t found;
    char names[128];
    int count;
    char fingerprint[32];
    const char* fpstr = "";

    fingerprint[0] = '\0';
    found = decode ? libinjection_classify_url(input, len, want)
                   : libinjection_classify(input, len, want);
    count = format_classes(found, names, sizeof(names));

    if (count == 0) {
        if (! as_json && ! quiet) {
            printf("ok\t%s\n", input);
        }
        return FALSE;
    }

    *any_match = TRUE;

    if ((found & LIBINJECTION_CLASS_SQLI) && want_fp) {
        if (decode) {
            /* fingerprint from the layer that matched (raw or one of
             * the decoded ones), consistent with the verdict above */
            libinjection_sqli_url(input, len, fingerprint);
        } else {
            libinjection_sqli(input, len, fingerprint);
        }
        fpstr = fingerprint;
    }

    if (as_json) {
        const struct class_def* def;
        int first = TRUE;
        printf("{\"input\":\"");
        json_escape(input, len);
        printf("\",\"classes\":[");
        for (def = CLASSES; def->name != NULL; ++def) {
            if (found & def->bit) {
                if (! first) {
                    putchar(',');
                }
                first = FALSE;
                printf("\"%s\"", def->name);
            }
        }
        printf("]");
        if (fpstr[0] != '\0') {
            printf(",\"fingerprint\":\"%s\"", fpstr);
        }
        printf("}\n");
    } else {
        printf("%s\t%s", names, input);
        if (fpstr[0] != '\0') {
            printf("\t%s", fpstr);
        }
        printf("\n");
    }
    return TRUE;
}

int main(int argc, char** argv)
{
    libinjection_class_mask_t want = LIBINJECTION_CLASS_ALL;
    int decode = FALSE;
    int as_json = FALSE;
    int quiet = FALSE;
    int want_fp = FALSE;
    int any_match = FALSE;
    int i;
    int offset = 1;
    char line[LINE_MAX_LEN];

    g_progname = (argc > 0 && argv[0] != NULL) ? argv[0] : "injection";

    while (offset < argc) {
        const char* a = argv[offset];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(0);
        } else if (strcmp(a, "-c") == 0 || strcmp(a, "--classes") == 0) {
            if (offset + 1 >= argc) {
                usage_error("--classes needs an argument");
            }
            want = parse_classes(argv[offset + 1]);
            offset += 2;
        } else if (strcmp(a, "-d") == 0 || strcmp(a, "--decode") == 0) {
            decode = TRUE;
            offset += 1;
        } else if (strcmp(a, "-j") == 0 || strcmp(a, "--json") == 0) {
            as_json = TRUE;
            offset += 1;
        } else if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
            quiet = TRUE;
            offset += 1;
        } else if (strcmp(a, "-F") == 0 || strcmp(a, "--fingerprint") == 0) {
            want_fp = TRUE;
            offset += 1;
        } else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "%s: unknown option %s\n", g_progname, a);
            usage_error("unknown option");
        } else {
            break;
        }
    }

    if (offset < argc) {
        /* inputs from argv */
        for (i = offset; i < argc; ++i) {
            process(argv[i], strlen(argv[i]), want, decode, as_json,
                    quiet, want_fp, &any_match);
        }
    } else {
        /* inputs from stdin, one per line */
        while (fgets(line, sizeof(line), stdin) != NULL) {
            size_t slen = strlen(line);
            while (slen > 0 && (line[slen - 1] == '\n' ||
                                line[slen - 1] == '\r')) {
                line[--slen] = '\0';
            }
            if (slen == 0) {
                continue;
            }
            process(line, slen, want, decode, as_json, quiet, want_fp,
                    &any_match);
        }
    }

    return any_match ? 1 : 0;
}
