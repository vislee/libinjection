/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * SSTI: a template-expression marker ({{ ${ <% #{ {%) near a
 * dangerous semantic (arithmetic probe, attribute climbing, engine
 * call).  Plain placeholders ({{name}}, ${user.id}) stay benign.
 */

#include <string.h>

#include "libinjection_ssti.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define ISALNUM(a) (((unsigned)((a) - '0') < 10u) || \
                    ((unsigned)((a) - 'a') < 26u) || \
                    ((unsigned)((a) - 'A') < 26u))

static const char* MARKERS[] = {
    "{{", "${", "<%", "#{", "{%", "*{", "@(", "<#", "[#", "<%=", "{$", NULL
};

static const char* DANGER[] = {
    "__class__"
    , "__mro__"
    , "__subclasses__"
    , "__globals__"
    , "__builtins__"
    , "__import__"
    , "constructor."
    , "getclass"
    , "forname"
    , "popen("
    , "phpinfo("
    , "7*'7'"
    , "__context"
    , "settings."
    , "secret_key"
    , "constant("
    , "smarty."
    , "import os"
    , "import sys"
    , "template.utility"
    , "freemarker.template"
    , "request."
    , "namespace"
    , "lipsum"                  /* Jinja2 global builtin probe */
    , "cycler"                  /* Jinja2 global builtin probe */
    , "joiner"                  /* Jinja2 global builtin probe */
    , "t(java."                 /* Spring EL: ${T(java.lang.Runtime)...} */
    , "process.mainmodule"      /* Node.js SSTI */
    , "child_process"           /* Node.js SSTI */
    , "mainmodule"              /* Node.js SSTI */
    , "|filter("                /* Twig filter injection */
    , "|map("                   /* Twig filter injection */
    , "|reduce("                /* Twig filter injection */
    , "|sort("                  /* Twig sort injection */
    , ".exec("                  /* Java/Groovy: .exec() call */
    , ".execute("              /* Java/Groovy: .execute() call */
    , "processbuilder"          /* Java ProcessBuilder */
    , "methodclosure"           /* Groovy MethodClosure */
    , "getruntime"             /* Java Runtime.getRuntime() */
    , "forname"                /* Java Class.forName() */
    , "getclass"               /* Java .getClass() */
    , "getresource"            /* Java .getResource() */
    , "getclassloader"         /* Java .getClassLoader() */
    , "system.shell"            /* Elixir System.shell */
    , "url_for"                 /* Jinja2 url_for global */
    , "get_flashed_messages"    /* Jinja2 flash messages global */
    , "config.items"            /* Jinja2 config.items() probe */
    , "_.version"              /* Underscore.js probe (_.VERSION) */
    , "dir.entries"            /* Ruby ERB Dir.entries */
    , "file.open"              /* Ruby ERB File.open */
    , "file.read"              /* Ruby ERB File.read */
    , NULL
};

/*
 * short English words that need a word-boundary check on the left
 * ("self" must not match "himself", "set " must not match "offset c")
 */
static const char* DANGER_BOUNDED[] = {
    "self"                      /* {{self}} - Jinja2/Twig context probe */
    , "set "                    /* {%set x=1%} - template tag injection */
    , "this"                    /* {{this}} - Jinja2/Spring context probe */
    , "request"                 /* {{request}} - Jinja2 request probe */
    , "include"                 /* {{include(...)}} - Twig/Jinja2 include */
    , "dump("                   /* {{dump(app)}} - Twig dump probe */
    , NULL
};

static char lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char) (c + 0x20);
    }
    return c;
}

/* case-insensitive substring search */
static int contains_ci(const char* s, size_t len, const char* needle)
{
    size_t nlen = strlen(needle);
    size_t i;
    if (nlen == 0 || len < nlen) {
        return FALSE;
    }
    for (i = 0; i + nlen <= len; ++i) {
        size_t j;
        int match = 1;
        for (j = 0; j < nlen; ++j) {
            if (lower(s[i + j]) != lower(needle[j])) {
                match = 0;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

int libinjection_ssti(const char* s, size_t len)
{
    size_t m;
    size_t d;
    size_t i;

    for (m = 0; MARKERS[m] != NULL; ++m) {
        size_t mlen = strlen(MARKERS[m]);
        for (i = 0; i + mlen <= len; ++i) {
            size_t j;
            int match = 1;
            for (j = 0; j < mlen; ++j) {
                if (lower(s[i + j]) != MARKERS[m][j]) {
                    match = 0;
                    break;
                }
            }
            if (! match) {
                continue;
            }
            /*
             * danger must sit in the same expression: search a
             * bounded window after the marker
             */
            {
                size_t window = i + mlen + 64;
                size_t k;
                if (window > len) {
                    window = len;
                }
                /* arithmetic oracle: digit * digit or digit / digit
                 * (7*7, 7 * 7, 1/0, 1/(0) ...) — spaces between
                 * digits and operator are common in SSTI probes */
                for (k = i + mlen + 1; k + 1 < window; ++k) {
                    if (s[k] == '*' || s[k] == '/') {
                        size_t back = k;
                        size_t fwd = k + 1;
                        /* skip spaces backward to find digit */
                        while (back > i + mlen && s[back - 1] == ' ') {
                            --back;
                        }
                        /* skip spaces forward to find digit */
                        while (fwd < window && s[fwd] == ' ') {
                            ++fwd;
                        }
                        if (back > i + mlen &&
                            s[back - 1] >= '0' && s[back - 1] <= '9' &&
                            fwd < window &&
                            ((s[fwd] >= '0' && s[fwd] <= '9') ||
                             s[fwd] == '(')) {
                            return TRUE;
                        }
                    }
                }
                for (d = 0; DANGER[d] != NULL; ++d) {
                    size_t dlen = strlen(DANGER[d]);
                    size_t k;
                    if (dlen > window - (i + mlen)) {
                        continue;
                    }
                    for (k = i + mlen; k + dlen <= window; ++k) {
                        int dmatch = 1;
                        size_t z;
                        for (z = 0; z < dlen; ++z) {
                            char a = s[k + z];
                            char b = DANGER[d][z];
                            if (b >= 'a' && b <= 'z' && a >= 'A' && a <= 'Z') {
                                a = (char) (a + 0x20);
                            }
                            if (a != b) {
                                dmatch = 0;
                                break;
                            }
                        }
                        if (dmatch) {
                            return TRUE;
                        }
                    }
                }
                /* same scan for words that must start on a word
                 * boundary (k == marker end, or non-alnum before) */
                for (d = 0; DANGER_BOUNDED[d] != NULL; ++d) {
                    size_t dlen = strlen(DANGER_BOUNDED[d]);
                    size_t k;
                    if (dlen > window - (i + mlen)) {
                        continue;
                    }
                    for (k = i + mlen; k + dlen <= window; ++k) {
                        int dmatch = 1;
                        size_t z;
                        if (k > i + mlen && ISALNUM(s[k - 1])) {
                            continue;         /* word glue: himself */
                        }
                        for (z = 0; z < dlen; ++z) {
                            char a = s[k + z];
                            char b = DANGER_BOUNDED[d][z];
                            if (b >= 'a' && b <= 'z' && a >= 'A' && a <= 'Z') {
                                a = (char) (a + 0x20);
                            }
                            if (a != b) {
                                dmatch = 0;
                                break;
                            }
                        }
                        if (dmatch) {
                            return TRUE;
                        }
                    }
                }
            }
        }
    }

    /* {{config}} / {{ config }} - the classic Jinja2 probe */
    for (i = 0; i + 4 <= len; ++i) {
        size_t j;
        size_t k;
        if (s[i] != '{' || s[i + 1] != '{') {
            continue;
        }
        j = i + 2;
        while (j < len && (s[j] == ' ' || s[j] == '\t')) {
            j += 1;
        }
        if (j + 6 > len) {
            continue;
        }
        if (lower(s[j]) == 'c' && lower(s[j + 1]) == 'o' &&
            lower(s[j + 2]) == 'n' && lower(s[j + 3]) == 'f' &&
            lower(s[j + 4]) == 'i' && lower(s[j + 5]) == 'g') {
            k = j + 6;
            while (k < len && (s[k] == ' ' || s[k] == '\t')) {
                k += 1;
            }
            if (k + 1 < len && s[k] == '}' && s[k + 1] == '}') {
                return TRUE;
            }
        }
    }

    /* Java reflection chains that do not carry a template marker:
     * getClassLoader() and "extends ClassLoader" are strong signals
     * on their own (Java class-name, dot-call or extends keyword).
     * Word-boundary on "extends" prevents matching "extendsX". */
    if (contains_ci(s, len, "getclassloader")) {
        return TRUE;
    }
    {
        size_t j;
        for (j = 0; j + 17 <= len; ++j) {
            if (lower(s[j]) == 'e' && lower(s[j + 1]) == 'x' &&
                lower(s[j + 2]) == 't' && lower(s[j + 3]) == 'e' &&
                lower(s[j + 4]) == 'n' && lower(s[j + 5]) == 'd' &&
                lower(s[j + 6]) == 's' && s[j + 7] == ' ') {
                /* word boundary before "extends" */
                if (j > 0 && ISALNUM(s[j - 1])) {
                    continue;
                }
                if (contains_ci(s + j + 8, len - j - 8, "classloader")) {
                    return TRUE;
                }
            }
        }
    }

    /* Marker-less SSTI patterns: template engines that use {tag}
     * syntax without a leading marker.  {php }, {exec(, {system(,
     * {passthru(, {shell_exec( are Smarty/Twig/Blade code-exec
     * tags.  Word-boundary: must be at start-of-input or after a
     * non-alnum char to avoid matching "{exec" in prose. */
    {
        static const char* SMARTY_TAGS[] = {
            "{php", "{exec(", "{system(", "{passthru(",
            "{shell_exec(", "{if exec", "{if system", "{if passthru",
            "{smarty::", NULL
        };
        size_t t;
        for (t = 0; SMARTY_TAGS[t] != NULL; ++t) {
            if (contains_ci(s, len, SMARTY_TAGS[t])) {
                return TRUE;
            }
        }
    }

    /* Node.js SSTI without a template marker: global.process or
     * root.process is a strong signal (process.mainModule.require
     * chains).  These are not seen in normal prose. */
    if (contains_ci(s, len, "global.process") ||
        contains_ci(s, len, "root.process") ||
        contains_ci(s, len, "process.mainmodule")) {
        return TRUE;
    }

    /* ERB backtick execution: <%= `cmd` %> — Ruby backtick in ERB
     * tag.  Also catches <%= system(...) %>. */
    {
        size_t i;
        for (i = 0; i + 4 <= len; ++i) {
            if (lower(s[i]) == '<' && lower(s[i + 1]) == '%' &&
                lower(s[i + 2]) == '=') {
                size_t j = i + 3;
                while (j < len && (s[j] == ' ' || s[j] == '\t' ||
                                   s[j] == '(')) {
                    j += 1;
                }
                if (j < len) {
                    /* backtick: <%= `cmd` %> */
                    if (s[j] == '`') {
                        return TRUE;
                    }
                    /* system call: <%= system("id") %> */
                    if (j + 6 <= len &&
                        lower(s[j]) == 's' && lower(s[j + 1]) == 'y' &&
                        lower(s[j + 2]) == 's' && lower(s[j + 3]) == 't' &&
                        lower(s[j + 4]) == 'e' && lower(s[j + 5]) == 'm') {
                        return TRUE;
                    }
                }
            }
        }
    }

    /* Jinja2 {{#with ...}} block tag and {{x=Object}} probe */
    {
        size_t i;
        for (i = 0; i + 3 <= len; ++i) {
            if (s[i] == '{' && s[i + 1] == '{' && s[i + 2] == '#') {
                return TRUE;
            }
            /* {{x=Object}} / {{x=...}} assignment probe */
            if (s[i] == '{' && s[i + 1] == '{') {
                size_t j = i + 2;
                while (j < len && (s[j] == ' ' || s[j] == '\t')) {
                    j += 1;
                }
                if (j + 2 < len && lower(s[j]) >= 'a' &&
                    lower(s[j]) <= 'z' && s[j + 1] == '=') {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}
