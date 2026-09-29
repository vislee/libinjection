/**
 * Copyright 2012-2016 Nick Galbreath / libinjection contributors
 * Copyright (c) 2026 vislee
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 */

#include <string.h>

#include "libinjection_code.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

static const char* NEEDLES[] = {
    "<?php"
    , "<?="
    , "<%@"
    , "eval(base64"
    , "eval(\""
    , "eval('"
    , "system(\""
    , "system('"
    , "shell_exec("
    , "passthru(\""
    , "runtime.getruntime"
    , "processbuilder"
    , "subprocess.popen"
    , "subprocess.call"
    , "__import__('os"
    , "__import__(\"os"
    , "os.popen('"
    , "os.popen(\""
    , "os.system('"
    , "os.system(\""
    , "popen('"
    , "popen(\""
    , "expect_popen("
    , "${@eval("
    , NULL
};

static char lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char) (c + 0x20);
    }
    return c;
}

int libinjection_code(const char* s, size_t len)
{
    size_t n;
    size_t i;
    size_t j;

    for (n = 0; NEEDLES[n] != NULL; ++n) {
        size_t nlen = strlen(NEEDLES[n]);
        if (len < nlen) {
            continue;
        }
        for (i = 0; i + nlen <= len; ++i) {
            int match = 1;
            for (j = 0; j < nlen; ++j) {
                if (lower(s[i + j]) != lower(NEEDLES[n][j])) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                return TRUE;
            }
        }
    }
    return FALSE;
}
