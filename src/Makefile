
AR=ar -r
# MAC
# AR=libtool -static

CC=cc
LD=ld
CFLAGS=-Wall -Wextra -Werror -pedantic -ansi -g -O3 -fPIC

INSTALL=install
PREFIX=/usr/local
INCLUDE_DIR=${PREFIX}/include
LIB_DIR=${PREFIX}/lib

LIBNAME=injection
STATICLIB_SUFFIX=a
STATICLIB=lib${LIBNAME}.${STATICLIB_SUFFIX}

SHAREDLIB_SUFFIX=so
SHAREDLIB=lib${LIBNAME}.${SHAREDLIB_SUFFIX}
# ABI version: bump on any breaking API/ABI change (major.so.ABI)
LIBRARY_VERSION=13

# platform-shared-library naming: ELF soname on Linux, install_name
# dylib on macOS
UNAME_S := $(shell uname -s 2>/dev/null || echo Linux)
ifeq ($(UNAME_S),Darwin)
SHAREDTARGET = lib${LIBNAME}.${LIBRARY_VERSION}.4.1.0.dylib
SHAREDFLAGS  = -dynamiclib -Wl,-install_name,${LIB_DIR}/lib${LIBNAME}.${LIBRARY_VERSION}.dylib
POSTBUILD    = ln -sf ${SHAREDTARGET} lib${LIBNAME}.${LIBRARY_VERSION}.dylib && ln -sf lib${LIBNAME}.${LIBRARY_VERSION}.dylib ${SHAREDLIB}lib${LIBNAME}.dylib
INSTALL_LINKS= ln -sf lib${LIBNAME}.${LIBRARY_VERSION}.4.1.0.dylib ${LIB_DIR}/lib${LIBNAME}.${LIBRARY_VERSION}.dylib && ln -sf lib${LIBNAME}.${LIBRARY_VERSION}.dylib ${LIB_DIR}/lib${LIBNAME}.dylib
else
SHAREDTARGET = ${SHAREDLIB}.${LIBRARY_VERSION}.4.1.0
SHAREDFLAGS  = -shared -Wl,-soname,${SHAREDLIB}.${LIBRARY_VERSION}
POSTBUILD    = ln -sf ${SHAREDTARGET} ${SHAREDLIB}.${LIBRARY_VERSION} && ln -sf ${SHAREDLIB}.${LIBRARY_VERSION} ${SHAREDLIB}
INSTALL_LINKS= ln -sf libinjection.so.${LIBRARY_VERSION}.4.1.0 ${LIB_DIR}/libinjection.so.${LIBRARY_VERSION} && ln -sf libinjection.so.${LIBRARY_VERSION} ${LIB_DIR}/libinjection.so
endif

HEADERS=libinjection.h libinjection_sqli.h libinjection_sqli_data.h libinjection_html5.h libinjection_xss.h libinjection_normalize.h libinjection_classify.h libinjection_trav.h libinjection_ssrf.h libinjection_deser.h libinjection_crlf.h libinjection_cmd.h libinjection_ssti.h libinjection_nosql.h libinjection_ldap.h libinjection_code.h libinjection_recon.h libinjection_redirect.h

SOURCES=libinjection_sqli.c \
	libinjection_html5.c \
	libinjection_xss.c \
	libinjection_normalize.c \
	libinjection_classify.c \
	libinjection_trav.c \
	libinjection_ssrf.c \
	libinjection_deser.c \
	libinjection_crlf.c \
	libinjection_cmd.c \
	libinjection_ssti.c \
	libinjection_nosql.c \
	libinjection_ldap.c \
	libinjection_code.c \
	libinjection_recon.c \
	libinjection_redirect.c

OBJECTS=libinjection_sqli.o \
	libinjection_html5.o \
	libinjection_xss.o \
	libinjection_normalize.o \
	libinjection_classify.o \
	libinjection_trav.o \
	libinjection_ssrf.o \
	libinjection_deser.o \
	libinjection_crlf.o \
	libinjection_cmd.o \
	libinjection_ssti.o \
	libinjection_nosql.o \
	libinjection_ldap.o \
	libinjection_code.o \
	libinjection_recon.o \
	libinjection_redirect.o

SAMPLES=html5 sqli fptool injection
TESTDRIVERS=reader testdriver testspeedxss testspeedsqli test_unit

all: ${SHAREDLIB} ${STATICLIB}
#all: ${STATICLIB}

samples: ${SAMPLES}
.PHONY: samples

fingerprints.txt: make_parens.py
	./make_parens.py < fingerprints.txt > fingerprints2.txt
	mv fingerprints2.txt fingerprints.txt

fingerprints:
	./make_parens.py < fingerprints.txt > fingerprints2.txt
	mv fingerprints2.txt fingerprints.txt
.PHONY: fingerprints

sqlparse_data.json: sqlparse_map.py fingerprints
	./sqlparse_map.py > sqlparse_data.json

libinjection_sqli_data.h: sqlparse2c.py sqlparse_data.json
	./sqlparse2c.py < sqlparse_data.json > libinjection_sqli_data.h

libinjection_sqli.o: libinjection.h libinjection_sqli.c libinjection_sqli.h libinjection_sqli_data.h
	${CC} ${CFLAGS} -c -o libinjection_sqli.o libinjection_sqli.c

libinjection_xss.o: libinjection.h libinjection_xss.c libinjection_xss.h libinjection_html5.h
	${CC} ${CFLAGS} -c -o libinjection_xss.o libinjection_xss.c

libinjection_html5.o: libinjection.h libinjection_html5.c libinjection_html5.h
	${CC} ${CFLAGS} -c -o libinjection_html5.o libinjection_html5.c

libinjection_normalize.o: libinjection.h libinjection_normalize.c libinjection_normalize.h
	${CC} ${CFLAGS} -c -o libinjection_normalize.o libinjection_normalize.c

libinjection_classify.o: libinjection.h libinjection_classify.c libinjection_classify.h libinjection_normalize.h libinjection_sqli.h libinjection_xss.h libinjection_trav.h libinjection_ssrf.h libinjection_deser.h libinjection_crlf.h libinjection_cmd.h libinjection_ssti.h libinjection_nosql.h libinjection_ldap.h libinjection_code.h libinjection_recon.h libinjection_redirect.h
	${CC} ${CFLAGS} -c -o libinjection_classify.o libinjection_classify.c

libinjection_trav.o: libinjection_trav.h libinjection_trav.c
	${CC} ${CFLAGS} -c -o libinjection_trav.o libinjection_trav.c

libinjection_ssrf.o: libinjection_ssrf.h libinjection_ssrf.c
	${CC} ${CFLAGS} -c -o libinjection_ssrf.o libinjection_ssrf.c

libinjection_deser.o: libinjection_deser.h libinjection_deser.c
	${CC} ${CFLAGS} -c -o libinjection_deser.o libinjection_deser.c

libinjection_crlf.o: libinjection_crlf.h libinjection_crlf.c
	${CC} ${CFLAGS} -c -o libinjection_crlf.o libinjection_crlf.c

libinjection_cmd.o: libinjection_cmd.h libinjection_cmd.c
	${CC} ${CFLAGS} -c -o libinjection_cmd.o libinjection_cmd.c

libinjection_ssti.o: libinjection_ssti.h libinjection_ssti.c
	${CC} ${CFLAGS} -c -o libinjection_ssti.o libinjection_ssti.c

libinjection_nosql.o: libinjection_nosql.h libinjection_nosql.c
	${CC} ${CFLAGS} -c -o libinjection_nosql.o libinjection_nosql.c

libinjection_ldap.o: libinjection_ldap.h libinjection_ldap.c
	${CC} ${CFLAGS} -c -o libinjection_ldap.o libinjection_ldap.c

libinjection_code.o: libinjection_code.h libinjection_code.c
	${CC} ${CFLAGS} -c -o libinjection_code.o libinjection_code.c

libinjection_recon.o: libinjection_recon.h libinjection_recon.c
	${CC} ${CFLAGS} -c -o libinjection_recon.o libinjection_recon.c

libinjection_redirect.o: libinjection_redirect.h libinjection_redirect.c
	${CC} ${CFLAGS} -c -o libinjection_redirect.o libinjection_redirect.c

${SHAREDLIB}: ${OBJECTS}
	$(CC) $+ ${SHAREDFLAGS} -lc -o ${SHAREDTARGET}
	@${POSTBUILD}

${STATICLIB}: ${OBJECTS}
	rm -f ${STATICLIB}
	${AR} ${STATICLIB} ${OBJECTS}

check: ${TESTDRIVERS}
	@make injection
	@./test-cli.sh
	@./test_unit
	@./testdriver -q ../tests/test-sqli-redteam-*.txt \
	              ../tests/test-sqli-precision-*.txt \
	              ../tests/test-xss-redteam-*.txt \
	              ../tests/test-xss-negative-*.txt \
	              ../tests/test-trav-*.txt \
	              ../tests/test-ssrf-*.txt \
	              ../tests/test-deser-*.txt \
	              ../tests/test-crlf-*.txt \
	              ../tests/test-cmd-*.txt \
	              ../tests/test-ssti-*.txt \
	              ../tests/test-nosql-*.txt \
	              ../tests/test-ldap-*.txt \
	              ../tests/test-code-*.txt \
	              ../tests/test-recon-*.txt \
	              ../tests/test-redirect-*.txt
	@./test-driver.sh test-unit.sh
	@./test-driver.sh test-samples-sqli-negative.sh
	@./test-driver.sh test-samples-sqli-positive.sh
	@./test-driver.sh test-samples-xss-positive.sh

# remove speed checks for now
#	@./test-driver.sh test-speed-xss.sh
#	@./test-driver.sh test-speed-sqli.sh

test: check
.PHONY: check test

reader: reader.c ${STATICLIB}
	${CC} ${CFLAGS} -o reader reader.c -L. ${STATICLIB}

sqli: sqli_cli.c ${STATICLIB}
	rm -f sqli
	${CC} ${CFLAGS} -o sqli sqli_cli.c -L. ${STATICLIB}

html5: html5_cli.c ${STATICLIB}
	${CC} ${CFLAGS} -o html5 html5_cli.c -L. ${STATICLIB}

testdriver: testdriver.c ${STATICLIB}
	${CC} ${CFLAGS} -o testdriver testdriver.c -L. ${STATICLIB}

test_unit: test_unit.c ${STATICLIB}
	${CC} ${CFLAGS} -o test_unit test_unit.c -L. ${STATICLIB}

testspeedsqli: test_speed_sqli.c ${STATICLIB}
	${CC} ${CFLAGS} -o testspeedsqli test_speed_sqli.c -L. ${STATICLIB}

testspeedxss: test_speed_xss.c ${STATICLIB}
	${CC} ${CFLAGS} -o testspeedxss test_speed_xss.c -L. ${STATICLIB}

fptool: fptool.c ${STATICLIB}
	${CC} ${CFLAGS} -o fptool fptool.c -L. ${STATICLIB}

injection: injection_cli.c ${STATICLIB}
	${CC} ${CFLAGS} -o injection injection_cli.c -L. ${STATICLIB}

install: all
	${INSTALL} -d ${INCLUDE_DIR}
	${INSTALL} -c ${HEADERS} ${INCLUDE_DIR}
	${INSTALL} -d ${LIB_DIR}
	${INSTALL} -c ${STATICLIB} ${LIB_DIR}
	${INSTALL} -c ${SHAREDTARGET} ${LIB_DIR}
	@${INSTALL_LINKS}
	ldconfig 2>/dev/null || true

.PHONY: install

clean:
	@rm -f *.so *.a *.o *.dylib *.lo *.gch
	@rm -f *~
	@rm -f *.log
	@rm -f ${SAMPLES} ${TESTDRIVERS}
	@rm -f *.gcno
	@rm -rf *.dSYM


#---- CLANG STATIC ANALYZER
#
#
#
# We are not using scan-analyze since it depends on perl
# Using clang directly produces text output which is fine for
# automated testing.  Oddly -Werror doesn't work here, and
# we have to test if any output occurred or not.  This done by
# piping output to a file and then checking what it contains.
#
# Open to better ideas here.
#

# ubuntu adds "-3.7" suffix
CLANG_VERSION=

analyze:
	rm -f /tmp/libinjection-analyze.txt
	clang${CLANG_VERSION} \
	-I. --analyze \
	-Xanalyzer -analyzer-checker=alpha.core.BoolAssignment \
	-Xanalyzer -analyzer-checker=alpha.core.CastSize \
	-Xanalyzer -analyzer-checker=alpha.core.FixedAddr \
	-Xanalyzer -analyzer-checker=alpha.core.IdenticalExpr \
	-Xanalyzer -analyzer-checker=alpha.core.PointerArithm \
	-Xanalyzer -analyzer-checker=alpha.core.PointerSub \
	-Xanalyzer -analyzer-checker=alpha.core.SizeofPtr \
	-Xanalyzer -analyzer-checker=alpha.core.TestAfterDivZero \
	-Xanalyzer -analyzer-checker=alpha.security.ArrayBound \
	-Xanalyzer -analyzer-checker=alpha.security.MallocOverflow \
	-Xanalyzer -analyzer-checker=alpha.security.ReturnPtrRange \
	-Xanalyzer -analyzer-checker=alpha.unix.cstring.BufferOverlap \
	-Xanalyzer -analyzer-checker=alpha.unix.cstring.OutOfBounds \
	libinjection*.c 2>&1 | tee /tmp/libinjection-analyze.txt
	test ! -s /tmp/libinjection-analyze.txt

.PHONY: analyze
