#!/bin/sh
#
# Configure an instrumented build for coverage measurement.
# Uses clang's LLVM source-based coverage (llvm-profdata / llvm-cov).
#
set -e
cd src
make clean
export CC=clang
export CFLAGS="-ansi -g -O0 -fprofile-instr-generate -fcoverage-mapping -Wall -Wextra -Werror -pedantic"
# static lib + test binaries only: the .so link rule does not carry
# the profile runtime
make -e libinjection.a
make -e testdriver
make -e test_unit
make -e reader
