#!/bin/sh
#
# XSS Sample Tests
#
# Threshold was 18 when the style attribute was banned outright.
# style= is now inspected for active content (expression(), url(,
# javascript:, ...) instead, which trades ~720 Shazzer fuzz-canary
# lines (benign-looking style values that needed browser quirks to
# execute) for a large real-world false-positive reduction
# (style="color: blue" no longer alerts).  See docs/OPTIMIZATION_PLAN.md.
#
set -e
${VALGRIND} ./reader -t -i -x -m 800 ../data/xss*
