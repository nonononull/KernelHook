# SPDX-License-Identifier: GPL-2.0-or-later
# Host build for kh_crc. Builds with the system cc; no cross-compiler.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -std=c99 -pedantic

# install is not wired up yet; will be added by a future task when there is
# a real use case. Removed from .PHONY so the name cannot be invoked as a
# no-op phony target that silently succeeds.
.PHONY: all test clean

all: kh_crc

kh_crc: kh_crc.c
	$(CC) $(CFLAGS) -o $@ $<

test: kh_crc
	@# Minimal test target: run the built-in self-test. The full test driver
	@# (tests/run_tests.sh) is added in Task 7 with golden regression and
	@# Contract 1 independence checks. Once present, `test` delegates to it.
	@if [ -x ./tests/run_tests.sh ]; then                                  \
	    ./tests/run_tests.sh;                                              \
	else                                                                   \
	    ./kh_crc --mode=self-test;                                         \
	fi

clean:
	rm -f kh_crc *.o
