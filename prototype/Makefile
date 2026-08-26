# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0

CC = gcc
CFLAGS = -O2 -Wall -lpthread

all: adi_pe_loader

adi_pe_loader: pe_loader.c win32_shims.c shim_table.c adi_test.c win32_types.h win32_shims.h pe_loader.h
	$(CC) pe_loader.c win32_shims.c shim_table.c adi_test.c -O2 -Wall -o adi_pe_loader -lpthread

clean:
	rm -f adi_pe_loader *.o

test: adi_pe_loader
	./adi_pe_loader ./CoreADI64.dll
