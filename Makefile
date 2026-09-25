# mini-loader build
#
# On macOS/Apple Silicon, change CC to `clang` and add `-arch x86_64`
# to CFLAGS so Rosetta translates the loader (and the x86 Windows code
# it runs) to ARM. See README. On Linux x86-64 the defaults just work.

CC      ?= cc
CFLAGS  ?= -Wall -Wextra -g -O0
MINGW   ?= x86_64-w64-mingw32-gcc

all: parse loader test/hello.exe test/reloc.exe test/crt.exe

# Step 1: the parser (standalone, for inspecting a .exe)
parse: src/pe_parse.c src/pe.h
	$(CC) $(CFLAGS) -DPARSE_MAIN -o $@ src/pe_parse.c

# Step 2: the loader (includes the parser as one TU)
loader: src/loader.c src/pe_parse.c src/pe.h src/teb.c src/teb.h src/win32.c
	$(CC) $(CFLAGS) -o $@ src/loader.c

# The freestanding test program. -nostdlib drops the CRT; -e go sets
# our custom entry; -lkernel32 supplies the import library.
test/hello.exe: test/hello.c
	$(MINGW) -nostdlib -e go -O0 -o $@ test/hello.c -lkernel32

# Same, but with absolute pointers, so it carries DIR64 relocations.
test/reloc.exe: test/reloc.c
	$(MINGW) -nostdlib -e go -O0 -o $@ test/reloc.c -lkernel32

# A normal C program: full CRT startup, which needs the TEB.
# __USE_MINGW_ANSI_STDIO=0 makes printf msvcrt's, i.e. our stub.
test/crt.exe: test/crt.c
	$(MINGW) -O1 -D__USE_MINGW_ANSI_STDIO=0 -o $@ test/crt.c

run: all
	./loader test/hello.exe

# Good images must run; malformed ones must be rejected cleanly.
test: all
	./test/check.sh

clean:
	rm -f parse loader test/*.exe

.PHONY: all run test clean
