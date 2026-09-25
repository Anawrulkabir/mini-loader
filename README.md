# mini-loader

A from-scratch PE loader: it opens a 64-bit Windows `.exe`, maps it into
memory, resolves its imports to your own functions, and runs it — without
Windows. This is the core mechanism behind Wine and CrossOver, in ~600
lines you can read in one sitting.

## Files

```
src/pe.h        PE/COFF structures (only the fields we use)
src/pe_parse.c  step 1 — parse & validate headers, sections, imports
src/loader.c    step 2 — map, relocate, bind imports, jump to entry
test/hello.c    a freestanding Windows .exe (no C runtime)
test/reloc.c    same, but with absolute pointers (exercises .reloc)
test/check.sh   runs both, plus a set of deliberately malformed .exes
Makefile
```

## Build & run

```sh
make run
```

Expected tail of output:

```
== jumping to entry 0x... ==

hello from inside the mini-loader
```

Run the tests (the two sample programs, then malformed images that
must be rejected with an error rather than a crash or hang):

```sh
make test
```

Inspect any `.exe` without running it:

```sh
./parse some.exe
```

## How it works

A Windows program doesn't need Windows — it needs the functions it
imports from DLLs like `kernel32`. The loader:

1. **Reserves** `SizeOfImage` bytes with `mmap`.
2. **Copies** headers and each section to its RVA.
3. **Relocates**: the image assumes it loads at `ImageBase`; we add the
   delta to every absolute address the linker baked in (the `.reloc`
   DIR64 fixups).
4. **Binds imports**: for each imported name, writes the address of our
   stub into the Import Address Table slot the code calls through.
5. **Sets page permissions** per section (`.text` r-x, `.data` rw-).
6. **Jumps** to the entry point.

Every offset, size and RVA in a PE comes from the file, so both the
parser and the loader bounds-check them before use. A truncated or
corrupt `.exe` gets an error message, not a segfault. If an import has
no stub, the loader lists every missing name and refuses to run,
rather than binding it to NULL and crashing on the first call.

The one non-obvious detail: our stubs are marked `ms_abi`, because
Windows x64 passes arguments in `RCX, RDX, R8, R9` while the System V
ABI (Linux/macOS) uses `RDI, RSI, RDX, RCX`. Without that attribute the
arguments arrive in the wrong registers.

`test/hello.c` is built with `-nostdlib` and a custom entry point on
purpose: a normal CRT reads the TEB from the `gs` segment register,
which the host OS uses for its own thread-local storage. Faking that is
the next real hurdle (see below).

## Running this on macOS / Apple Silicon

The logic is identical; three build changes:

1. In the `Makefile`, set `CC = clang` and add `-arch x86_64` to
   `CFLAGS`. This builds the loader as an x86-64 Mach-O, so **Rosetta 2
   translates both the loader and the x86 Windows code** it runs.
   Install Rosetta once with `softwareupdate --install-rosetta`.
2. `mmap`, `mprotect`, `MAP_ANON`, `write`, `sysconf` all exist on
   macOS as-is. No source change needed.
3. You still need the mingw cross-compiler to build the test exe:
   `brew install mingw-w64`.

`ms_abi` works the same under clang, so the stub mechanism is unchanged.

## What's deliberately missing (the roadmap from here)

Each of these is where a real chunk of Wine's effort goes:

- **TEB/`gs` setup** — allocate a fake thread block and point a segment
  at it, so CRT-linked programs stop crashing on startup.
- **Real DLLs** — instead of hardcoded stubs, load the actual DLL,
  recursively load *its* imports, and run its entry point. Or keep
  faking, which is what Wine does for the Windows DLLs themselves.
- **Ordinal imports** — resolve by number, not just by name.
- **`user32`/`gdi32` on Cocoa** — the GUI layer. This is the majority
  of the work and where you should read Wine rather than reinvent.
- **Exception handling** — `.pdata`/`.xdata` unwinding for SEH.

Stop at any layer — you'll already understand exactly why some Windows
apps run under Wine and others don't.
