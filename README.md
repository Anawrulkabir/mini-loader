# mini-loader

A from-scratch PE loader: it opens a 64-bit Windows `.exe`, maps it into
memory, resolves its imports to your own functions, and runs it — without
Windows. It runs ordinary C programs, C runtime and all, not just
hand-built ones. This is the core mechanism behind Wine and CrossOver,
in ~1,400 lines you can read in a couple of sittings.

## Files

```
src/pe.h        PE/COFF structures (only the fields we use)
src/pe_parse.c  step 1 — parse & validate headers, sections, imports
src/loader.c    step 2 — map, relocate, bind imports, jump to entry
src/teb.h       the TEB and PEB (Windows' per-thread/process blocks)
src/teb.c       step 3 — build a TEB, point gs at it, set up TLS
src/win32.c     the fake kernel32/msvcrt the program's imports bind to
test/hello.c    a freestanding Windows .exe (no C runtime)
test/reloc.c    same, but with absolute pointers (exercises .reloc)
test/crt.c      a normal C program: CRT startup, argv, printf, atexit
test/tls.c      native thread-locals via gs:[0x58] (built with clang)
test/check.sh   runs those, plus a set of deliberately malformed .exes
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

A normal C program, with arguments passed through to its `main`:

```sh
./loader test/crt.exe some args
```

Run the tests (the sample programs, then malformed images that must be
rejected with an error rather than a crash or hang):

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
6. **Builds a thread** for it: a TEB, with `gs` pointing at it, and the
   image's static TLS block. Runs the TLS callbacks.
7. **Jumps** to the entry point.

Every offset, size and RVA in a PE comes from the file, so both the
parser and the loader bounds-check them before use. A truncated or
corrupt `.exe` gets an error message, not a segfault. If an import has
no stub, the loader lists every missing name and refuses to run,
rather than binding it to NULL and crashing on the first call.

The one non-obvious detail: our stubs are marked `ms_abi`, because
Windows x64 passes arguments in `RCX, RDX, R8, R9` while the System V
ABI (Linux/macOS) uses `RDI, RSI, RDX, RCX`. Without that attribute the
arguments arrive in the wrong registers. That's why even `memcpy` gets
a wrapper in `win32.c` rather than binding straight to the host's.

Two more ABI differences appear once a C runtime is involved: `long` is
32 bits on Windows and 64 on Linux/macOS, and a Windows `va_list` is a
different type from the host's. So the `printf` family can't forward to
the host's `vprintf`; `ms_vfprintf` walks the format string and fetches
each argument the Windows way.

## The thread block (TEB)

Windows keeps a per-thread block, the TEB, and points the `gs` register
at it. Code finds it with a single instruction: `mov rax, gs:[0x30]`
reads the TEB's pointer to itself. The C runtime does this within its
first few instructions, which is why `test/hello.c` is built with
`-nostdlib`. Without a TEB, every normal `.exe` crashes before `main`.

`teb.c` allocates one and fills in what programs read:

| offset | field | used for |
|---|---|---|
| `0x08` / `0x10` | `StackBase` / `StackLimit` | the CRT's per-thread id, stack checks |
| `0x30` | `Self` | finding the TEB at all |
| `0x48` | `ClientId.UniqueThread` | `GetCurrentThreadId` |
| `0x58` | `ThreadLocalStoragePointer` | static TLS (`gs:[0x58][index]`) |
| `0x60` | `ProcessEnvironmentBlock` | the PEB, and its `ImageBaseAddress` |
| `0x68` | `LastErrorValue` | `GetLastError` / `SetLastError` |
| `0x1480` | `TlsSlots[64]` | `TlsAlloc` / `TlsGetValue` |

Then it points `gs` at it with `arch_prctl(ARCH_SET_GS)`. On x86-64
Linux this is free to do: glibc keeps its own thread data behind `fs`
and never touches `gs`, so the two sides don't collide. Wine does the
same.

Static TLS comes from the image's TLS directory: a template to copy
into a fresh block, an index to assign, and callbacks to run before the
entry point (mingw's CRT uses one). mingw's gcc emits emulated TLS
instead (`TlsAlloc` and friends), so `test/tls.c` is compiled with
clang to get real `gs:[0x58]` accesses.

It's one thread only: `CreateThread` would need a TEB per thread, and
the critical-section stubs are no-ops.

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

The TEB is the exception. macOS uses `gs` for its own thread data, so
the loader can't point it at a TEB there. It warns and runs anyway:
`hello.exe` and `reloc.exe` still work, but CRT-linked programs like
`crt.exe` crash at startup. Wine gets around this on macOS by
reserving pthread keys so that the slots at `gs:[0x30]` and `gs:[0x58]`
hold its TEB values, which is a good next step to read about. This
path is untested here.

## What's deliberately missing (the roadmap from here)

Each of these is where a real chunk of Wine's effort goes:

- **Threads** — `CreateThread`, with a TEB and TLS block for each, and
  real critical sections.
- **More of msvcrt** — `win32.c` has what mingw's CRT and simple
  programs need: no files, no `scanf`, no locales. Unresolved imports
  are listed by name, so the next stub to write is never a mystery.
- **Real DLLs** — instead of hardcoded stubs, load the actual DLL,
  recursively load *its* imports, and run its entry point. Or keep
  faking, which is what Wine does for the Windows DLLs themselves.
- **Ordinal imports** — resolve by number, not just by name.
- **`user32`/`gdi32` on Cocoa** — the GUI layer. This is the majority
  of the work and where you should read Wine rather than reinvent.
- **Exception handling** — `.pdata`/`.xdata` unwinding for SEH.

Stop at any layer — you'll already understand exactly why some Windows
apps run under Wine and others don't.
