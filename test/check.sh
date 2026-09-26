#!/bin/sh
# check.sh — run the test programs and a few malformed images.
#
# The good images must print what they should; the bad ones must be
# rejected with a clean error (nonzero exit, no crash, no hang).
# Needs python3 to build the malformed images; skipped without it.
set -u
cd "$(dirname "$0")/.."
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fail=0

ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }

echo "== good images =="

out=$(./loader test/hello.exe 2>&1); rc=$?
case "$out" in *"hello from inside the mini-loader"*) [ $rc -eq 0 ] && ok hello || bad "hello (exit $rc)";;
                *) bad "hello (output)";; esac

./loader test/reloc.exe >"$T/out" 2>"$T/err"; rc=$?
if grep -q "relocated pointer 1" "$T/out" && grep -q "relocated pointer 2" "$T/out" \
   && grep -q "goes to stderr" "$T/err" && ! grep -q "goes to stderr" "$T/out" \
   && [ $rc -eq 7 ]; then ok "reloc (DIR64 fixups, stderr, exit code)"
else bad "reloc (exit $rc)"; fi

./loader test/crt.exe a "b c" >"$T/out" 2>"$T/err"; rc=$?
crt_ok=1
for want in "argc=3 [a] [b c]" "constructor ran: yes" "TEB self pointer: yes" \
            "stack within TEB bounds: yes" "PEB image base: yes" \
            "thread id from TEB: yes" "last error in TEB: yes" "thread-local: 42" \
            "heap works" "formats: -123456 1099511627776 3.14 wide abc" \
            "atexit handler ran"; do
    grep -qF "$want" "$T/out" || { echo "        missing: $want"; crt_ok=0; }
done
grep -q "to stderr" "$T/err" || { echo "        missing stderr line"; crt_ok=0; }
if [ $crt_ok -eq 1 ] && [ $rc -eq 3 ]; then ok "crt (CRT startup, TEB, argv, atexit, printf)"
else bad "crt (exit $rc)"; fi

# Real DLLs: the output must match exactly, since the order of the
# attach/detach lines is part of what's being tested.
./loader test/dlltest.exe 2>"$T/err" | sed -n '/^== loaded/,$p' | grep -v '^== ' >"$T/out"
rc=$?
cat >"$T/want" <<'WANT'
base.dll: attach
mathlib.dll: attach (static)

main: start
greet: hello from mathlib.dll
add(2, 3) = 5
mul(6, 7) = 42 (by ordinal)
magic() = 43 (via base.dll)
forty_two() = 42 (forwarded)
mathlib_calls = 2 (data export)
GetModuleHandle(mathlib) matches LoadLibrary: yes
GetProcAddress(#7)(3, 4) = 12
GetProcAddress(nope) is NULL: yes
plugin.dll: attach
plugin says: demo plugin
plugin.dll: detach
FreeLibrary(plugin): ok
LoadLibrary(missing.dll) is NULL: yes
module file name ends with dlltest.exe: yes
main: end
mathlib.dll: detach
base.dll: detach
WANT
if diff "$T/want" "$T/out" >"$T/diff" && [ $rc -eq 0 ]; then
    ok "dlls (load order, ordinals, forwarders, data, LoadLibrary, detach)"
else
    bad "dlls (exit $rc)"; sed 's/^/        /' "$T/diff"
fi

# Native TLS needs a compiler that emits it; mingw gcc doesn't. Linked
# without relocations, so it also covers loading at ImageBase.
if command -v clang >/dev/null 2>&1 && \
   clang --target=x86_64-w64-windows-gnu -fno-emulated-tls \
         -isystem /usr/x86_64-w64-mingw32/include -D__USE_MINGW_ANSI_STDIO=0 \
         -O1 -c -o "$T/tls.o" test/tls.c 2>/dev/null && \
   ${MINGW:-x86_64-w64-mingw32-gcc} -Wl,--disable-dynamicbase,--disable-reloc-section \
         -o "$T/tls.bin" "$T/tls.o" 2>/dev/null; then
    out=$(./loader "$T/tls.bin" 2>&1); rc=$?
    case "$out" in
    *"native tls 8 2"*)
        [ $rc -eq 0 ] && ok "tls (gs:[0x58], stripped relocs)" || bad "tls (exit $rc)";;
    *"can't be loaded at"*)
        # Something else owns ImageBase in this process (ASan's shadow
        # memory does); refusing is the right answer, but untested.
        echo "  skip  tls (ImageBase not available in this process)";;
    *)  bad "tls (output)";;
    esac
else
    echo "  skip  tls (needs clang that can target x86_64-w64-windows-gnu)"
fi

echo "== malformed images =="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  skip  (python3 not found)"
    exit $fail
fi

python3 - "$T" <<'PY'
import struct, sys
out = sys.argv[1]
hello = open("test/hello.exe", "rb").read()
reloc = open("test/reloc.exe", "rb").read()
crt   = open("test/crt.exe", "rb").read()

def put(name, data): open(f"{out}/{name}.exe", "wb").write(data)

def layout(d):
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    nsec, optsz = struct.unpack_from("<H", d, lf + 6)[0], struct.unpack_from("<H", d, lf + 20)[0]
    opt = lf + 24
    secs = []
    for i in range(nsec):
        o = opt + optsz + 40 * i
        va, rawsz, rawptr = struct.unpack_from("<III", d, o + 12)
        secs.append((o, va, rawsz, rawptr))
    return lf, opt, secs

def rva_to_off(d, rva):
    for _, va, rawsz, rawptr in layout(d)[2]:
        if va <= rva < va + rawsz: return rawptr + rva - va
    raise ValueError(hex(rva))

put("empty", b"")
put("truncated_dos", hello[:32])
put("truncated_headers", hello[:0x100])

d = bytearray(hello); struct.pack_into("<I", d, 0x3C, 0x7FFFFFF0); put("bad_lfanew", d)

d = bytearray(hello); lf, opt, secs = layout(d)
struct.pack_into("<I", d, secs[0][0] + 20, 0x7FFFFFF0); put("bad_section_ptr", d)

d = bytearray(hello); lf, opt, secs = layout(d)
struct.pack_into("<H", d, lf + 6, 0xFFFF); put("too_many_sections", d)

d = bytearray(hello); lf, opt, secs = layout(d)
struct.pack_into("<I", d, secs[0][0] + 12, 0x7FFF0000); put("section_past_image", d)

# a relocation block with BlockSize 0 used to loop forever
d = bytearray(reloc); lf, opt, _ = layout(d)
rel_rva = struct.unpack_from("<I", d, opt + 112 + 8 * 5)[0]
struct.pack_into("<I", d, rva_to_off(d, rel_rva) + 4, 0); put("zero_reloc_block", d)

# relocation pointing far outside the image
d = bytearray(reloc)
struct.pack_into("<I", d, rva_to_off(d, rel_rva), 0x7FFF0000); put("reloc_out_of_range", d)

# an import we have no stub for
d = bytearray(hello); i = d.index(b"WriteFile\0"); d[i:i+9] = b"WriteFilX"; put("unresolved_import", d)

# import directory pointing outside the image
d = bytearray(hello); lf, opt, _ = layout(d)
struct.pack_into("<I", d, opt + 112 + 8 * 1, 0x7FFF0000); put("bad_import_dir", d)

# TLS directory pointing outside the image
d = bytearray(crt); lf, opt, _ = layout(d)
struct.pack_into("<I", d, opt + 112 + 8 * 9, 0x7FFF0000); put("bad_tls_dir", d)

# a TLS callback that points outside the image
d = bytearray(crt); lf, opt, _ = layout(d)
base = struct.unpack_from("<Q", d, opt + 24)[0]
tls = rva_to_off(d, struct.unpack_from("<I", d, opt + 112 + 8 * 9)[0])
cbs = struct.unpack_from("<Q", d, tls + 24)[0]
struct.pack_into("<Q", d, rva_to_off(d, cbs - base), 0x7FFFFFFF0000); put("bad_tls_callback", d)

# DLL cases: each gets its own directory with the exe and its DLLs, so
# the loader finds the (possibly broken) copies next to the exe.
import os, shutil
def dll_case(name, mutate):
    d = f"{out}/{name}"; os.mkdir(d)
    for f in ("dlltest.exe", "mathlib.dll", "base.dll", "plugin.dll"):
        shutil.copy(f"test/{f}", d)
    mutate(d)

def patch(path, fn):
    d = bytearray(open(path, "rb").read()); fn(d); open(path, "wb").write(d)

# a DLL the exe imports doesn't exist
dll_case("missing_dll", lambda d: os.remove(f"{d}/mathlib.dll"))

# export directory pointing outside the DLL
def bad_exports(d):
    def f(b):
        lf, opt, _ = layout(b)
        struct.pack_into("<I", b, opt + 112, 0x7FFF0000)
    patch(f"{d}/mathlib.dll", f)
dll_case("bad_export_dir", bad_exports)

# a forwarder back to itself: mathlib.forty_two -> mathlib.#8 (itself)
def fwd_loop(d):
    def f(b):
        i = b.index(b"base.base_value\0")
        b[i:i+16] = b"mathlib.#8\0".ljust(16, b"\0")
    patch(f"{d}/mathlib.dll", f)
dll_case("forwarder_loop", fwd_loop)

# DllMain returns FALSE: turn base.dll's "return TRUE" into FALSE by
# making its entry point return 0 immediately (xor eax,eax; ret)
def dllmain_fails(d):
    def f(b):
        lf, opt, _ = layout(b)
        entry = struct.unpack_from("<I", b, opt + 16)[0]
        o = rva_to_off(b, entry); b[o:o+3] = b"\x31\xc0\xc3"
    patch(f"{d}/base.dll", f)
dll_case("dllmain_fails", dllmain_fails)
PY

# Run with a timeout where available, so a hang shows as a failure.
TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout 5"

for f in "$T"/*.exe "$T"/*/dlltest.exe; do
    name=$(basename "$f" .exe)
    [ "$name" = dlltest ] && name=$(basename "$(dirname "$f")")

    # parse only dumps headers: it may accept an image that can't load,
    # but must never crash on one. (124 = timeout, >128 = signal.)
    $TO ./parse "$f" >/dev/null 2>&1; rc=$?
    if [ $rc -le 1 ]; then ok "parse  $name"; else bad "parse  $name (exit $rc)"; fi

    # loader must reject every one of them cleanly.
    $TO ./loader "$f" >/dev/null 2>"$T/err"; rc=$?
    if [ $rc -eq 1 ]; then ok "loader $name: $(tail -n 1 "$T/err")"
    else bad "loader $name (exit $rc)"; fi
done

exit $fail
