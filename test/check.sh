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
PY

# Run with a timeout where available, so a hang shows as a failure.
TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout 5"

for f in "$T"/*.exe; do
    name=$(basename "$f" .exe)

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
