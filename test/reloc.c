/* reloc.c — exercises base relocations and the stderr handle.
 *
 * `lines` is an array of pointers, i.e. absolute addresses the linker
 * bakes in assuming ImageBase. Loaded anywhere else, each one needs a
 * DIR64 fixup from .reloc, or the loop below reads garbage.
 *
 * Like hello.c: -nostdlib, custom entry, only kernel32 imports.
 */

typedef unsigned int u32;

__declspec(dllimport) void *GetStdHandle(u32 nStdHandle);
__declspec(dllimport) int   WriteFile(void *h, const void *buf, u32 len,
                                      u32 *written, void *overlapped);
__declspec(dllimport) void  ExitProcess(u32 code);

#define STD_OUTPUT_HANDLE ((u32)-11)
#define STD_ERROR_HANDLE  ((u32)-12)

static const char *lines[] = {
    "relocated pointer 1\n",
    "relocated pointer 2\n",
};

static u32 slen(const char *s) { u32 n = 0; while (s[n]) n++; return n; }

void go(void) {
    void *out = GetStdHandle(STD_OUTPUT_HANDLE);
    void *err = GetStdHandle(STD_ERROR_HANDLE);
    u32 written = 0;
    for (u32 i = 0; i < sizeof(lines) / sizeof(lines[0]); i++)
        WriteFile(out, lines[i], slen(lines[i]), &written, 0);
    const char *e = "this line goes to stderr\n";
    WriteFile(err, e, slen(e), &written, 0);
    ExitProcess(7);
}
