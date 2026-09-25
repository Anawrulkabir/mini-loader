/* hello.c — a deliberately tiny Windows program.
 *
 * Built with -nostdlib and a custom entry point, so it has NO C runtime
 * startup. That means it imports only the three functions we name below
 * and never touches the TEB (the thread block Windows keeps in the gs
 * register), which is the thing that's hard to fake on macOS/Linux.
 *
 * Imports resolved from kernel32: GetStdHandle, WriteFile, ExitProcess.
 */

typedef unsigned int  u32;
typedef unsigned long long u64;

/* Minimal declarations of the Windows APIs we use. On x86-64 there is
 * only one calling convention, so no attribute is needed here — mingw
 * targets the Windows x64 ABI already. */
__declspec(dllimport) void *GetStdHandle(u32 nStdHandle);
__declspec(dllimport) int   WriteFile(void *h, const void *buf, u32 len,
                                      u32 *written, void *overlapped);
__declspec(dllimport) void  ExitProcess(u32 code);

#define STD_OUTPUT_HANDLE ((u32)-11)

static u32 slen(const char *s) { u32 n = 0; while (s[n]) n++; return n; }

/* Custom entry point (set via -e go). No argc/argv, no CRT. */
void go(void) {
    const char *msg = "hello from inside the mini-loader\n";
    void *out = GetStdHandle(STD_OUTPUT_HANDLE);
    u32 written = 0;
    WriteFile(out, msg, slen(msg), &written, 0);
    ExitProcess(0);
}
