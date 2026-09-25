/* crt.c — an ordinary C program, C runtime and all.
 *
 * Unlike hello.c this is built the normal way: mingw's CRT startup runs
 * first, reads the TEB through gs, sets up the heap, stdio, argv and
 * constructors, then calls main(). None of that works unless the loader
 * provides a TEB, so this is the test for teb.c.
 *
 * It then pokes at the TEB directly (gs:[0x30] and friends) to check
 * that what the loader built matches what Windows code expects.
 *
 * Built with __USE_MINGW_ANSI_STDIO=0, so printf is msvcrt's (i.e. our
 * stub, with a Windows va_list) rather than mingw's built-in one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

extern IMAGE_DOS_HEADER __ImageBase;   /* linker-provided: our own base */

static __thread int counter = 40;      /* thread-local, via TlsAlloc */
static int constructed;

__attribute__((constructor)) static void ctor(void) { constructed = 1; }
static void bye(void) { puts("atexit handler ran"); }

static const char *ok(int cond) { return cond ? "yes" : "NO"; }

int main(int argc, char **argv) {
    printf("argc=%d", argc);
    for (int i = 1; i < argc; i++) printf(" [%s]", argv[i]);
    printf("\n");
    printf("constructor ran: %s\n", ok(constructed));

    /* The TEB, the way Windows code finds it. */
    char   *teb  = (char *)__readgsqword(0x30);  /* NT_TIB.Self */
    NT_TIB *tib  = (NT_TIB *)teb;
    char   *peb  = (char *)__readgsqword(0x60);  /* ProcessEnvironmentBlock */
    char    here;
    printf("TEB self pointer: %s\n", ok(teb && tib->Self == (void *)teb));
    printf("stack within TEB bounds: %s\n",
           ok((void *)&here < tib->StackBase && (void *)&here >= tib->StackLimit));
    printf("PEB image base: %s\n", ok(*(void **)(peb + 0x10) == (void *)&__ImageBase));
    printf("thread id from TEB: %s\n",
           ok(GetCurrentThreadId() == (DWORD)*(ULONG_PTR *)(teb + 0x48)));

    SetLastError(1234);
    printf("last error in TEB: %s\n",
           ok(GetLastError() == 1234 && *(DWORD *)(teb + 0x68) == 1234));

    counter += 2;
    printf("thread-local: %d\n", counter);

    char *s = malloc(32);
    strcpy(s, "heap");
    printf("%s works\n", s);
    free(s);

    /* Windows-specific printf: `long` is 32 bits, wide strings are UTF-16. */
    printf("formats: %ld %lld %.2f %ls %I64x\n",
           -123456L, 1LL << 40, 3.14159, L"wide", 0xabcULL);
    fprintf(stderr, "to stderr\n");

    atexit(bye);
    return 3;
}
