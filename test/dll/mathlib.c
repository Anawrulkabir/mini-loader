/* mathlib.c — a DLL with every kind of export (see mathlib.def):
 * by name, by ordinal only, a data export, and a forwarder to base.dll.
 * It imports base.dll itself, so loading it means loading that too. */
#include <stdio.h>
#include <windows.h>

int base_value(void);                 /* from base.dll */

int mathlib_calls;                    /* data export */

int add(int a, int b) { mathlib_calls++; return a + b; }
int mul(int a, int b) { mathlib_calls++; return a * b; }   /* ordinal only */
int magic(void)       { return base_value() + 1; }
const char *greet(void) { return "hello from mathlib.dll"; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)h;
    /* reserved is non-NULL for DLLs loaded at startup (static imports). */
    if (reason == DLL_PROCESS_ATTACH)
        printf("mathlib.dll: attach (%s)\n", reserved ? "static" : "dynamic");
    if (reason == DLL_PROCESS_DETACH) puts("mathlib.dll: detach");
    return TRUE;
}
