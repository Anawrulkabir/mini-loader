/* base.c — the bottom of the DLL chain: dlltest.exe -> mathlib.dll -> base.dll.
 * Loaded because mathlib.dll imports it, so it must be initialised
 * first and shut down last. */
#include <stdio.h>
#include <windows.h>

__declspec(dllexport) int base_value(void) { return 42; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)h; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) puts("base.dll: attach");
    if (reason == DLL_PROCESS_DETACH) puts("base.dll: detach");
    return TRUE;
}
