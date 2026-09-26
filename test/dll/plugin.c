/* plugin.c — not imported by anything; dlltest.exe loads it at run time
 * with LoadLibraryA and finds its functions with GetProcAddress. */
#include <stdio.h>
#include <windows.h>

__declspec(dllexport) const char *plugin_name(void) { return "demo plugin"; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)h; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) puts("plugin.dll: attach");
    if (reason == DLL_PROCESS_DETACH) puts("plugin.dll: detach");
    return TRUE;
}
