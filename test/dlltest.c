/* dlltest.c — exercises real DLL loading.
 *
 * Imports from mathlib.dll by name (add, greet, magic), by ordinal only
 * (mul, #7), a data export (mathlib_calls) and a forwarder (forty_two,
 * really base.dll!base_value). Then loads plugin.dll at run time.
 *
 * Expected order of events: base.dll attaches before mathlib.dll (it's
 * a dependency), both before main; at exit they detach in reverse.
 */
#include <stdio.h>
#include <windows.h>

__declspec(dllimport) int add(int, int);
__declspec(dllimport) int mul(int, int);
__declspec(dllimport) int magic(void);
__declspec(dllimport) int forty_two(void);
__declspec(dllimport) const char *greet(void);
__declspec(dllimport) int mathlib_calls;

typedef const char *(*NameFn)(void);
typedef int (*MulFn)(int, int);

int main(void) {
    puts("main: start");
    printf("greet: %s\n", greet());
    printf("add(2, 3) = %d\n", add(2, 3));
    printf("mul(6, 7) = %d (by ordinal)\n", mul(6, 7));
    printf("magic() = %d (via base.dll)\n", magic());
    printf("forty_two() = %d (forwarded)\n", forty_two());
    printf("mathlib_calls = %d (data export)\n", mathlib_calls);

    HMODULE m = GetModuleHandleA("MATHLIB");
    printf("GetModuleHandle(mathlib) matches LoadLibrary: %s\n",
           m && m == LoadLibraryA("mathlib.dll") ? "yes" : "no");
    MulFn m7 = (MulFn)GetProcAddress(m, (LPCSTR)(ULONG_PTR)7);
    printf("GetProcAddress(#7)(3, 4) = %d\n", m7 ? m7(3, 4) : -1);
    printf("GetProcAddress(nope) is NULL: %s\n",
           GetProcAddress(m, "nope") == NULL ? "yes" : "no");

    HMODULE p = LoadLibraryA("plugin.dll");
    NameFn name = p ? (NameFn)GetProcAddress(p, "plugin_name") : NULL;
    printf("plugin says: %s\n", name ? name() : "(not loaded)");
    printf("FreeLibrary(plugin): %s\n", p && FreeLibrary(p) ? "ok" : "failed");
    printf("LoadLibrary(missing.dll) is NULL: %s\n",
           LoadLibraryA("missing.dll") == NULL ? "yes" : "no");

    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, sizeof path);
    printf("module file name ends with dlltest.exe: %s\n",
           n >= 11 && strcmp(path + n - 11, "dlltest.exe") == 0 ? "yes" : "no");

    puts("main: end");
    return 0;
}
