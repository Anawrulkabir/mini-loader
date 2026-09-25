/* win32.c — the fake Windows API the loaded program calls into.
 *
 * A Windows .exe calls functions it imports from system DLLs. We don't
 * have those DLLs; we provide our own implementations and bind the
 * import table to them. The ms_abi attribute makes these use the
 * Windows x64 calling convention (args in RCX, RDX, R8, R9) even though
 * we're compiled for the System V ABI. That is the single most important
 * detail: without it, arguments land in the wrong registers. It is also
 * why even memcpy needs a wrapper here, rather than binding the import
 * straight to the host's memcpy.
 *
 * Two more ABI differences show up once a real C runtime is involved:
 *   - `long` is 32 bits on Windows (LLP64), 64 on Linux/macOS (LP64).
 *   - A Windows va_list is a plain pointer walking 8-byte stack slots,
 *     unlike the host's; see ms_vfprintf.
 *
 * Everything is single-threaded, so locks are no-ops.
 *
 * Included by loader.c, after teb.c.
 */
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <signal.h>

extern char **environ;

/* ---- process: args, exit, errors ----------------------------------------- */

static int    g_argc;   /* what __getmainargs hands to main() */
static char **g_argv;

#define MAX_ONEXIT 64
static WinFn *g_onexit[MAX_ONEXIT];
static int g_nonexit;

/* Run atexit/_onexit handlers, newest first, once. */
static void run_onexit(void) {
    while (g_nonexit > 0) g_onexit[--g_nonexit]();
}

static WINAPI void *my__onexit(WinFn *fn) {
    if (g_nonexit == MAX_ONEXIT) return NULL;
    g_onexit[g_nonexit++] = fn;
    return (void *)fn;
}

/* msvcrt's exit runs the CRT's handlers; ExitProcess (kernel32) is
 * lower level and does not. */
static WINAPI void my_exit(int code)           { run_onexit(); exit(code); }
static WINAPI void my__cexit(void)             { run_onexit(); fflush(NULL); }
static WINAPI void my_ExitProcess(uint32_t c)  { fflush(NULL); exit((int)c); }
static WINAPI void my_abort(void)              { abort(); }
static WINAPI void my__amsg_exit(int n) {
    fprintf(stderr, "runtime error R60%02d\n", n);
    exit(255);
}

/* Per-thread state lives in the TEB, as on Windows. */
static WINAPI uint32_t my_GetLastError(void)       { return g_teb->LastErrorValue; }
static WINAPI void     my_SetLastError(uint32_t e) { g_teb->LastErrorValue = e; }
static WINAPI uint32_t my_GetCurrentProcessId(void) { return (uint32_t)g_teb->UniqueProcess; }
static WINAPI uint32_t my_GetCurrentThreadId(void)  { return (uint32_t)g_teb->UniqueThread; }
static void set_last_error(uint32_t e)             { g_teb->LastErrorValue = e; }

/* __getmainargs(&argc, &argv, &envp, glob, &startupinfo) — the CRT asks
 * for main()'s arguments. They're ours, minus the loader's own argv[0]. */
static WINAPI int my___getmainargs(int *argc, char ***argv, char ***envp,
                                   int glob, void *si) {
    (void)glob; (void)si;
    *argc = g_argc; *argv = g_argv; *envp = environ;
    return 0;
}

/* _initterm(begin, end): call each non-NULL function pointer in the
 * table. These are the program's constructors, so they're Windows ABI. */
static WINAPI void my__initterm(WinFn **b, WinFn **e) {
    for (; b < e; b++) if (*b) (*b)();
}

static WINAPI void  my___set_app_type(int t)        { (void)t; }
static WINAPI void  my___setusermatherr(void *f)    { (void)f; }
static WINAPI void  my__lock(int n)                 { (void)n; }
static WINAPI void  my__unlock(int n)               { (void)n; }
static WINAPI int  *my__errno(void)                 { return &errno; }
static WINAPI char *my_strerror(int e)              { return strerror(e); }
static WINAPI int   my___lc_codepage_func(void)     { return 0; }  /* "C" */
static WINAPI int   my___mb_cur_max_func(void)      { return 1; }
static WINAPI void *my_signal(int s, void *h)       { (void)s; (void)h; return NULL; }
static WINAPI void *my_SetUnhandledExceptionFilter(void *f) { (void)f; return NULL; }
static WINAPI void  my_Sleep(uint32_t ms)           { usleep(ms * 1000u); }

/* The SEH personality routine: only an unwinder calls it, and we don't
 * have one (see the README roadmap). */
static WINAPI int my___C_specific_handler(void *rec, void *frame,
                                          void *ctx, void *dispatch) {
    (void)rec; (void)frame; (void)ctx; (void)dispatch;
    fprintf(stderr, "  [structured exception raised; not supported]\n");
    abort();
}

/* Data imports: the IAT slot gets the variable's address, not a
 * function. mingw's CRT reads and writes these directly. */
static int    win__commode;
static int    win__fmode;
static char **win___initenv;

/* ---- critical sections and TLS slots -------------------------------------- */

static WINAPI void my_InitializeCriticalSection(void *cs) { (void)cs; }
static WINAPI void my_DeleteCriticalSection(void *cs)     { (void)cs; }
static WINAPI void my_EnterCriticalSection(void *cs)      { (void)cs; }
static WINAPI void my_LeaveCriticalSection(void *cs)      { (void)cs; }

/* Dynamic TLS lives in the TEB's TlsSlots, one pointer per index. */
#define TLS_OUT_OF_INDEXES 0xFFFFFFFFu
static uint64_t g_tls_used;   /* bitmap of allocated indices */

static WINAPI uint32_t my_TlsAlloc(void) {
    for (uint32_t i = 0; i < TLS_MINIMUM_AVAILABLE; i++)
        if (!(g_tls_used & (1ULL << i))) {
            g_tls_used |= 1ULL << i;
            g_teb->TlsSlots[i] = NULL;
            return i;
        }
    return TLS_OUT_OF_INDEXES;
}
static WINAPI int my_TlsFree(uint32_t i) {
    if (i >= TLS_MINIMUM_AVAILABLE) return 0;
    g_tls_used &= ~(1ULL << i);
    return 1;
}
static WINAPI void *my_TlsGetValue(uint32_t i) {
    if (i >= TLS_MINIMUM_AVAILABLE) { set_last_error(87); return NULL; }
    set_last_error(0);  /* callers tell NULL-stored from failure this way */
    return g_teb->TlsSlots[i];
}
static WINAPI int my_TlsSetValue(uint32_t i, void *v) {
    if (i >= TLS_MINIMUM_AVAILABLE) { set_last_error(87); return 0; }
    g_teb->TlsSlots[i] = v;
    return 1;
}

/* ---- memory: VirtualQuery / VirtualProtect ------------------------------- *
 *
 * mingw's startup code uses these to patch its own image ("pseudo
 * relocations" for auto-imported data). We track a Windows PAGE_* value
 * for every page of the image so we can answer queries truthfully. */

#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80

static int host_prot(uint32_t win) {
    switch (win & 0xFF) {
    case PAGE_READONLY:          return PROT_READ;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:         return PROT_READ | PROT_WRITE;
    case PAGE_EXECUTE:           return PROT_EXEC;
    case PAGE_EXECUTE_READ:      return PROT_READ | PROT_EXEC;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY: return PROT_READ | PROT_WRITE | PROT_EXEC;
    default:                     return PROT_NONE;
    }
}

static long page_size(void) {
    static long pg;
    if (!pg) pg = sysconf(_SC_PAGESIZE);
    return pg;
}

/* Set protection on [rva, rva+len) of the image, rounded out to pages.
 * The caller has checked the range is inside the image. */
static int image_protect(Image *img, uint64_t rva, uint64_t len, uint32_t win) {
    uint64_t pg    = (uint64_t)page_size();
    uint64_t first = rva / pg;
    uint64_t last  = (rva + len + pg - 1) / pg;   /* exclusive */
    if (last == first) return 0;
    if (mprotect(img->base + first * pg, (last - first) * pg, host_prot(win)) != 0)
        return -1;
    for (uint64_t p = first; p < last; p++) img->page_prot[p] = win;
    return 0;
}

/* Map a pointer into the image to its page index, or -1. */
static int64_t image_page(const void *addr) {
    uintptr_t a = (uintptr_t)addr, b = (uintptr_t)g_img.base;
    if (!g_img.base || a < b || a - b >= g_img.size) return -1;
    return (int64_t)((a - b) / (uintptr_t)page_size());
}

/* MEMORY_BASIC_INFORMATION, x64 layout. */
typedef struct {
    void    *BaseAddress;
    void    *AllocationBase;
    uint32_t AllocationProtect;
    uint16_t PartitionId;
    size_t   RegionSize;       /* at 0x18, after padding */
    uint32_t State;
    uint32_t Protect;
    uint32_t Type;
} MemoryBasicInformation;
_Static_assert(sizeof(MemoryBasicInformation) == 48, "MBI layout");

#define MEM_COMMIT 0x1000
#define MEM_IMAGE  0x1000000

/* Describe the run of same-protection pages starting at addr's page. */
static WINAPI size_t my_VirtualQuery(const void *addr, MemoryBasicInformation *mbi,
                                     size_t len) {
    int64_t p = image_page(addr);
    if (p < 0 || len < sizeof(*mbi)) { set_last_error(87); return 0; }
    uint64_t pg = (uint64_t)page_size(), npages = (g_img.size + pg - 1) / pg;
    uint64_t q = (uint64_t)p;
    while (q < npages && g_img.page_prot[q] == g_img.page_prot[p]) q++;

    memset(mbi, 0, sizeof(*mbi));
    mbi->BaseAddress       = g_img.base + (uint64_t)p * pg;
    mbi->AllocationBase    = g_img.base;
    mbi->AllocationProtect = PAGE_EXECUTE_WRITECOPY;
    mbi->RegionSize        = (q - (uint64_t)p) * pg;
    mbi->State             = MEM_COMMIT;
    mbi->Protect           = g_img.page_prot[p];
    mbi->Type              = MEM_IMAGE;
    return sizeof(*mbi);
}

static WINAPI int my_VirtualProtect(void *addr, size_t len, uint32_t prot,
                                    uint32_t *old) {
    int64_t p = image_page(addr);
    if (p < 0 || !old) { set_last_error(487); return 0; }
    uint64_t rva = (uint64_t)((uint8_t *)addr - g_img.base);
    if (len > g_img.size - rva) { set_last_error(487); return 0; }
    *old = g_img.page_prot[p];
    if (image_protect(&g_img, rva, len, prot) != 0) { set_last_error(87); return 0; }
    return 1;
}

/* ---- console handles ------------------------------------------------------ */

/* Windows hands out opaque HANDLEs; ours are just POSIX fds in
 * disguise. STD_INPUT/OUTPUT/ERROR_HANDLE are (DWORD)-10/-11/-12. */
#define INVALID_HANDLE ((void *)(intptr_t)-1)
static WINAPI void *my_GetStdHandle(uint32_t n) {
    switch ((int32_t)n) {
    case -10: return (void *)(intptr_t)0;
    case -11: return (void *)(intptr_t)1;
    case -12: return (void *)(intptr_t)2;
    default:  return INVALID_HANDLE;
    }
}

/* WriteFile(handle, buf, len, &written, overlapped) — enough of the
 * signature to route console output to POSIX write(). */
static WINAPI int my_WriteFile(void *h, const void *buf, uint32_t len,
                               uint32_t *written, void *ovl) {
    (void)ovl;
    if (h == INVALID_HANDLE) { if (written) *written = 0; return 0; }
    ssize_t n = write((int)(intptr_t)h, buf, len);
    if (written) *written = (uint32_t)(n < 0 ? 0 : n);
    return n >= 0;
}

/* ---- stdio ------------------------------------------------------------------
 *
 * msvcrt's stdin/stdout/stderr are elements of an array of its own FILE
 * structs, which the program reaches through __iob_func() and then
 * passes back to fwrite and friends. The layout is msvcrt's, not ours,
 * so we hand out an array of the right size (48 bytes per FILE) and
 * translate those pointers back to the host's streams. */

typedef struct { uint8_t opaque[48]; } WinFile;
static WinFile win_iob[3];

static FILE *host_file(void *f) {
    if (f == &win_iob[0]) return stdin;
    if (f == &win_iob[1]) return stdout;
    if (f == &win_iob[2]) return stderr;
    return NULL;
}

static WINAPI WinFile *my___iob_func(void) { return win_iob; }

static WINAPI int my_fputc(int c, void *f) {
    FILE *h = host_file(f);
    return h ? fputc(c, h) : EOF;
}
static WINAPI size_t my_fwrite(const void *p, size_t sz, size_t n, void *f) {
    FILE *h = host_file(f);
    return h ? fwrite(p, sz, n, h) : 0;
}
static WINAPI int my_fflush(void *f) {
    if (!f) return fflush(NULL);
    FILE *h = host_file(f);
    return h ? fflush(h) : EOF;
}
static WINAPI int my_puts(const char *s)   { return puts(s); }
static WINAPI int my_putchar(int c)        { return putchar(c); }

/* A Windows wchar_t is 16 bits (UTF-16); the host's is 32. */
static WINAPI size_t my_wcslen(const uint16_t *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

/* Narrow a UTF-16 string for printing; non-ASCII becomes '?'. Enough for
 * a console demo; the real thing is WideCharToMultiByte's job. */
static char *narrow(const uint16_t *w, size_t n) {
    char *s = malloc(n + 1);
    if (!s) return NULL;
    for (size_t i = 0; i < n; i++) s[i] = w[i] < 0x80 ? (char)w[i] : '?';
    s[n] = 0;
    return s;
}

/* printf with a Windows va_list. The host's vfprintf can't read one, so
 * walk the format ourselves: for each conversion, pull the argument with
 * the Windows-side type (32-bit `long`, 16-bit wide strings) and hand the
 * host's fprintf that one conversion with that one argument. */
static int ms_vfprintf(FILE *out, const char *fmt, __builtin_ms_va_list ap) {
    int total = 0;
    while (*fmt) {
        if (*fmt != '%') { fputc(*fmt++, out); total++; continue; }

        /* Rebuild the conversion as a host format in spec[]. The flags
         * and digit runs are clamped so it can't overflow. */
        char spec[64];
        int n = 0;
        spec[n++] = *fmt++;
        while (*fmt && strchr("-+ #0", *fmt) && n < 8) spec[n++] = *fmt++;
        if (*fmt == '*') {
            n += snprintf(spec + n, 16, "%d", __builtin_va_arg(ap, int));
            fmt++;
        } else {
            for (int k = 0; isdigit((unsigned char)*fmt); fmt++)
                if (k++ < 8) spec[n++] = *fmt;
        }
        if (*fmt == '.') {
            fmt++;
            if (*fmt == '*') {
                int prec = __builtin_va_arg(ap, int);
                if (prec >= 0) n += snprintf(spec + n, 16, ".%d", prec);
                fmt++;
            } else {
                spec[n++] = '.';
                for (int k = 0; isdigit((unsigned char)*fmt); fmt++)
                    if (k++ < 8) spec[n++] = *fmt;
            }
        }

        /* Length modifier: 64-bit for ll, I64, I, z, j, t; wide strings
         * and chars for l and w. h/hh pass through unchanged. */
        int wide64 = 0, wide_str = 0;
        if      (fmt[0] == 'I' && fmt[1] == '6' && fmt[2] == '4') { wide64 = 1; fmt += 3; }
        else if (fmt[0] == 'I' && fmt[1] == '3' && fmt[2] == '2') { fmt += 3; }
        else if (fmt[0] == 'l' && fmt[1] == 'l') { wide64 = 1; fmt += 2; }
        else if (*fmt && strchr("Izjt", *fmt))  { wide64 = 1; fmt++; }
        else if (*fmt == 'l' || *fmt == 'w')    { wide_str = 1; fmt++; }
        else if (*fmt == 'L')                   { fmt++; }  /* long double == double */
        else if (fmt[0] == 'h' && fmt[1] == 'h') { spec[n++] = 'h'; spec[n++] = 'h'; fmt += 2; }
        else if (*fmt == 'h')                   { spec[n++] = 'h'; fmt++; }

        char conv = *fmt ? *fmt++ : 0;
        int r = 0;
        switch (conv) {
        case 'd': case 'i': case 'u': case 'o': case 'x': case 'X':
            if (wide64) {
                spec[n++] = 'l'; spec[n++] = 'l'; spec[n++] = conv; spec[n] = 0;
                r = fprintf(out, spec, __builtin_va_arg(ap, long long));
            } else {
                spec[n++] = conv; spec[n] = 0;
                r = fprintf(out, spec, __builtin_va_arg(ap, int));
            }
            break;
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G':
        case 'a': case 'A':
            spec[n++] = conv; spec[n] = 0;
            r = fprintf(out, spec, __builtin_va_arg(ap, double));
            break;
        case 'c': case 'C': {
            int c = __builtin_va_arg(ap, int);
            if (wide_str || conv == 'C') c = (c & 0xFFFF) < 0x80 ? c & 0x7F : '?';
            spec[n++] = 'c'; spec[n] = 0;
            r = fprintf(out, spec, c);
            break;
        }
        case 's': case 'S': {
            void *p = __builtin_va_arg(ap, void *);
            spec[n++] = 's'; spec[n] = 0;
            if ((wide_str || conv == 'S') && p) {
                char *s = narrow(p, my_wcslen(p));
                r = fprintf(out, spec, s ? s : "");
                free(s);
            } else {
                r = fprintf(out, spec, (char *)p);
            }
            break;
        }
        case 'p':
            spec[n++] = 'p'; spec[n] = 0;
            r = fprintf(out, spec, __builtin_va_arg(ap, void *));
            break;
        case 'n':
            *__builtin_va_arg(ap, int *) = total;
            break;
        case '%':
            r = fputc('%', out) == EOF ? -1 : 1;
            break;
        default:  /* unknown or truncated: print it as written */
            if (conv) spec[n++] = conv;
            r = (int)fwrite(spec, 1, (size_t)n, out);
            break;
        }
        if (r < 0) return -1;
        total += r;
    }
    return total;
}

static WINAPI int my_vfprintf(void *f, const char *fmt, __builtin_ms_va_list ap) {
    FILE *h = host_file(f);
    return h ? ms_vfprintf(h, fmt, ap) : -1;
}
static WINAPI int my_fprintf(void *f, const char *fmt, ...) {
    FILE *h = host_file(f);
    if (!h) return -1;
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    int r = ms_vfprintf(h, fmt, ap);
    __builtin_ms_va_end(ap);
    return r;
}
static WINAPI int my_printf(const char *fmt, ...) {
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    int r = ms_vfprintf(stdout, fmt, ap);
    __builtin_ms_va_end(ap);
    return r;
}

/* msvcrt's struct lconv: same first fields as C's, which is all the
 * mingw formatter reads (decimal_point, thousands_sep, grouping). */
static WINAPI void *my_localeconv(void) {
    static char *lc[16] = { ".", "", "" };
    return lc;
}

/* ---- code pages ------------------------------------------------------------
 * Treated as Latin-1: one byte, one UTF-16 unit. */

static WINAPI int my_IsDBCSLeadByteEx(uint32_t cp, uint8_t c) { (void)cp; (void)c; return 0; }

static WINAPI int my_MultiByteToWideChar(uint32_t cp, uint32_t flags,
                                         const char *src, int srclen,
                                         uint16_t *dst, int dstlen) {
    (void)cp; (void)flags;
    if (srclen < 0) srclen = (int)strlen(src) + 1;
    if (dstlen == 0) return srclen;
    if (dstlen < srclen) { set_last_error(122); return 0; }
    for (int i = 0; i < srclen; i++) dst[i] = (uint8_t)src[i];
    return srclen;
}

static WINAPI int my_WideCharToMultiByte(uint32_t cp, uint32_t flags,
                                         const uint16_t *src, int srclen,
                                         char *dst, int dstlen,
                                         const char *defchar, int *used_def) {
    (void)cp; (void)flags;
    if (srclen < 0) srclen = (int)my_wcslen(src) + 1;
    if (used_def) *used_def = 0;
    if (dstlen == 0) return srclen;
    if (dstlen < srclen) { set_last_error(122); return 0; }
    for (int i = 0; i < srclen; i++) {
        if (src[i] <= 0xFF) { dst[i] = (char)src[i]; continue; }
        dst[i] = defchar ? *defchar : '?';
        if (used_def) *used_def = 1;
    }
    return srclen;
}

/* ---- plain C library: the same functions, Windows ABI on the outside ---- */

static WINAPI void  *my_malloc(size_t n)                   { return malloc(n); }
static WINAPI void  *my_calloc(size_t n, size_t s)         { return calloc(n, s); }
static WINAPI void  *my_realloc(void *p, size_t n)         { return realloc(p, n); }
static WINAPI void   my_free(void *p)                      { free(p); }
static WINAPI void  *my_memcpy(void *d, const void *s, size_t n)  { return memcpy(d, s, n); }
static WINAPI void  *my_memmove(void *d, const void *s, size_t n) { return memmove(d, s, n); }
static WINAPI void  *my_memset(void *d, int c, size_t n)   { return memset(d, c, n); }
static WINAPI int    my_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
static WINAPI size_t my_strlen(const char *s)              { return strlen(s); }
static WINAPI int    my_strcmp(const char *a, const char *b) { return strcmp(a, b); }
static WINAPI int    my_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
static WINAPI char  *my_strcpy(char *d, const char *s)     { return strcpy(d, s); }

/* ---- the import table ----------------------------------------------------- */

/* Import name -> our stub (or, for data imports, our variable). A real
 * loader would load the actual DLL and look each name up in its export
 * table; we resolve against this list, whichever DLL the name is from. */
typedef struct { const char *name; void *fn; } Stub;
static Stub g_stubs[] = {
    /* kernel32 */
    { "DeleteCriticalSection",       (void *)my_DeleteCriticalSection },
    { "EnterCriticalSection",        (void *)my_EnterCriticalSection },
    { "ExitProcess",                 (void *)my_ExitProcess },
    { "GetCurrentProcessId",         (void *)my_GetCurrentProcessId },
    { "GetCurrentThreadId",          (void *)my_GetCurrentThreadId },
    { "GetLastError",                (void *)my_GetLastError },
    { "GetStdHandle",                (void *)my_GetStdHandle },
    { "InitializeCriticalSection",   (void *)my_InitializeCriticalSection },
    { "IsDBCSLeadByteEx",            (void *)my_IsDBCSLeadByteEx },
    { "LeaveCriticalSection",        (void *)my_LeaveCriticalSection },
    { "MultiByteToWideChar",         (void *)my_MultiByteToWideChar },
    { "SetLastError",                (void *)my_SetLastError },
    { "SetUnhandledExceptionFilter", (void *)my_SetUnhandledExceptionFilter },
    { "Sleep",                       (void *)my_Sleep },
    { "TlsAlloc",                    (void *)my_TlsAlloc },
    { "TlsFree",                     (void *)my_TlsFree },
    { "TlsGetValue",                 (void *)my_TlsGetValue },
    { "TlsSetValue",                 (void *)my_TlsSetValue },
    { "VirtualProtect",              (void *)my_VirtualProtect },
    { "VirtualQuery",                (void *)my_VirtualQuery },
    { "WideCharToMultiByte",         (void *)my_WideCharToMultiByte },
    { "WriteFile",                   (void *)my_WriteFile },

    /* msvcrt: startup and exit */
    { "__C_specific_handler",        (void *)my___C_specific_handler },
    { "___lc_codepage_func",         (void *)my___lc_codepage_func },
    { "___mb_cur_max_func",          (void *)my___mb_cur_max_func },
    { "__getmainargs",               (void *)my___getmainargs },
    { "__initenv",                   (void *)&win___initenv },   /* data */
    { "__iob_func",                  (void *)my___iob_func },
    { "__set_app_type",              (void *)my___set_app_type },
    { "__setusermatherr",            (void *)my___setusermatherr },
    { "_amsg_exit",                  (void *)my__amsg_exit },
    { "_cexit",                      (void *)my__cexit },
    { "_commode",                    (void *)&win__commode },    /* data */
    { "_errno",                      (void *)my__errno },
    { "_fmode",                      (void *)&win__fmode },      /* data */
    { "_initterm",                   (void *)my__initterm },
    { "_lock",                       (void *)my__lock },
    { "_onexit",                     (void *)my__onexit },
    { "_unlock",                     (void *)my__unlock },
    { "abort",                       (void *)my_abort },
    { "exit",                        (void *)my_exit },
    { "signal",                      (void *)my_signal },

    /* msvcrt: stdio */
    { "fflush",                      (void *)my_fflush },
    { "fprintf",                     (void *)my_fprintf },
    { "fputc",                       (void *)my_fputc },
    { "fwrite",                      (void *)my_fwrite },
    { "localeconv",                  (void *)my_localeconv },
    { "printf",                      (void *)my_printf },
    { "putchar",                     (void *)my_putchar },
    { "puts",                        (void *)my_puts },
    { "vfprintf",                    (void *)my_vfprintf },

    /* msvcrt: memory and strings */
    { "calloc",                      (void *)my_calloc },
    { "free",                        (void *)my_free },
    { "malloc",                      (void *)my_malloc },
    { "memcmp",                      (void *)my_memcmp },
    { "memcpy",                      (void *)my_memcpy },
    { "memmove",                     (void *)my_memmove },
    { "memset",                      (void *)my_memset },
    { "realloc",                     (void *)my_realloc },
    { "strcmp",                      (void *)my_strcmp },
    { "strcpy",                      (void *)my_strcpy },
    { "strerror",                    (void *)my_strerror },
    { "strlen",                      (void *)my_strlen },
    { "strncmp",                     (void *)my_strncmp },
    { "wcslen",                      (void *)my_wcslen },
    { NULL, NULL }
};

static void *resolve_stub(const char *name) {
    for (Stub *s = g_stubs; s->name; s++)
        if (strcmp(s->name, name) == 0) return s->fn;
    fprintf(stderr, "  [unresolved import: %s]\n", name);
    return NULL;  /* load_image refuses to run the image if any are NULL */
}
