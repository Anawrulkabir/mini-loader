/* teb.c — give the image a Windows thread to run on.
 *
 * Windows code expects gs to point at a TEB (see teb.h). A program
 * built with -nostdlib never looks, but the C runtime reads gs:[0x30]
 * within its first few instructions, so without this every normal
 * .exe crashes before main().
 *
 * On x86-64 Linux, glibc keeps its own thread data behind fs and leaves
 * gs alone, so we can point gs at our TEB with arch_prctl and neither
 * side notices the other. This is what Wine does. macOS uses gs for its
 * own thread data, which is why Wine has to play tricks there (see the
 * README); we just warn and carry on.
 *
 * Included by loader.c, after Image and in_image are defined.
 */
#include "teb.h"
#include <pthread.h>

#ifdef __linux__
#include <asm/prctl.h>
#include <sys/syscall.h>
#endif

static Teb *g_teb;

/* Point gs at `p`. Returns 0 on success. */
static int set_gs_base(void *p) {
#ifdef __linux__
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, (unsigned long)(uintptr_t)p) != 0) {
        perror("arch_prctl(ARCH_SET_GS)");
        return -1;
    }
    return 0;
#else
    (void)p;
    fprintf(stderr, "  [can't point gs at the TEB on this OS; a program "
                    "that reads it (any CRT-linked .exe) will crash]\n");
    return -1;
#endif
}

/* The Windows code runs on our stack, so that's the stack it should
 * see in StackBase/StackLimit. The CRT uses StackBase as a per-thread
 * id; stack probes and unwinding compare against both. */
static void stack_bounds(void **lo, void **hi) {
#if defined(__linux__)
    pthread_attr_t a;
    void *addr; size_t size;
    if (pthread_getattr_np(pthread_self(), &a) == 0 &&
        pthread_attr_getstack(&a, &addr, &size) == 0) {
        *lo = addr;
        *hi = (uint8_t *)addr + size;
        pthread_attr_destroy(&a);
        return;
    }
#elif defined(__APPLE__)
    *hi = pthread_get_stackaddr_np(pthread_self());
    *lo = (uint8_t *)*hi - pthread_get_stacksize_np(pthread_self());
    return;
#endif
    /* Fallback: a window around where we are now. */
    uint8_t here;
    *hi = (void *)(((uintptr_t)&here + 0xFFFF) & ~(uintptr_t)0xFFFF);
    *lo = (uint8_t *)*hi - (1 << 20);
}

/* A VA from the TLS directory, as an RVA; out of range if below base. */
static uint64_t va_to_rva(Module *m, uint64_t va) {
    uint64_t base = (uint64_t)(uintptr_t)m->base;
    return va >= base ? va - base : UINT64_MAX;
}

static TlsDirectory64 *tls_directory(Module *m) {
    if (m->builtin) return NULL;
    DataDirectory *d = &m->pe->opt->DataDirectory[DIR_TLS];
    if (!d->VirtualAddress) return NULL;
    if (!in_image(m->pe, d->VirtualAddress, sizeof(TlsDirectory64))) return NULL;
    return (TlsDirectory64 *)(m->base + d->VirtualAddress);
}

/* Static TLS (__declspec(thread) under MSVC). Each module with a TLS
 * directory gets a slot index; its code finds its variables at
 * gs:[0x58][index] + offset. Each thread has one block per module,
 * copied from the module's template. */
#define MAX_TLS_MODULES 64
static Module *g_tls_modules[MAX_TLS_MODULES];

/* A fresh TLS block for `m`: the template, then zeroes. */
static void *new_tls_block(Module *m) {
    uint8_t *block = calloc(1, m->tls_raw + m->tls_zero + 1);
    if (block && m->tls_raw) memcpy(block, m->tls_template, m->tls_raw);
    return block;
}

static int setup_module_tls(Module *m) {
    DataDirectory *d = &m->pe->opt->DataDirectory[DIR_TLS];
    if (!d->VirtualAddress) return 0;

    TlsDirectory64 *tls = tls_directory(m);
    if (!tls) { fprintf(stderr, "TLS directory out of range\n"); return -1; }

    uint64_t start = va_to_rva(m, tls->StartAddressOfRawData);
    uint64_t end   = va_to_rva(m, tls->EndAddressOfRawData);
    uint64_t raw   = end - start;
    if (!tls->StartAddressOfRawData && !tls->EndAddressOfRawData) raw = 0;
    else if (end < start || !in_image(m->pe, start, raw)) {
        fprintf(stderr, "TLS template out of range\n");
        return -1;
    }
    uint64_t idx_rva = 0;
    if (tls->AddressOfIndex) {
        idx_rva = va_to_rva(m, tls->AddressOfIndex);
        if (!in_image(m->pe, idx_rva, 4)) {
            fprintf(stderr, "TLS index out of range\n");
            return -1;
        }
    }

    int idx = 0;
    while (idx < MAX_TLS_MODULES && g_tls_modules[idx]) idx++;
    if (idx == MAX_TLS_MODULES) { fprintf(stderr, "out of TLS slots\n"); return -1; }

    m->tls_index    = idx;
    m->tls_template = raw ? m->base + start : NULL;
    m->tls_raw      = raw;
    m->tls_zero     = tls->SizeOfZeroFill;
    if (tls->AddressOfIndex) *(uint32_t *)(m->base + idx_rva) = (uint32_t)idx;

    void *block = new_tls_block(m);
    if (!block) { perror("calloc"); return -1; }
    g_teb->ThreadLocalStoragePointer[idx] = block;
    g_tls_modules[idx] = m;
    return 0;
}

static void release_module_tls(Module *m) {
    if (m->tls_index < 0) return;
    free(g_teb->ThreadLocalStoragePointer[m->tls_index]);
    g_teb->ThreadLocalStoragePointer[m->tls_index] = NULL;
    g_tls_modules[m->tls_index] = NULL;
    m->tls_index = -1;
}

typedef WINAPI void TlsCallback(void *module, uint32_t reason, void *reserved);

#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1

/* Windows calls each TLS callback before the entry point (and again at
 * exit). The mingw CRT uses one to set up its thread-key machinery. */
static int run_tls_callbacks(Module *m, uint32_t reason) {
    TlsDirectory64 *tls = tls_directory(m);
    if (!tls || !tls->AddressOfCallBacks) return 0;

    for (uint64_t rva = va_to_rva(m, tls->AddressOfCallBacks); ; rva += 8) {
        if (!in_image(m->pe, rva, 8)) {
            fprintf(stderr, "TLS callback array out of range\n");
            return -1;
        }
        uint64_t cb = *(uint64_t *)(m->base + rva);
        if (!cb) break;
        if (!in_image(m->pe, va_to_rva(m, cb), 1)) {
            fprintf(stderr, "TLS callback outside the image\n");
            return -1;
        }
        TlsCallback *fn = (TlsCallback *)(uintptr_t)cb;
        fn(m->base, reason, NULL);
    }
    return 0;
}

/* Build the TEB and PEB for the (only) thread and point gs at it. */
static int setup_teb(void) {
    g_teb = calloc(1, sizeof(Teb));
    Peb *peb = calloc(1, sizeof(Peb));
    void **tls = calloc(MAX_TLS_MODULES, sizeof(void *));
    if (!g_teb || !peb || !tls) { perror("calloc"); return -1; }

    stack_bounds(&g_teb->StackLimit, &g_teb->StackBase);
    g_teb->Self          = g_teb;
    g_teb->UniqueProcess = (uint64_t)getpid();
#ifdef __linux__
    g_teb->UniqueThread  = (uint64_t)syscall(SYS_gettid);
#endif
    g_teb->ThreadLocalStoragePointer = tls;
    g_teb->ProcessEnvironmentBlock   = peb;

    /* Not fatal: -nostdlib programs never touch gs. */
    set_gs_base(g_teb);
    return 0;
}
