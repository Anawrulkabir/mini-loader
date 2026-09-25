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
static uint64_t va_to_rva(Image *img, uint64_t va) {
    uint64_t base = (uint64_t)(uintptr_t)img->base;
    return va >= base ? va - base : UINT64_MAX;
}

static TlsDirectory64 *tls_directory(PEFile *pe, Image *img) {
    DataDirectory *d = &pe->opt->DataDirectory[DIR_TLS];
    if (!d->VirtualAddress) return NULL;
    if (!in_image(pe, d->VirtualAddress, sizeof(TlsDirectory64))) return NULL;
    return (TlsDirectory64 *)(img->base + d->VirtualAddress);
}

/* Static TLS (__declspec(thread) under MSVC). Each module gets a slot
 * index; code finds its variables at gs:[0x58][index] + offset. We have
 * one module and one thread, so: one block, copied from the template,
 * in slot 0. */
static int setup_tls(PEFile *pe, Image *img) {
    DataDirectory *d = &pe->opt->DataDirectory[DIR_TLS];
    if (!d->VirtualAddress) return 0;

    TlsDirectory64 *tls = tls_directory(pe, img);
    if (!tls) { fprintf(stderr, "TLS directory out of range\n"); return -1; }

    uint64_t start = va_to_rva(img, tls->StartAddressOfRawData);
    uint64_t end   = va_to_rva(img, tls->EndAddressOfRawData);
    uint64_t raw   = end - start;
    if (!tls->StartAddressOfRawData && !tls->EndAddressOfRawData) raw = 0;
    else if (end < start || !in_image(pe, start, raw)) {
        fprintf(stderr, "TLS template out of range\n");
        return -1;
    }

    uint8_t *block = calloc(1, raw + tls->SizeOfZeroFill + 1);
    if (!block) { perror("calloc"); return -1; }
    if (raw) memcpy(block, img->base + start, raw);

    static void *tls_array[1];
    tls_array[0] = block;
    g_teb->ThreadLocalStoragePointer = tls_array;

    if (tls->AddressOfIndex) {
        uint64_t idx = va_to_rva(img, tls->AddressOfIndex);
        if (!in_image(pe, idx, 4)) {
            fprintf(stderr, "TLS index out of range\n");
            return -1;
        }
        *(uint32_t *)(img->base + idx) = 0;
    }
    return 0;
}

typedef WINAPI void TlsCallback(void *module, uint32_t reason, void *reserved);

#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1

/* Windows calls each TLS callback before the entry point (and again at
 * exit). The mingw CRT uses one to set up its thread-key machinery. */
static int run_tls_callbacks(PEFile *pe, Image *img, uint32_t reason) {
    TlsDirectory64 *tls = tls_directory(pe, img);
    if (!tls || !tls->AddressOfCallBacks) return 0;

    for (uint64_t rva = va_to_rva(img, tls->AddressOfCallBacks); ; rva += 8) {
        if (!in_image(pe, rva, 8)) {
            fprintf(stderr, "TLS callback array out of range\n");
            return -1;
        }
        uint64_t cb = *(uint64_t *)(img->base + rva);
        if (!cb) break;
        if (!in_image(pe, va_to_rva(img, cb), 1)) {
            fprintf(stderr, "TLS callback outside the image\n");
            return -1;
        }
        TlsCallback *fn = (TlsCallback *)(uintptr_t)cb;
        fn(img->base, reason, NULL);
    }
    return 0;
}

/* Build the TEB and PEB for the (only) thread and point gs at it. */
static int setup_teb(PEFile *pe, Image *img) {
    g_teb = calloc(1, sizeof(Teb));
    Peb *peb = calloc(1, sizeof(Peb));
    if (!g_teb || !peb) { perror("calloc"); return -1; }

    stack_bounds(&g_teb->StackLimit, &g_teb->StackBase);
    g_teb->Self          = g_teb;
    g_teb->UniqueProcess = (uint64_t)getpid();
#ifdef __linux__
    g_teb->UniqueThread  = (uint64_t)syscall(SYS_gettid);
#endif
    g_teb->ProcessEnvironmentBlock = peb;
    peb->ImageBaseAddress = img->base;

    if (setup_tls(pe, img) != 0) return -1;

    /* Not fatal: -nostdlib programs never touch gs. */
    set_gs_base(g_teb);
    return 0;
}
