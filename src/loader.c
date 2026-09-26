/* loader.c — step 2: actually load and run the image.
 *
 * For the .exe and every .dll it pulls in:
 *   1. reserve SizeOfImage bytes of memory
 *   2. copy headers + each section to its RVA
 *   3. apply base relocations (we rarely get the preferred ImageBase)
 *   4. bind imports: load each DLL it names (recursively), and write
 *      the address of each function into the Import Address Table
 *   5. set per-section page permissions
 *   6. give it a TLS slot, if it has thread-local data (teb.c)
 * Then:
 *   7. initialise DLLs, dependencies first: TLS callbacks, DllMain
 *   8. jump to the .exe's entry point
 *
 * A DLL is loaded from disk if a file of that name sits next to the
 * .exe (or in the current directory). Otherwise it is "builtin": its
 * imports resolve to our own functions in win32.c. That's the Wine
 * model: real DLLs for the application's own libraries, fakes for the
 * system ones.
 *
 * We build everything as one translation unit by including the other
 * .c files. The parser's main() is behind PARSE_MAIN, so it stays out.
 */
#define _GNU_SOURCE   /* pthread_getattr_np, in teb.c */
#include "pe_parse.c"

#include <ctype.h>
#include <dirent.h>
#include <sys/mman.h>
#include <unistd.h>

/* Windows x64 calling convention; see win32.c. Function pointers into
 * the image need it too, via a function type: WinFn *f. */
#define WINAPI __attribute__((ms_abi))
typedef WINAPI void WinFn(void);
typedef WINAPI int  DllEntry(void *module, uint32_t reason, void *reserved);

/* ---- modules -------------------------------------------------------------- */

typedef struct Module {
    struct Module *next;        /* every loaded module, newest first */
    char      name[64];         /* lower-case file name: "mathlib.dll" */
    char     *path;             /* file it came from; NULL if builtin */
    PEFile   *pe;               /* its parsed headers; NULL if builtin */
    uint8_t  *base;             /* where it's mapped; the HMODULE */
    uint32_t  size;             /* SizeOfImage */
    uint64_t  entry;            /* entry point address, or 0 */
    uint32_t *page_prot;        /* Windows PAGE_* value of each page */
    int       builtin;          /* stands in for a DLL we fake */
    int       is_dll;
    int       refcount;         /* LoadLibrary count */
    int       initialised;      /* DllMain(PROCESS_ATTACH) has run */

    /* Static TLS (teb.c). tls_index is -1 without a TLS directory. */
    int       tls_index;
    uint8_t  *tls_template;
    uint64_t  tls_raw, tls_zero;
} Module;

static Module *g_modules;
static Module *g_exe;
static char    g_exe_dir[4096] = ".";   /* where DLLs are looked for first */

/* Initialisation order: a module is appended once everything it
 * imports has been loaded, so dependencies come first. Shutdown walks
 * it backwards. FreeLibrary leaves a NULL hole. */
#define MAX_MODULES 256
static Module *g_init_order[MAX_MODULES];
static int     g_ninit;

/* True if [rva, rva+len) lies inside the mapped image. */
static int in_image(PEFile *pe, uint64_t rva, uint64_t len) {
    uint64_t size = pe->opt->SizeOfImage;
    return rva <= size && len <= size - rva;
}

/* Find the NUL-terminated string at `rva` inside the mapped image. */
static char *image_str(PEFile *pe, uint8_t *base, uint64_t rva) {
    if (!in_image(pe, rva, 1)) return NULL;
    char *s = (char *)base + rva;
    return memchr(s, 0, pe->opt->SizeOfImage - rva) ? s : NULL;
}

/* "C:\\dir\\MathLib" -> "mathlib.dll": drop the directory, lower-case,
 * and add .dll if there's no extension, as LoadLibrary does. */
static void module_key(const char *in, char *out, size_t n) {
    const char *s = in;
    for (const char *p = in; *p; p++) if (*p == '/' || *p == '\\') s = p + 1;
    size_t i = 0;
    for (; s[i] && i + 5 < n; i++) out[i] = (char)tolower((unsigned char)s[i]);
    out[i] = 0;
    if (!strchr(out, '.')) strcat(out, ".dll");
}

static Module *find_module(const char *name) {
    char key[64];
    module_key(name, key, sizeof key);
    for (Module *m = g_modules; m; m = m->next)
        if (strcmp(m->name, key) == 0) return m;
    return NULL;
}

static Module *module_from_handle(const void *h) {
    for (Module *m = g_modules; m; m = m->next)
        if (m->base == h) return m;
    return NULL;
}

/* The mapped module containing `addr`, or NULL. */
static Module *module_from_addr(const void *addr) {
    uintptr_t a = (uintptr_t)addr;
    for (Module *m = g_modules; m; m = m->next)
        if (!m->builtin && a >= (uintptr_t)m->base && a - (uintptr_t)m->base < m->size)
            return m;
    return NULL;
}

/* Defined below, but the API stubs in win32.c call them. */
static Module *load_dll(const char *name);
static Module *load_library(const char *name);
static int     free_library(Module *m);
static void   *module_export(Module *m, const char *name, uint32_t ordinal, int depth);
static void    shutdown_modules(void);

#include "teb.c"
#include "win32.c"

/* The Windows protection for a section, from its characteristics. */
static uint32_t section_prot(SectionHeader *s) {
    int r = !!(s->Characteristics & SCN_MEM_READ);
    int w = !!(s->Characteristics & SCN_MEM_WRITE);
    int x = !!(s->Characteristics & SCN_MEM_EXECUTE);
    if (x) return w ? PAGE_EXECUTE_READWRITE : r ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    return w ? PAGE_READWRITE : PAGE_READONLY;  /* nothing set: read-only */
}

/* ---- exports ------------------------------------------------------------- */

/* Look up an export by name, or by ordinal when name is NULL. Follows
 * forwarders ("base.base_value") into other DLLs, loading them if need
 * be. Builtins have no export table: names go to win32.c's stubs, and
 * ordinals can't be resolved. `depth` stops forwarder loops. */
static void *module_export(Module *m, const char *name, uint32_t ordinal, int depth) {
    if (depth > 8) return NULL;
    if (m->builtin) return name ? find_stub(name) : NULL;

    PEFile *pe = m->pe;
    DataDirectory *d = &pe->opt->DataDirectory[DIR_EXPORT];
    if (!d->VirtualAddress || !in_image(pe, d->VirtualAddress, sizeof(ExportDirectory)))
        return NULL;
    ExportDirectory *ed = (ExportDirectory *)(m->base + d->VirtualAddress);
    if (!in_image(pe, ed->AddressOfFunctions, 4ULL * ed->NumberOfFunctions) ||
        !in_image(pe, ed->AddressOfNames, 4ULL * ed->NumberOfNames) ||
        !in_image(pe, ed->AddressOfNameOrdinals, 2ULL * ed->NumberOfNames))
        return NULL;
    uint32_t *funcs = (uint32_t *)(m->base + ed->AddressOfFunctions);
    uint32_t *names = (uint32_t *)(m->base + ed->AddressOfNames);
    uint16_t *ords  = (uint16_t *)(m->base + ed->AddressOfNameOrdinals);

    /* Turn the request into an index into funcs[]. */
    uint64_t idx = UINT64_MAX;
    if (name) {
        for (uint32_t i = 0; i < ed->NumberOfNames; i++) {
            char *n = image_str(pe, m->base, names[i]);
            if (n && strcmp(n, name) == 0) { idx = ords[i]; break; }
        }
    } else if (ordinal >= ed->Base) {
        idx = (uint64_t)ordinal - ed->Base;
    }
    if (idx >= ed->NumberOfFunctions || !funcs[idx]) return NULL;

    uint32_t rva = funcs[idx];
    if (rva >= d->VirtualAddress && rva - d->VirtualAddress < d->Size) {
        /* Forwarder: "DLL.Name" or "DLL.#ordinal". */
        char *fwd = image_str(pe, m->base, rva);
        char *dot = fwd ? strrchr(fwd, '.') : NULL;
        if (!dot || dot == fwd) return NULL;
        char dll[64];
        snprintf(dll, sizeof dll, "%.*s", (int)(dot - fwd), fwd);
        Module *target = load_dll(dll);
        if (!target) return NULL;
        if (dot[1] == '#') return module_export(target, NULL, (uint32_t)atoi(dot + 2), depth + 1);
        return module_export(target, dot + 1, 0, depth + 1);
    }
    if (!in_image(pe, rva, 1)) return NULL;
    return m->base + rva;
}

/* ---- mapping one image ---------------------------------------------------- */

/* Map and relocate `pe` (steps 1-3). Fills in m->base, size, page_prot. */
static int map_image(PEFile *pe, Module *m) {
    uint32_t image_size = pe->opt->SizeOfImage;
    if (image_size == 0 || pe->opt->SizeOfHeaders > image_size ||
        pe->opt->SizeOfHeaders > pe->size) {
        fprintf(stderr, "bad SizeOfImage/SizeOfHeaders\n");
        return -1;
    }

    /* 1. Reserve the whole image as RW first; we tighten perms later.
     *    MAP_ANON gives zero-filled pages, which also zeroes .bss for us.
     *    An image whose relocations were stripped only runs at ImageBase,
     *    so ask for that address (a hint; the kernel may still refuse). */
    int stripped = pe->coff->Characteristics & FILE_RELOCS_STRIPPED;
    void *want = stripped ? (void *)(uintptr_t)pe->opt->ImageBase : NULL;
    uint8_t *base = mmap(want, image_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return -1; }

    /* Every page starts out as mmap left it, read-write. */
    long pg = page_size();
    size_t npages = ((size_t)image_size + pg - 1) / pg;
    m->base      = base;
    m->size      = image_size;
    m->page_prot = malloc(npages * sizeof(uint32_t));
    if (!m->page_prot) { perror("malloc"); munmap(base, image_size); return -1; }
    for (size_t i = 0; i < npages; i++) m->page_prot[i] = PAGE_READWRITE;

    /* 2. Copy headers, then each section from file offset to its RVA.
     *    Raw data is padded to FileAlignment, so it can be larger than
     *    the section's real (virtual) size; copy only what belongs. */
    memcpy(base, pe->data, pe->opt->SizeOfHeaders);
    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        uint32_t n = s->SizeOfRawData;
        if (s->VirtualSize && s->VirtualSize < n) n = s->VirtualSize;
        if (!in_image(pe, s->VirtualAddress, n)) {
            fprintf(stderr, "section %d lies outside SizeOfImage\n", i);
            goto fail;
        }
        if (n)
            memcpy(base + s->VirtualAddress, pe->data + s->PointerToRawData, n);
    }

    /* 3. Base relocations. The image assumes it loads at ImageBase; we
     *    loaded at `base`. Every absolute (DIR64) address baked into the
     *    code must be shifted by this delta. */
    int64_t delta = (int64_t)(uintptr_t)base - (int64_t)pe->opt->ImageBase;
    DataDirectory *rel = &pe->opt->DataDirectory[DIR_BASERELOC];
    if (delta != 0 && rel->VirtualAddress) {
        if (!in_image(pe, rel->VirtualAddress, rel->Size)) {
            fprintf(stderr, "relocation directory out of range\n");
            goto fail;
        }
        uint8_t *p   = base + rel->VirtualAddress;
        uint8_t *end = p + rel->Size;
        while ((size_t)(end - p) >= sizeof(BaseRelocBlock)) {
            BaseRelocBlock *blk = (BaseRelocBlock *)p;
            /* A block smaller than its own header would never advance p. */
            if (blk->BlockSize < sizeof(*blk) ||
                blk->BlockSize > (size_t)(end - p)) {
                fprintf(stderr, "malformed relocation block\n");
                goto fail;
            }
            int count = (blk->BlockSize - sizeof(*blk)) / 2;
            uint16_t *entries = (uint16_t *)(blk + 1);
            for (int i = 0; i < count; i++) {
                int type   = entries[i] >> 12;
                int offset = entries[i] & 0x0FFF;
                if (type == REL_DIR64) {
                    uint64_t rva = (uint64_t)blk->PageRVA + offset;
                    if (!in_image(pe, rva, 8)) {
                        fprintf(stderr, "relocation target out of range\n");
                        goto fail;
                    }
                    uint64_t *fixup = (uint64_t *)(base + rva);
                    *fixup += delta;
                } else if (type != REL_ABSOLUTE) {
                    /* REL_ABSOLUTE (0) is padding; anything else we
                     * don't implement would leave a stale address. */
                    fprintf(stderr, "unsupported relocation type %d\n", type);
                    goto fail;
                }
            }
            p += blk->BlockSize;
        }
    } else if (delta != 0 && stripped) {
        /* Linked with relocations stripped: the code only works at
         * ImageBase, and we didn't get it. (No .reloc *without* that
         * flag just means there was nothing to fix up.) */
        fprintf(stderr, "image has no relocations and can't be loaded "
                        "at 0x%llx\n", (unsigned long long)pe->opt->ImageBase);
        goto fail;
    }
    return 0;

fail:
    munmap(base, image_size);
    free(m->page_prot);
    m->page_prot = NULL;
    return -1;
}

/* 4. Bind imports. For each DLL the image names, load it (which may
 *    load more), then write each function's address into the Import
 *    Address Table (FirstThunk) slot the code will call through.
 *    Collect every failure before giving up, so one run lists all the
 *    stubs still to write. */
static int bind_imports(Module *m) {
    PEFile *pe = m->pe;
    uint8_t *base = m->base;
    int unresolved = 0;
    DataDirectory *imp = &pe->opt->DataDirectory[DIR_IMPORT];
    if (!imp->VirtualAddress) return 0;

    for (uint64_t d_rva = imp->VirtualAddress; ; d_rva += sizeof(ImportDescriptor)) {
        if (!in_image(pe, d_rva, sizeof(ImportDescriptor))) {
            fprintf(stderr, "import directory out of range\n");
            return -1;
        }
        ImportDescriptor *desc = (ImportDescriptor *)(base + d_rva);
        if (!desc->Name) break;

        char *dll_name = image_str(pe, base, desc->Name);
        if (!dll_name) { fprintf(stderr, "bad import DLL name\n"); return -1; }
        Module *dll = load_dll(dll_name);
        if (!dll) {
            fprintf(stderr, "  [can't load %s]\n", dll_name);
            unresolved++;
        }

        uint64_t lookup_rva = desc->OriginalFirstThunk
                            ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint64_t iat_rva    = desc->FirstThunk;
        for (;; lookup_rva += 8, iat_rva += 8) {
            if (!in_image(pe, lookup_rva, 8) || !in_image(pe, iat_rva, 8)) {
                fprintf(stderr, "import thunk out of range\n");
                return -1;
            }
            uint64_t *lookup = (uint64_t *)(base + lookup_rva);
            uint64_t *iat    = (uint64_t *)(base + iat_rva);
            if (!*lookup) break;

            void *fn = NULL;
            if (*lookup & 0x8000000000000000ULL) {
                /* high bit set: import by ordinal, in the low 16 bits */
                uint32_t ord = (uint32_t)(*lookup & 0xFFFF);
                if (dll && !(fn = module_export(dll, NULL, ord, 0)))
                    fprintf(stderr, "  [unresolved import: %s!#%u]\n", dll_name, ord);
            } else {
                /* skip the 2-byte hint to reach the name */
                char *name = image_str(pe, base, (uint32_t)*lookup + 2ULL);
                if (!name) fprintf(stderr, "  [bad import name RVA]\n");
                else if (dll && !(fn = module_export(dll, name, 0, 0)))
                    fprintf(stderr, "  [unresolved import: %s!%s]\n", dll_name, name);
            }
            if (!fn) unresolved++;
            *iat = (uint64_t)(uintptr_t)fn;
        }
    }
    if (unresolved) {
        fprintf(stderr, "%s: %d import(s) unresolved\n", m->name, unresolved);
        return -1;
    }
    return 0;
}

/* 5. Apply real page permissions: headers r--, then per section.
 *    Text becomes r-x, rdata r--, data rw-. This is also what catches
 *    stray writes. image_protect rounds each section out to whole
 *    pages and records the result for VirtualQuery. */
static int protect_image(Module *m) {
    PEFile *pe = m->pe;
    if (image_protect(m, 0, pe->opt->SizeOfHeaders, PAGE_READONLY) != 0) {
        perror("mprotect");
        return -1;
    }
    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        uint64_t len = s->VirtualSize ? s->VirtualSize : s->SizeOfRawData;
        if (len > m->size - s->VirtualAddress)
            len = m->size - s->VirtualAddress;
        if (image_protect(m, s->VirtualAddress, len, section_prot(s)) != 0) {
            perror("mprotect");
            return -1;
        }
    }
    return 0;
}

static void unlink_module(Module *m) {
    for (Module **pp = &g_modules; *pp; pp = &(*pp)->next)
        if (*pp == m) { *pp = m->next; break; }
    for (int i = 0; i < g_ninit; i++)
        if (g_init_order[i] == m) g_init_order[i] = NULL;
}

static void free_module(Module *m) {
    if (!m->builtin && m->base) munmap(m->base, m->size);
    free(m->page_prot);
    free(m->path);
    free(m);
}

/* Load the PE file at `path` and everything it imports. */
static Module *load_pe(const char *path) {
    PEFile *pe = pe_open(path);
    if (!pe) return NULL;

    Module *m = calloc(1, sizeof(Module));
    if (!m) { perror("calloc"); return NULL; }
    module_key(path, m->name, sizeof m->name);
    m->path      = strdup(path);
    m->pe        = pe;
    m->is_dll    = !!(pe->coff->Characteristics & FILE_DLL);
    m->refcount  = 1;
    m->tls_index = -1;

    if (map_image(pe, m) != 0) { free_module(m); return NULL; }

    /* Register before binding imports, so a DLL that (indirectly)
     * imports this one finds it instead of loading it twice. */
    m->next = g_modules;
    g_modules = m;
    if (m->is_dll) {
        printf("== loaded %s at 0x%llx ==\n", m->name,
               (unsigned long long)(uintptr_t)m->base);
    }

    if (bind_imports(m) != 0 || protect_image(m) != 0) goto fail;

    if (pe->opt->AddressOfEntryPoint) {
        if (!in_image(pe, pe->opt->AddressOfEntryPoint, 1)) {
            fprintf(stderr, "entry point outside the image\n");
            goto fail;
        }
        m->entry = (uint64_t)(uintptr_t)m->base + pe->opt->AddressOfEntryPoint;
    }
    if (setup_module_tls(m) != 0) goto fail;

    if (g_ninit == MAX_MODULES) { fprintf(stderr, "too many modules\n"); goto fail; }
    g_init_order[g_ninit++] = m;
    return m;

fail:
    unlink_module(m);
    free_module(m);
    return NULL;
}

/* Find a DLL's file: next to the .exe first, then in the current
 * directory. Windows file names are case-insensitive, so compare that
 * way. Returns a malloc'd path, or NULL. */
static char *find_dll_file(const char *key) {
    const char *dirs[2] = { g_exe_dir, "." };
    int ndirs = strcmp(g_exe_dir, ".") == 0 ? 1 : 2;

    for (int i = 0; i < ndirs; i++) {
        DIR *d = opendir(dirs[i]);
        if (!d) continue;
        struct dirent *e;
        while ((e = readdir(d))) {
            if (strcasecmp(e->d_name, key) != 0) continue;
            size_t n = strlen(dirs[i]) + strlen(e->d_name) + 2;
            char *path = malloc(n);
            if (path) snprintf(path, n, "%s/%s", dirs[i], e->d_name);
            closedir(d);
            return path;
        }
        closedir(d);
    }
    return NULL;
}

/* The system DLLs win32.c stands in for. Anything else has to be a
 * real file, as on Windows. */
static const char *g_builtin_dlls[] = {
    "kernel32.dll", "kernelbase.dll", "ntdll.dll", "msvcrt.dll", NULL
};

/* Load a DLL by name, or return the copy already loaded. A file on disk
 * wins; failing that, a builtin is a stand-in whose exports are our
 * stubs. */
static Module *load_dll(const char *name) {
    Module *m = find_module(name);
    if (m) { m->refcount++; return m; }

    char key[64];
    module_key(name, key, sizeof key);
    char *path = find_dll_file(key);
    if (path) {
        m = load_pe(path);
        free(path);
        return m;
    }

    int known = 0;
    for (const char **b = g_builtin_dlls; *b; b++) known |= strcmp(*b, key) == 0;
    if (!known) return NULL;

    /* The handle is just a unique address; nothing is mapped there. */
    m = calloc(1, sizeof(Module));
    if (!m) return NULL;
    snprintf(m->name, sizeof m->name, "%s", key);
    m->builtin   = 1;
    m->is_dll    = 1;
    m->refcount  = 1;
    m->tls_index = -1;
    m->base      = malloc(16);
    m->next      = g_modules;
    g_modules    = m;
    return m;
}

/* ---- initialisation and shutdown ------------------------------------------ */

#define DLL_THREAD_ATTACH  2
#define DLL_THREAD_DETACH  3

static void call_dll_entry(Module *m, uint32_t reason, void *reserved, int *ok) {
    if (!m->entry) return;
    int r = ((DllEntry *)(uintptr_t)m->entry)(m->base, reason, reserved);
    if (ok) *ok = r;
}

/* 7. Run DllMain(PROCESS_ATTACH) for every loaded DLL not yet
 *    initialised, in dependency order. `reserved` is non-NULL for DLLs
 *    loaded at startup and NULL for LoadLibrary, as on Windows. */
static int init_modules(int at_startup) {
    for (int i = 0; i < g_ninit; i++) {
        Module *m = g_init_order[i];
        if (!m || !m->is_dll || m->initialised) continue;
        m->initialised = 1;
        if (run_tls_callbacks(m, DLL_PROCESS_ATTACH) != 0) return -1;
        int ok = 1;
        call_dll_entry(m, DLL_PROCESS_ATTACH, at_startup ? (void *)1 : NULL, &ok);
        if (!ok) {
            fprintf(stderr, "%s: DllMain failed\n", m->name);
            m->initialised = 0;
            return -1;
        }
    }
    return 0;
}

/* At exit: DllMain(PROCESS_DETACH) and TLS callbacks, newest first. */
static void shutdown_modules(void) {
    static int done;
    if (done) return;
    done = 1;
    for (int i = g_ninit - 1; i >= 0; i--) {
        Module *m = g_init_order[i];
        if (!m) continue;
        if (m->is_dll && m->initialised) {
            call_dll_entry(m, DLL_PROCESS_DETACH, (void *)1, NULL);
            run_tls_callbacks(m, DLL_PROCESS_DETACH);
        } else if (!m->is_dll) {
            run_tls_callbacks(m, DLL_PROCESS_DETACH);
        }
    }
    fflush(NULL);
}

/* LoadLibrary: load (or re-reference) and initialise. On failure,
 * anything loaded along the way stays loaded; Windows would undo it. */
static Module *load_library(const char *name) {
    Module *m = load_dll(name);
    if (!m) return NULL;
    if (init_modules(0) != 0) return NULL;
    return m;
}

/* FreeLibrary: detach and unmap when the last reference goes. The DLLs
 * it imported keep their references; Windows would release them too. */
static int free_library(Module *m) {
    if (!m || m == g_exe) return 0;
    if (--m->refcount > 0 || m->builtin) return 1;
    if (m->initialised) {
        call_dll_entry(m, DLL_PROCESS_DETACH, NULL, NULL);
        run_tls_callbacks(m, DLL_PROCESS_DETACH);
    }
    release_module_tls(m);
    unlink_module(m);
    free_module(m);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s file.exe [args...]\n", argv[0]);
        return 2;
    }

    PEFile *pe = pe_open(argv[1]);
    if (!pe) return 1;
    pe_dump(pe);

    /* The thread comes first: DLLs with TLS need its slot array, and
     * DllMain runs on it. */
    if (setup_teb() != 0) return 1;

    const char *slash = strrchr(argv[1], '/');
    if (slash) snprintf(g_exe_dir, sizeof g_exe_dir, "%.*s", (int)(slash - argv[1]), argv[1]);
    if (!g_exe_dir[0]) strcpy(g_exe_dir, "/");

    g_exe = load_pe(argv[1]);
    if (!g_exe) return 1;
    if (g_exe->is_dll) { fprintf(stderr, "%s is a DLL, not a program\n", argv[1]); return 1; }
    g_teb->ProcessEnvironmentBlock->ImageBaseAddress = g_exe->base;

    /* The program sees its own path as argv[0], then the rest of ours. */
    g_argc = argc - 1;
    g_argv = argv + 1;
    win___initenv = environ;

    if (init_modules(1) != 0) return 1;

    printf("== jumping to entry 0x%llx ==\n\n", (unsigned long long)g_exe->entry);
    fflush(stdout);

    if (run_tls_callbacks(g_exe, DLL_PROCESS_ATTACH) != 0) return 1;

    /* The entry point uses the Windows ABI, so the pointer we call
     * through must carry the ms_abi convention too. */
    WinFn *entry = (WinFn *)(uintptr_t)g_exe->entry;
    entry();

    /* A well-behaved program calls ExitProcess and never returns here.
     * If it does return, exit cleanly. */
    printf("\n== entry returned ==\n");
    shutdown_modules();
    return 0;
}
