/* loader.c — step 2: actually load and run the image.
 *
 * Pipeline:
 *   1. reserve SizeOfImage bytes of memory
 *   2. copy headers + each section to its RVA
 *   3. apply base relocations (we rarely get the preferred ImageBase)
 *   4. bind imports to our own stub functions
 *   5. set per-section page permissions
 *   6. build a TEB, point gs at it, run TLS callbacks (teb.c)
 *   7. jump to the entry point
 *
 * The fake Windows API the image imports lives in win32.c.
 *
 * We build everything as one translation unit by including the other
 * .c files. The parser's main() is behind PARSE_MAIN, so it stays out.
 */
#define _GNU_SOURCE   /* pthread_getattr_np, in teb.c */
#include "pe_parse.c"

#include <sys/mman.h>
#include <unistd.h>

/* Windows x64 calling convention; see win32.c. Function pointers into
 * the image need it too, via a function type: WinFn *f. */
#define WINAPI __attribute__((ms_abi))
typedef WINAPI void WinFn(void);

/* ---- the loader itself -------------------------------------------------- */

typedef struct {
    uint8_t  *base;      /* where we actually mapped the image */
    uint32_t  size;      /* SizeOfImage */
    uint64_t  entry;     /* absolute address of the entry point */
    uint32_t *page_prot; /* Windows PAGE_* value of each page */
} Image;

/* The loaded image, for the API stubs that need to know about it
 * (VirtualQuery, VirtualProtect). */
static Image g_img;

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

static int load_image(PEFile *pe, Image *out) {
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
    out->base      = base;
    out->size      = image_size;
    out->page_prot = malloc(npages * sizeof(uint32_t));
    if (!out->page_prot) { perror("malloc"); munmap(base, image_size); return -1; }
    for (size_t i = 0; i < npages; i++) out->page_prot[i] = PAGE_READWRITE;

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

    /* 4. Bind imports. For each imported name, write the address of our
     *    stub into the Import Address Table (FirstThunk) slot the code
     *    will actually call through. Collect every failure before giving
     *    up, so one run lists all the stubs still to write. */
    int unresolved = 0;
    DataDirectory *imp = &pe->opt->DataDirectory[DIR_IMPORT];
    if (imp->VirtualAddress) {
        for (uint64_t d_rva = imp->VirtualAddress; ; d_rva += sizeof(ImportDescriptor)) {
            if (!in_image(pe, d_rva, sizeof(ImportDescriptor))) {
                fprintf(stderr, "import directory out of range\n");
                goto fail;
            }
            ImportDescriptor *desc = (ImportDescriptor *)(base + d_rva);
            if (!desc->Name) break;

            uint64_t lookup_rva = desc->OriginalFirstThunk
                                ? desc->OriginalFirstThunk : desc->FirstThunk;
            uint64_t iat_rva    = desc->FirstThunk;
            for (;; lookup_rva += 8, iat_rva += 8) {
                if (!in_image(pe, lookup_rva, 8) || !in_image(pe, iat_rva, 8)) {
                    fprintf(stderr, "import thunk out of range\n");
                    goto fail;
                }
                uint64_t *lookup = (uint64_t *)(base + lookup_rva);
                uint64_t *iat    = (uint64_t *)(base + iat_rva);
                if (!*lookup) break;

                void *fn = NULL;
                if (*lookup & 0x8000000000000000ULL) {
                    fprintf(stderr, "  [ordinal imports not supported: #%llu]\n",
                            (unsigned long long)(*lookup & 0xFFFF));
                } else {
                    /* skip the 2-byte hint to reach the name */
                    char *name = image_str(pe, base, (uint32_t)*lookup + 2ULL);
                    if (name) fn = resolve_stub(name);
                    else fprintf(stderr, "  [bad import name RVA]\n");
                }
                if (!fn) unresolved++;
                *iat = (uint64_t)(uintptr_t)fn;
            }
        }
    }
    if (unresolved) {
        fprintf(stderr, "%d import(s) unresolved; refusing to run\n", unresolved);
        goto fail;
    }

    /* 5. Apply real page permissions: headers r--, then per section.
     *    Text becomes r-x, rdata r--, data rw-. This is also what
     *    catches stray writes. image_protect rounds each section out to
     *    whole pages and records the result for VirtualQuery. */
    if (image_protect(out, 0, pe->opt->SizeOfHeaders, PAGE_READONLY) != 0) {
        perror("mprotect");
        goto fail;
    }
    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        uint64_t len = s->VirtualSize ? s->VirtualSize : s->SizeOfRawData;
        if (len > image_size - s->VirtualAddress)
            len = image_size - s->VirtualAddress;
        if (image_protect(out, s->VirtualAddress, len, section_prot(s)) != 0) {
            perror("mprotect");
            goto fail;
        }
    }

    out->entry = (uint64_t)(uintptr_t)base + pe->opt->AddressOfEntryPoint;
    if (!in_image(pe, pe->opt->AddressOfEntryPoint, 1)) {
        fprintf(stderr, "entry point outside the image\n");
        goto fail;
    }
    return 0;

fail:
    munmap(base, image_size);
    free(out->page_prot);
    memset(out, 0, sizeof(*out));
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s file.exe [args...]\n", argv[0]);
        return 2;
    }

    PEFile *pe = pe_open(argv[1]);
    if (!pe) return 1;
    pe_dump(pe);

    if (load_image(pe, &g_img) != 0) return 1;

    /* The program sees its own path as argv[0], then the rest of ours. */
    g_argc = argc - 1;
    g_argv = argv + 1;
    win___initenv = environ;

    if (setup_teb(pe, &g_img) != 0) return 1;

    printf("== jumping to entry 0x%llx ==\n\n",
           (unsigned long long)g_img.entry);
    fflush(stdout);

    if (run_tls_callbacks(pe, &g_img, DLL_PROCESS_ATTACH) != 0) return 1;

    /* The entry point uses the Windows ABI, so the pointer we call
     * through must carry the ms_abi convention too. */
    WinFn *entry = (WinFn *)(uintptr_t)g_img.entry;
    entry();

    /* A well-behaved program calls ExitProcess and never returns here.
     * If it does return, exit cleanly. */
    printf("\n== entry returned ==\n");
    return 0;
}
