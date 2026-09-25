/* loader.c — step 2: actually load and run the image.
 *
 * Pipeline:
 *   1. reserve SizeOfImage bytes of memory
 *   2. copy headers + each section to its RVA
 *   3. apply base relocations (we rarely get the preferred ImageBase)
 *   4. bind imports to our own stub functions
 *   5. set per-section page permissions
 *   6. jump to the entry point
 *
 * We reuse the parser by including it as one translation unit. Its
 * main() is behind PARSE_MAIN, so it stays out of this build.
 */
#include "pe_parse.c"

#include <sys/mman.h>
#include <unistd.h>

/* ---- fake Windows API ---------------------------------------------------
 *
 * A Windows .exe calls functions it imports from system DLLs. We don't
 * have those DLLs; we provide our own implementations and bind the
 * import table to them. The ms_abi attribute makes these use the
 * Windows x64 calling convention (args in RCX, RDX, R8, R9) even though
 * we're compiled for the System V ABI. That is the single most important
 * detail: without it, arguments land in the wrong registers.
 */
#define WINAPI __attribute__((ms_abi))

static WINAPI void   my_ExitProcess(uint32_t code)        { exit((int)code); }
static WINAPI int    my_puts(const char *s)               { return puts(s); }

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

/* Lookup table: import name -> our stub. A real loader would load the
 * actual DLL and dlsym each name; we resolve against this table. */
typedef struct { const char *name; void *fn; } Stub;
static Stub g_stubs[] = {
    { "ExitProcess",  (void *)my_ExitProcess  },
    { "GetStdHandle", (void *)my_GetStdHandle },
    { "WriteFile",    (void *)my_WriteFile    },
    { "puts",         (void *)my_puts         },
    { NULL, NULL }
};

static void *resolve_stub(const char *name) {
    for (Stub *s = g_stubs; s->name; s++)
        if (strcmp(s->name, name) == 0) return s->fn;
    fprintf(stderr, "  [unresolved import: %s]\n", name);
    return NULL;  /* load_image refuses to run the image if any are NULL */
}

/* ---- the loader itself -------------------------------------------------- */

typedef struct {
    uint8_t *base;     /* where we actually mapped the image */
    uint64_t entry;    /* absolute address of the entry point */
} Image;

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

    /* 5. Apply real page permissions per section. Text becomes r-x,
     *    rdata r--, data rw-. This is also what catches stray writes. */
    long pg = sysconf(_SC_PAGESIZE);
    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        int prot = 0;
        if (s->Characteristics & SCN_MEM_READ)    prot |= PROT_READ;
        if (s->Characteristics & SCN_MEM_WRITE)   prot |= PROT_WRITE;
        if (s->Characteristics & SCN_MEM_EXECUTE) prot |= PROT_EXEC;
        /* round the section up to a page boundary, but not past the
         * end of our mapping */
        uint64_t vs  = s->VirtualSize ? s->VirtualSize : s->SizeOfRawData;
        uint64_t len = (vs + pg - 1) & ~(uint64_t)(pg - 1);
        if (len > image_size - s->VirtualAddress)
            len = image_size - s->VirtualAddress;
        if (len && mprotect(base + s->VirtualAddress, len,
                            prot ? prot : PROT_READ) != 0) {
            perror("mprotect");
            goto fail;
        }
    }

    out->base  = base;
    out->entry = (uint64_t)(uintptr_t)base + pe->opt->AddressOfEntryPoint;
    if (!in_image(pe, pe->opt->AddressOfEntryPoint, 1)) {
        fprintf(stderr, "entry point outside the image\n");
        goto fail;
    }
    return 0;

fail:
    munmap(base, image_size);
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s file.exe\n", argv[0]); return 2; }

    PEFile *pe = pe_open(argv[1]);
    if (!pe) return 1;
    pe_dump(pe);

    Image img;
    if (load_image(pe, &img) != 0) return 1;

    printf("== jumping to entry 0x%llx ==\n\n",
           (unsigned long long)img.entry);
    fflush(stdout);

    /* The entry point uses the Windows ABI, so the pointer we call
     * through must carry the ms_abi convention too. */
    WINAPI void (*entry)(void) = (void *)(uintptr_t)img.entry;
    entry();

    /* A well-behaved program calls ExitProcess and never returns here.
     * If it does return, exit cleanly. */
    printf("\n== entry returned ==\n");
    return 0;
}
