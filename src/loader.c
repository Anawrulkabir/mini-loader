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
static WINAPI void  *my_GetStdHandle(uint32_t n)          { return (void *)(uintptr_t)n; }

/* WriteFile(handle, buf, len, &written, overlapped) — enough of the
 * signature to route console output to POSIX write(). */
static WINAPI int my_WriteFile(void *h, const void *buf, uint32_t len,
                               uint32_t *written, void *ovl) {
    (void)h; (void)ovl;
    ssize_t n = write(1, buf, len);
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
    return (void *)0;  /* calling it will crash — intentional for now */
}

/* ---- the loader itself -------------------------------------------------- */

typedef struct {
    uint8_t *base;     /* where we actually mapped the image */
    uint64_t entry;    /* absolute address of the entry point */
} Image;

static int load_image(PEFile *pe, Image *out) {
    uint32_t image_size = pe->opt->SizeOfImage;

    /* 1. Reserve the whole image as RW first; we tighten perms later.
     *    MAP_ANON gives zero-filled pages, which also zeroes .bss for us. */
    uint8_t *base = mmap(NULL, image_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return -1; }

    /* 2. Copy headers, then each section from file offset to its RVA. */
    memcpy(base, pe->data, pe->opt->SizeOfHeaders);
    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        if (s->SizeOfRawData)
            memcpy(base + s->VirtualAddress,
                   pe->data + s->PointerToRawData,
                   s->SizeOfRawData);
    }

    /* 3. Base relocations. The image assumes it loads at ImageBase; we
     *    loaded at `base`. Every absolute (DIR64) address baked into the
     *    code must be shifted by this delta. */
    int64_t delta = (int64_t)(uintptr_t)base - (int64_t)pe->opt->ImageBase;
    DataDirectory *rel = &pe->opt->DataDirectory[DIR_BASERELOC];
    if (delta != 0 && rel->VirtualAddress) {
        uint8_t *p   = base + rel->VirtualAddress;
        uint8_t *end = p + rel->Size;
        while (p < end) {
            BaseRelocBlock *blk = (BaseRelocBlock *)p;
            int count = (blk->BlockSize - sizeof(*blk)) / 2;
            uint16_t *entries = (uint16_t *)(blk + 1);
            for (int i = 0; i < count; i++) {
                int type   = entries[i] >> 12;
                int offset = entries[i] & 0x0FFF;
                if (type == REL_DIR64) {
                    uint64_t *fixup = (uint64_t *)(base + blk->PageRVA + offset);
                    *fixup += delta;
                }
                /* REL_ABSOLUTE (0) is padding — skip. */
            }
            p += blk->BlockSize;
        }
    }

    /* 4. Bind imports. For each imported name, write the address of our
     *    stub into the Import Address Table (FirstThunk) slot the code
     *    will actually call through. */
    DataDirectory *imp = &pe->opt->DataDirectory[DIR_IMPORT];
    if (imp->VirtualAddress) {
        ImportDescriptor *desc =
            (ImportDescriptor *)(base + imp->VirtualAddress);
        for (; desc->Name; desc++) {
            uint32_t lookup_rva = desc->OriginalFirstThunk
                                ? desc->OriginalFirstThunk : desc->FirstThunk;
            uint64_t *lookup = (uint64_t *)(base + lookup_rva);
            uint64_t *iat    = (uint64_t *)(base + desc->FirstThunk);
            for (; *lookup; lookup++, iat++) {
                if (*lookup & 0x8000000000000000ULL) {
                    fprintf(stderr, "  [ordinal imports not supported]\n");
                    *iat = 0;
                } else {
                    char *name = (char *)(base + (uint32_t)*lookup) + 2;
                    *iat = (uint64_t)(uintptr_t)resolve_stub(name);
                }
            }
        }
    }

    /* 5. Apply real page permissions per section. Text becomes r-x,
     *    rdata r--, data rw-. This is also what catches stray writes. */
    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        int prot = 0;
        if (s->Characteristics & SCN_MEM_READ)    prot |= PROT_READ;
        if (s->Characteristics & SCN_MEM_WRITE)   prot |= PROT_WRITE;
        if (s->Characteristics & SCN_MEM_EXECUTE) prot |= PROT_EXEC;
        /* round the section up to a page boundary */
        long pg = sysconf(_SC_PAGESIZE);
        uint32_t vs = s->VirtualSize ? s->VirtualSize : s->SizeOfRawData;
        size_t len = (vs + pg - 1) & ~(pg - 1);
        mprotect(base + s->VirtualAddress, len, prot ? prot : PROT_READ);
    }

    out->base  = base;
    out->entry = (uint64_t)(uintptr_t)base + pe->opt->AddressOfEntryPoint;
    return 0;
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
