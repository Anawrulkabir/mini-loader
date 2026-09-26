/* pe_parse.c — read a PE file into memory and expose its structure.
 *
 * This is step 1: understand the file. No loading yet, just parsing
 * and validation. loader.c builds on the PEFile this produces.
 */
#include "pe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t       *data;      /* whole file slurped into memory */
    size_t         size;
    DosHeader     *dos;
    CoffHeader    *coff;
    OptHeader64   *opt;
    SectionHeader *sections;  /* array of coff->NumberOfSections */
} PEFile;

/* True if [off, off+len) lies inside the file. Every offset we read
 * from the headers is attacker-controlled, so check before touching. */
static int in_file(PEFile *pe, uint64_t off, uint64_t len) {
    return off <= pe->size && len <= pe->size - off;
}

/* Convert an RVA (address relative to ImageBase) into a pointer into
 * our raw file buffer, by finding which section contains it. Returns
 * NULL unless all `len` bytes at that RVA lie inside the section's raw
 * data (and so, since pe_open checked the sections, inside the file). */
static uint8_t *rva_to_ptr(PEFile *pe, uint32_t rva, uint32_t len) {
    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        uint32_t start = s->VirtualAddress;
        uint64_t end   = (uint64_t)start + s->SizeOfRawData;
        if (rva >= start && rva < end) {
            if ((uint64_t)rva + len > end) return NULL;
            return pe->data + s->PointerToRawData + (rva - start);
        }
    }
    return NULL;
}

/* Like rva_to_ptr, but for a NUL-terminated string: NULL unless the
 * terminator is inside the file too. */
static char *rva_to_str(PEFile *pe, uint32_t rva) {
    char *s = (char *)rva_to_ptr(pe, rva, 1);
    if (!s) return NULL;
    size_t max = pe->size - (size_t)((uint8_t *)s - pe->data);
    return memchr(s, 0, max) ? s : NULL;
}

static PEFile *pe_open(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < (long)sizeof(DosHeader)) {
        fprintf(stderr, "not a PE: file too small\n");
        fclose(f); return NULL;
    }

    PEFile *pe = calloc(1, sizeof(PEFile));
    pe->size = (size_t)sz;
    pe->data = malloc(sz);
    if (!pe->data || fread(pe->data, 1, sz, f) != (size_t)sz) {
        fprintf(stderr, "short read\n");
        fclose(f); free(pe->data); free(pe); return NULL;
    }
    fclose(f);

    /* DOS header */
    pe->dos = (DosHeader *)pe->data;
    if (pe->dos->e_magic != 0x5A4D) {
        fprintf(stderr, "not a PE: bad MZ magic\n");
        goto fail;
    }

    /* PE signature "PE\0\0" at e_lfanew, followed by the COFF header
     * and at least the fixed part of the optional header. */
    if (!in_file(pe, pe->dos->e_lfanew, 4 + sizeof(CoffHeader) + 2)) {
        fprintf(stderr, "not a PE: e_lfanew out of range\n");
        goto fail;
    }
    uint32_t *sig = (uint32_t *)(pe->data + pe->dos->e_lfanew);
    if (*sig != 0x00004550) {
        fprintf(stderr, "not a PE: bad PE signature\n");
        goto fail;
    }

    pe->coff = (CoffHeader *)(pe->data + pe->dos->e_lfanew + 4);
    pe->opt  = (OptHeader64 *)((uint8_t *)pe->coff + sizeof(CoffHeader));

    if (pe->coff->Machine != 0x8664) {
        fprintf(stderr, "not x86-64 (Machine=0x%x)\n", pe->coff->Machine);
        goto fail;
    }
    if (pe->opt->Magic != 0x20B) {
        fprintf(stderr, "not PE32+ (Magic=0x%x)\n", pe->opt->Magic);
        goto fail;
    }
    /* We index DataDirectory[] directly, so require the full table. */
    uint64_t opt_off = (uint8_t *)pe->opt - pe->data;
    if (pe->coff->SizeOfOptionalHeader < sizeof(OptHeader64) ||
        !in_file(pe, opt_off, sizeof(OptHeader64)) ||
        pe->opt->NumberOfRvaAndSizes < NUM_DIRS) {
        fprintf(stderr, "truncated optional header\n");
        goto fail;
    }

    /* Section table follows the optional header. */
    uint64_t sec_off = opt_off + pe->coff->SizeOfOptionalHeader;
    if (!in_file(pe, sec_off,
                 (uint64_t)pe->coff->NumberOfSections * sizeof(SectionHeader))) {
        fprintf(stderr, "section table out of range\n");
        goto fail;
    }
    pe->sections = (SectionHeader *)(pe->data + sec_off);

    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        if (!in_file(pe, s->PointerToRawData, s->SizeOfRawData)) {
            fprintf(stderr, "section %d raw data out of range\n", i);
            goto fail;
        }
    }
    return pe;

fail:
    free(pe->data); free(pe); return NULL;
}

static void pe_dump(PEFile *pe) {
    printf("== PE summary ==\n");
    printf("  ImageBase        0x%llx\n", (unsigned long long)pe->opt->ImageBase);
    printf("  SizeOfImage      0x%x (%u bytes)\n",
           pe->opt->SizeOfImage, pe->opt->SizeOfImage);
    printf("  EntryPoint RVA   0x%x\n", pe->opt->AddressOfEntryPoint);
    printf("  Sections         %d\n", pe->coff->NumberOfSections);

    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        char name[9] = {0};
        memcpy(name, s->Name, 8);
        printf("    %-8s RVA 0x%06x  vsize 0x%05x  rawsize 0x%05x  %c%c%c\n",
               name, s->VirtualAddress, s->VirtualSize, s->SizeOfRawData,
               (s->Characteristics & SCN_MEM_READ)    ? 'r' : '-',
               (s->Characteristics & SCN_MEM_WRITE)   ? 'w' : '-',
               (s->Characteristics & SCN_MEM_EXECUTE) ? 'x' : '-');
    }

    /* Exports, if this is a DLL: ordinal, then name or "(no name)". */
    DataDirectory *exp = &pe->opt->DataDirectory[DIR_EXPORT];
    ExportDirectory *ed = exp->VirtualAddress
        ? (ExportDirectory *)rva_to_ptr(pe, exp->VirtualAddress, sizeof(*ed)) : NULL;
    if (ed) {
        char *self = rva_to_str(pe, ed->Name);
        printf("  Exports          %s\n", self ? self : "(?)");
        for (uint32_t i = 0; i < ed->NumberOfFunctions && i < 4096; i++) {
            uint32_t *fn = (uint32_t *)rva_to_ptr(pe, ed->AddressOfFunctions + 4 * i, 4);
            if (!fn) break;
            if (!*fn) continue;               /* unused ordinal */
            const char *name = "(no name)";
            for (uint32_t j = 0; j < ed->NumberOfNames && j < 4096; j++) {
                uint16_t *o = (uint16_t *)rva_to_ptr(pe, ed->AddressOfNameOrdinals + 2 * j, 2);
                uint32_t *n = (uint32_t *)rva_to_ptr(pe, ed->AddressOfNames + 4 * j, 4);
                if (o && n && *o == i) { char *s = rva_to_str(pe, *n); if (s) name = s; break; }
            }
            int fwd = *fn >= exp->VirtualAddress && *fn - exp->VirtualAddress < exp->Size;
            char *target = fwd ? rva_to_str(pe, *fn) : NULL;
            printf("        #%-4u %s%s%s\n", ed->Base + i, name,
                   fwd ? " -> " : "", fwd ? (target ? target : "(?)") : "");
        }
    }

    /* Walk the import directory and list DLLs + named functions. */
    DataDirectory *imp = &pe->opt->DataDirectory[DIR_IMPORT];
    if (imp->VirtualAddress == 0) {
        printf("  Imports          (none)\n");
        return;
    }
    printf("  Imports:\n");
    ImportDescriptor *desc;
    for (uint32_t d_rva = imp->VirtualAddress;
         (desc = (ImportDescriptor *)rva_to_ptr(pe, d_rva, sizeof(*desc))) && desc->Name;
         d_rva += sizeof(*desc)) {
        char *dll = rva_to_str(pe, desc->Name);
        printf("    %s\n", dll ? dll : "(?)");

        /* OriginalFirstThunk points at the import lookup table:
         * an array of 64-bit entries, terminated by a zero. Each
         * entry is either an ordinal (high bit set) or an RVA to a
         * hint/name table entry (2-byte hint, then the name). */
        uint32_t thunk_rva = desc->OriginalFirstThunk
                           ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint64_t *thunk;
        for (; (thunk = (uint64_t *)rva_to_ptr(pe, thunk_rva, 8)) && *thunk;
             thunk_rva += 8) {
            if (*thunk & 0x8000000000000000ULL) {
                printf("        #%llu (ordinal)\n",
                       (unsigned long long)(*thunk & 0xFFFF));
            } else {
                /* skip the 2-byte hint to reach the name */
                char *name = rva_to_str(pe, (uint32_t)*thunk + 2);
                printf("        %s\n", name ? name : "(?)");
            }
        }
    }
}

#ifdef PARSE_MAIN
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s file.exe\n", argv[0]); return 2; }
    PEFile *pe = pe_open(argv[1]);
    if (!pe) return 1;
    pe_dump(pe);
    return 0;
}
#endif
