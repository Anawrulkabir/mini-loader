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

/* Convert an RVA (address relative to ImageBase) into a pointer into
 * our raw file buffer, by finding which section contains it. Returns
 * NULL if the RVA falls outside every section. */
static uint8_t *rva_to_ptr(PEFile *pe, uint32_t rva) {
    for (int i = 0; i < pe->coff->NumberOfSections; i++) {
        SectionHeader *s = &pe->sections[i];
        uint32_t start = s->VirtualAddress;
        uint32_t end   = start + s->SizeOfRawData;
        if (rva >= start && rva < end) {
            return pe->data + s->PointerToRawData + (rva - start);
        }
    }
    return NULL;
}

static PEFile *pe_open(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    PEFile *pe = calloc(1, sizeof(PEFile));
    pe->size = (size_t)sz;
    pe->data = malloc(sz);
    if (fread(pe->data, 1, sz, f) != (size_t)sz) {
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

    /* PE signature "PE\0\0" at e_lfanew */
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

    /* Section table follows the optional header. */
    pe->sections = (SectionHeader *)((uint8_t *)pe->opt +
                                     pe->coff->SizeOfOptionalHeader);
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

    /* Walk the import directory and list DLLs + named functions. */
    DataDirectory *imp = &pe->opt->DataDirectory[DIR_IMPORT];
    if (imp->VirtualAddress == 0) {
        printf("  Imports          (none)\n");
        return;
    }
    printf("  Imports:\n");
    ImportDescriptor *desc = (ImportDescriptor *)rva_to_ptr(pe, imp->VirtualAddress);
    for (; desc && desc->Name; desc++) {
        char *dll = (char *)rva_to_ptr(pe, desc->Name);
        printf("    %s\n", dll ? dll : "(?)");

        /* OriginalFirstThunk points at the import lookup table:
         * an array of 64-bit entries, terminated by a zero. Each
         * entry is either an ordinal (high bit set) or an RVA to a
         * hint/name table entry (2-byte hint, then the name). */
        uint32_t thunk_rva = desc->OriginalFirstThunk
                           ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint64_t *thunk = (uint64_t *)rva_to_ptr(pe, thunk_rva);
        for (; thunk && *thunk; thunk++) {
            if (*thunk & 0x8000000000000000ULL) {
                printf("        #%llu (ordinal)\n",
                       (unsigned long long)(*thunk & 0xFFFF));
            } else {
                char *name = (char *)rva_to_ptr(pe, (uint32_t)*thunk) + 2;
                printf("        %s\n", name);
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
