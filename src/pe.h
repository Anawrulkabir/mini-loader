/* pe.h — minimal PE/COFF structures for a 64-bit loader.
 *
 * We only declare the fields we actually use. The real headers
 * (winnt.h) have far more, but this keeps the layout visible and
 * makes the offsets easy to check against the spec.
 *
 * All structs are packed to match the on-disk layout exactly.
 */
#ifndef PE_H
#define PE_H

#include <stdint.h>

#pragma pack(push, 1)

/* DOS header — first 64 bytes of every PE. We only need the magic
 * ("MZ") and e_lfanew, the file offset of the real PE header. */
typedef struct {
    uint16_t e_magic;      /* 0x5A4D = "MZ" */
    uint8_t  _pad[58];
    uint32_t e_lfanew;     /* offset to the PE signature */
} DosHeader;

/* COFF file header — comes right after the "PE\0\0" signature. */
typedef struct {
    uint16_t Machine;              /* 0x8664 = x86-64 */
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} CoffHeader;

#define FILE_RELOCS_STRIPPED 0x0001  /* CoffHeader.Characteristics */

/* One entry in the data directory (imports, relocations, etc.). */
typedef struct {
    uint32_t VirtualAddress;       /* RVA */
    uint32_t Size;
} DataDirectory;

#define DIR_IMPORT     1
#define DIR_BASERELOC  5
#define DIR_TLS        9
#define NUM_DIRS       16

/* Optional header (PE32+ / 64-bit variant, Magic == 0x20B). */
typedef struct {
    uint16_t Magic;                /* 0x20B = PE32+ */
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;  /* RVA of the entry point */
    uint32_t BaseOfCode;
    uint64_t ImageBase;            /* preferred load address */
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOSVersion;
    uint16_t MinorOSVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;          /* total bytes to reserve in memory */
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectory[NUM_DIRS];
} OptHeader64;

/* Section header — one per section (.text, .data, .rdata, ...). */
typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;       /* RVA where this section loads */
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;     /* file offset of the bytes */
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SectionHeader;

#define SCN_MEM_EXECUTE 0x20000000
#define SCN_MEM_READ    0x40000000
#define SCN_MEM_WRITE   0x80000000

/* Import directory entry — one per imported DLL. */
typedef struct {
    uint32_t OriginalFirstThunk;   /* RVA to the import lookup table */
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;                 /* RVA to the DLL name string */
    uint32_t FirstThunk;           /* RVA to the import address table */
} ImportDescriptor;

/* Base relocation block header. Followed by NumberOfBlockEntries
 * 16-bit entries: top 4 bits = type, low 12 bits = offset. */
typedef struct {
    uint32_t PageRVA;
    uint32_t BlockSize;
} BaseRelocBlock;

/* TLS directory (DataDirectory[DIR_TLS]). Unlike most of the PE, these
 * are full virtual addresses, not RVAs, so base relocation fixes them
 * up. The raw data is the initial image of every thread's TLS block. */
typedef struct {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;       /* where to store this module's slot */
    uint64_t AddressOfCallBacks;   /* NULL-terminated array of VAs */
    uint32_t SizeOfZeroFill;       /* zeroed bytes after the raw data */
    uint32_t Characteristics;
} TlsDirectory64;

#define REL_ABSOLUTE 0
#define REL_DIR64    10

#pragma pack(pop)

#endif /* PE_H */
