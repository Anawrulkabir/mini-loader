/* teb.h — the Thread Environment Block and Process Environment Block.
 *
 * Windows keeps a per-thread block (the TEB) and points the gs segment
 * register at it, so code can reach it with a single `mov rax, gs:[0x30]`
 * (the TEB's pointer to itself). The C runtime does this on startup,
 * and so does every GetLastError, TlsGetValue and thread-local access.
 *
 * As with pe.h, we only name the fields we use; everything else is
 * padding. The offsets are fixed by the x64 ABI, so they're checked
 * with static asserts below rather than trusted to the compiler.
 */
#ifndef TEB_H
#define TEB_H

#include <stddef.h>
#include <stdint.h>

#define TLS_MINIMUM_AVAILABLE 64

typedef struct {
    uint8_t  InheritedAddressSpace;     /* 0x00 */
    uint8_t  ReadImageFileExecOptions;  /* 0x01 */
    uint8_t  BeingDebugged;             /* 0x02 */
    uint8_t  _pad0[0x10 - 0x03];
    void    *ImageBaseAddress;          /* 0x10 */
    void    *Ldr;                       /* 0x18 loader data; NULL here */
    uint8_t  _rest[0x800 - 0x20];
} Peb;

typedef struct {
    /* NT_TIB — the architecture-neutral head of the TEB. */
    void    *ExceptionList;             /* 0x00 (unused on x64) */
    void    *StackBase;                 /* 0x08 highest stack address */
    void    *StackLimit;                /* 0x10 lowest committed address */
    void    *SubSystemTib;              /* 0x18 */
    void    *FiberData;                 /* 0x20 */
    void    *ArbitraryUserPointer;      /* 0x28 */
    void    *Self;                      /* 0x30 what gs:[0x30] reads */

    void    *EnvironmentPointer;        /* 0x38 */
    uint64_t UniqueProcess;             /* 0x40 ClientId: process id */
    uint64_t UniqueThread;              /* 0x48 ClientId: thread id */
    void    *ActiveRpcHandle;           /* 0x50 */
    void   **ThreadLocalStoragePointer; /* 0x58 one block per module */
    Peb     *ProcessEnvironmentBlock;   /* 0x60 */
    uint32_t LastErrorValue;            /* 0x68 GetLastError() */
    uint8_t  _pad0[0x1480 - 0x6c];
    void    *TlsSlots[TLS_MINIMUM_AVAILABLE]; /* 0x1480 TlsGetValue() */
    uint8_t  _rest[0x1838 - 0x1680];
} Teb;

_Static_assert(offsetof(Peb, ImageBaseAddress)          == 0x10,   "PEB layout");
_Static_assert(offsetof(Teb, Self)                      == 0x30,   "TEB layout");
_Static_assert(offsetof(Teb, ThreadLocalStoragePointer) == 0x58,   "TEB layout");
_Static_assert(offsetof(Teb, ProcessEnvironmentBlock)   == 0x60,   "TEB layout");
_Static_assert(offsetof(Teb, LastErrorValue)            == 0x68,   "TEB layout");
_Static_assert(offsetof(Teb, TlsSlots)                  == 0x1480, "TEB layout");
_Static_assert(sizeof(Teb)                              == 0x1838, "TEB layout");

#endif /* TEB_H */
