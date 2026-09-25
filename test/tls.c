/* tls.c — native (static) thread-local storage.
 *
 * MSVC-style TLS: code reaches its variables through the TEB, at
 * gs:[0x58][_tls_index] + offset, in a block the loader builds from the
 * image's TLS directory. mingw's gcc only does emulated TLS (TlsAlloc
 * and friends), so check.sh compiles this with clang -fno-emulated-tls
 * and links it with mingw.
 *
 * `seeded` checks the block was copied from the template, `zeroed` the
 * zero-fill that follows it.
 */
#include <stdio.h>

static _Thread_local int seeded = 7;
static _Thread_local int zeroed;

int main(void) {
    seeded += 1;
    zeroed += 2;
    printf("native tls %d %d\n", seeded, zeroed);
    return 0;
}
