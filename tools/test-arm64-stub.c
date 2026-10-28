// Execute the generated ARM64 patch with the real, copied libc++ storage helper.
// Only that helper's operator-new call is redirected to malloc. No app is loaded,
// no GUI is launched and no user preferences are accessed.
#if !defined(__APPLE__) || !defined(__aarch64__)
#error This test must run natively on an Apple Silicon Mac.
#endif
#include <assert.h>
#include <inttypes.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

extern void invoke_stub(void *code, void *result);
__asm__(".text\n.globl _invoke_stub\n_invoke_stub:\nmov x16,x0\nmov x8,x1\nbr x16\n");

static void read_at(FILE *file, long offset, void *target, size_t count) {
    assert(fseek(file, offset, SEEK_SET) == 0);
    assert(fread(target, 1, count, file) == count);
}
static uint32_t branch(long from, long to) {
    long delta = to - from;
    assert(delta % 4 == 0 && delta >= -0x8000000 && delta < 0x8000000);
    return 0x94000000 | (((uint32_t)(delta / 4)) & 0x3ffffff);
}
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <patched-thin-arm64-libcc.dylib>\n", argv[0]); return 2; }
    FILE *file = fopen(argv[1], "rb");
    assert(file);
    uint32_t header[3];
    read_at(file, 0, header, sizeof(header));
    assert(header[0] == 0xfeedfacf && header[1] == 0x100000c && header[2] == 0);
    unsigned char stub[448], helper[0x78];
    read_at(file, 0x2a7fbfc, stub, sizeof(stub));
    read_at(file, 0x23b0, helper, sizeof(helper));
    fclose(file);
    assert(*(uint32_t *)stub == 0xa9bf7bfd);
    assert(*(uint32_t *)helper == 0xa9bd57f6);
    unsigned char *code = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    assert(code != MAP_FAILED);
    pthread_jit_write_protect_np(0);
    memcpy(code, stub, sizeof(stub));
    memcpy(code + 0x400, helper, sizeof(helper));
    *(uint32_t *)(code + 16) = branch(16, 0x400);
    *(uint32_t *)(code + 0x450) = branch(0x450, 0x800);
    *(uint32_t *)(code + 0x800) = 0x58000050; // ldr x16, pc+8
    *(uint32_t *)(code + 0x804) = 0xd61f0200; // br x16
    *(uintptr_t *)(code + 0x808) = (uintptr_t)&malloc;
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(code, 0x4000);
    for (int i = 0; i < 100; ++i) {
        struct { uint64_t before; uintptr_t fields[3]; uint64_t after; } object;
        memset(&object, 0xa5, sizeof(object));
        invoke_stub(code, object.fields);
        assert(object.before == UINT64_C(0xa5a5a5a5a5a5a5a5));
        assert(object.after == UINT64_C(0xa5a5a5a5a5a5a5a5));
        assert(object.fields[1] == 392);
        assert(object.fields[2] >> 63 == 1);
        assert((object.fields[2] & ~(UINT64_C(1) << 63)) >= 393);
        const char *text = (char *)object.fields[0];
        assert(memcmp(text, stub + 56, 392) == 0);
        assert(text[392] == 0);
        free((void *)text);
    }
    munmap(code, 0x4000);
    puts("ARM64 execution: 100/100 passes; real storage helper, 392-byte key, NUL terminator, object canaries.");
    return 0;
}
