// Load the Android CoreADI build on aarch64 and call it the way feed_spim
// calls the Windows one, so the two can be compared directly.
//
// libCoreADI.so exports the SAME obfuscated names as CoreADI64.dll:
//   cvu8io98wun  (init)      vdfut768ig  (the gate)      JNI_OnLoad
// so the call shape is identical to the Windows ENVS model: a 32-byte Common
// ADI Header in RDX, {buffer_ptr@0, u32 input_len@8, u32 cursor@0xC,
// out_ptr@0x10, u32 out_len@0x18, u32 flags@0x1C}.
//
// Build:  aarch64-linux-gnu-gcc -O0 -o adi_run adi_run.c -ldl
// Run:    qemu-aarch64 -L /usr/aarch64-linux-gnu ./adi_run spim.bin
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t (*export_fn)(uint64_t, uint64_t, uint64_t, uint64_t);

struct adi_env {
    uint64_t buffer_ptr;
    uint32_t input_len;
    uint32_t cursor;
    uint64_t out_ptr;
    uint32_t out_len;
    uint32_t flags;
};

#define SPIM_LEN 347
#define OUT_CAP  65536

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <spim.bin>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open spim"); return 1; }
    static uint8_t spim[SPIM_LEN];
    size_t got = fread(spim, 1, SPIM_LEN, f);
    fclose(f);
    printf("[adi] spim %zu bytes, first u32 LE = %#x\n", got,
           *(uint32_t *)spim);

    void *h = dlopen("./libCoreADI.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    printf("[adi] dlopen OK\n");

    export_fn init = (export_fn)dlsym(h, "cvu8io98wun");
    export_fn op = (export_fn)dlsym(h, "vdfut768ig");
    if (!init || !op) {
        fprintf(stderr, "dlsym: init=%p op=%p (%s)\n", (void *)init, (void *)op, dlerror());
        return 1;
    }
    printf("[adi] exports resolved: cvu8io98wun=%p vdfut768ig=%p\n",
           (void *)init, (void *)op);

    // The init call, same shape feed_spim uses: a zeroed 1 KiB region, twice.
    static uint8_t inner[1024];
    uint64_t rc_init = init((uint64_t)inner, (uint64_t)inner, 0, 0);
    printf("[adi] cvu8io98wun -> %#llx (%lld)\n",
           (unsigned long long)rc_init, (long long)rc_init);

    // The gate call, the honest ENVS envelope.
    static uint8_t out[OUT_CAP];
    struct adi_env env = {
        .buffer_ptr = (uint64_t)spim,
        .input_len = (uint32_t)got,
        .cursor = 0,
        .out_ptr = (uint64_t)out,
        .out_len = OUT_CAP,
        .flags = 0,
    };
    uint64_t rc = op((uint64_t)&env, (uint64_t)&env, 0, 0);
    size_t nz = 0;
    for (size_t i = 0; i < OUT_CAP; i++) { if (out[i]) nz++; }
    printf("[adi] vdfut768ig -> %#llx (%lld)\n", (unsigned long long)rc, (long long)rc);
    printf("[adi] cursor=%u input_len=%u OUT_nonzero=%zu\n", env.cursor, env.input_len, nz);
    if (nz) {
        printf("[adi] out[0..64] = ");
        for (int i = 0; i < 64 && (size_t)i < OUT_CAP; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
