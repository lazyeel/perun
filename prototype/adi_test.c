/*
 * Copyright 2026 lazyeel (https://github.com/lazyeel)
 * SPDX-License-Identifier: Apache-2.0
 */

/* adi_test.c — Test harness: load CoreADI64.dll and call ADI exports
 * Build: gcc pe_loader.c win32_shims.c shim_table.c adi_test.c -O2 -Wall -o adi_pe_loader -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "pe_loader.h"
#include "win32_types.h"

/* Generic stub for unimplemented imports */
static intptr_t generic_stub(void) { return 0; }

int main(int argc, char *argv[]) {
    const char *dll_path = argc > 1 ? argv[1] : "./CoreADI64.dll";
    
    fprintf(stderr, "[adi] ENTERING MAIN\n");
    fflush(stderr);
    printf("[adi] Loading %s\n", dll_path);
    fflush(stdout);
    
    pe_module_t *mod = pe_load(dll_path);
    if (!mod) {
        fprintf(stderr, "[adi] Failed to load DLL\n");
        return 1;
    }
    
    /* ── Call DllMain to initialize the DLL's CRT ── */
    printf("\n[adi] Calling DllMain(DLL_PROCESS_ATTACH)...\n");
    
    uint32_t entry_rva = 0x131b00; /* from our PE analysis */
    typedef BOOL (*dllmain_fn_t)(void *, DWORD, void *);
    dllmain_fn_t dll_main = (dllmain_fn_t)((uint8_t *)pe_get_base(mod) + entry_rva);
    
    fflush(stdout);
    
    /* Try calling the REAL DllMain body at 0x1319b4 (bypasses CRT startup) */
    BOOL init_result = FALSE;
    printf("[adi] Calling real DllMain body at RVA 0x1319b4...\n");
    {
        typedef BOOL (*real_dllmain_t)(void *, DWORD, void *);
        real_dllmain_t real_dm = (real_dllmain_t)((uint8_t *)pe_get_base(mod) + 0x1319b4);
        init_result = real_dm(pe_get_base(mod), DLL_PROCESS_ATTACH, NULL);
        printf("[adi] Real DllMain => %d\n", (int)init_result);
    }
    
    if (!init_result) {
        fprintf(stderr, "[adi] WARNING: DllMain returned FALSE.\n");
        fprintf(stderr, "[adi] Some ADI functions may not work correctly.\n");
        /* Continue anyway — some exports may still be callable */
    }
    
    /* ── Parse and list exports ── */
    printf("\n[adi] === Exports ===\n");
    
    /* We need the export info stored in pe_module_t.
     * The pe_loader already parsed it during loading. */
    extern struct { void *base; size_t image_size; } _dummy; /* placeholder */
    
    /* Access export tables through the module base */
    uint8_t *image_base = (uint8_t *)pe_get_base(mod);
    
    /* Export directory RVA was 0x19c150 for this specific DLL */
    /* In a production version we'd store it in pe_module_t */
    const uint32_t exp_dir_offset = 0x19c150;
    const uint8_t *exp_dir = image_base + exp_dir_offset;
    
    /* Read fields with explicit offsets (avoiding struct padding) */
    uint32_t ordinal_base     = *(uint32_t *)(exp_dir + 16);
    uint32_t num_functions    = *(uint32_t *)(exp_dir + 20);
    uint32_t num_names        = *(uint32_t *)(exp_dir + 24);
    uint32_t addr_table_rva   = *(uint32_t *)(exp_dir + 28);
    uint32_t name_table_rva   = *(uint32_t *)(exp_dir + 32);
    uint32_t ord_table_rva    = *(uint32_t *)(exp_dir + 36);
    
    uint32_t *addr_table = (uint32_t *)(image_base + addr_table_rva);
    uint32_t *name_table = (uint32_t *)(image_base + name_table_rva);
    uint16_t *ord_table  = (uint16_t *)(image_base + ord_table_rva);
    
    printf("Functions=%u Named=%u OrdinalBase=%u\n",
           num_functions, num_names, ordinal_base);
    
    for (uint32_t i = 0; i < num_names && i < 5; i++) {
        const char *name = (const char *)(image_base + name_table[i]);
        uint16_t ord_idx = ord_table[i];
        uint32_t func_rva = addr_table[ord_idx];
        
        printf("  [%u] '%s' @ RVA %#06x\n", i, name, func_rva);
    }

    /* ── Call the ADI dispatcher ── */
    if (num_names > 0 && num_functions > 0) {
        printf("\n[adi] === Calling ADI Dispatcher ===\n");
        
        uint16_t first_ord = ord_table[0];
        void *dispatch_func = (void *)(image_base + addr_table[first_ord]);
        
        printf("Dispatch function at %p\n", dispatch_func);
        fflush(stdout);
        
        /* The ADI dispatcher signature (recovered from Android .so analysis):
         *
         * int dispatch(
         *     uint32_t operation_code,     ← what to do
         *     uint8_t *output_buffer,       ← where to write results
         *     uint32_t output_length,       ← buffer size
         *     const char *device_guid,      ← device identifier string
         *     uint32_t guid_length,         ← length of guid
         *     void *extra_data,             ← optional additional data
         *     uint32_t extra_data_len       ← its length
         * );
         */
        typedef int (*adi_dispatch_t)(uint32_t, uint8_t *, uint32_t,
                                       const char *, uint32_t,
                                       void *, uint32_t);
        
        adi_dispatch_t dispatch = (adi_dispatch_t)dispatch_func;
        
        uint8_t output_buffer[4096];
        memset(output_buffer, 0xAB, sizeof(output_buffer));
        
        const char *test_guid = "12000000ba69c18b";
        
        printf("Calling dispatch(0, buf, 4096, \"%s\", %zu, NULL, 0)\n",
               test_guid, strlen(test_guid));
        fflush(stdout);
        
        int return_value = dispatch(0, output_buffer, sizeof(output_buffer),
                                     test_guid, (uint32_t)strlen(test_guid),
                                     NULL, 0);
        
        printf("[adi] Dispatch => %d\n", return_value);
        
        if (return_value == 0) {
            printf("\n*** ADI DISPATCH SUCCESSFUL ON x86_64 NATIVE ***\n");
            
            /* Check if output was written */
            int non_default_bytes = 0;
            for (int j = 0; j < 64; j++) {
                if (output_buffer[j] != 0xAB) non_default_bytes++;
            }
            
            if (non_default_bytes > 0) {
                printf("[adi] Output data (%d bytes modified):\n", non_default_bytes);
                for (int row = 0; row < 64; row += 16) {
                    printf("  ");
                    for (int col = 0; col < 16 && row + col < 64; col++) {
                        printf("%02x ", output_buffer[row + col]);
                    }
                    printf("\n");
                }
            } else {
                printf("[adi] No output data generated (expected for op=0)\n");
            }
        } else {
            printf("[adi] Non-zero return code. This may indicate:\n");
            printf("[adi]   - Missing DllMain initialization (CRT state)\n");
            printf("[adi]   - Invalid parameters for this operation code\n");
            printf("[adi]   - Internal error in ADI engine\n");
            printf("[adi]   - Need valid GSA session tokens for provisioning\n");
        }
    }

    /* ── Cleanup ── */
    /* Call DllMain(DLL_PROCESS_DETACH) before unloading */
    dll_main(pe_get_base(mod), DLL_PROCESS_DETACH, NULL);
    
    pe_unload(mod);
    printf("\n[adi] done.\n");
    return 0;
}
