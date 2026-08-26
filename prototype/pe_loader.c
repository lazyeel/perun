/*
 * Copyright 2026 lazyeel (https://github.com/lazyeel)
 * SPDX-License-Identifier: Apache-2.0
 */

/* pe_loader.c — Minimal x86_64 PE32+ loader for Linux
 * Maps DLL sections at the preferred base, applies relocations,
 * patches IAT with shim functions, returns a handle for export lookup.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "win32_types.h"
#include "pe_loader.h"

/* PE structures used internally */
struct pe_module {
    void *base;
    size_t image_size;
    uint32_t num_functions;   /* total functions in export address table */
    uint32_t num_names;        /* named exports */
    uint32_t base_ordinal;     /* ordinal base */
    uint32_t addr_table_offset; /* offset from image base to export address table */
    uint32_t name_table_offset;
    uint32_t ordinal_table_offset;
};


typedef struct {
    char name[8];
    uint32_t virt_size, virt_addr, raw_size, raw_ptr;
    uint32_t reloc_ptr, line_ptr;
    uint16_t num_relocs, num_lines, chars;
} pe_section_t;

typedef struct {
    uint32_t lookup_rva, timestamp, forwarder, name_rva, iat_rva;
} import_desc_t;

void *pe_shim_lookup(const char *name);

/* Generic stub that returns 0 for unimplemented Win32 functions */
static intptr_t generic_stub(void) { return 0; }

static int rva_in_section(uint32_t rva, const pe_section_t *s) {
    return rva >= s->virt_addr && rva < s->virt_addr + s->virt_size;
}

pe_module_t *pe_load(const char *path) {
    fprintf(stderr, "[pe] opening file...\n");
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[pe] Cannot open %s\n", path); return NULL; }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    fprintf(stderr, "[pe] file size=%ld, allocating...\n", file_size);
    uint8_t *file_data = malloc(file_size);
    fprintf(stderr, "[pe] malloc returned %p\n", (void*)file_data);
    fprintf(stderr, "[pe] reading %ld bytes...\n", file_size);
    size_t bytes_read = fread(file_data, 1, file_size, f);
    fprintf(stderr, "[pe] read %ld bytes\n", bytes_read);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "[pe] Short read\n");
        fclose(f); free(file_data); return NULL;
    }
    fclose(f);

    /* Parse DOS header */
    if (file_data[0] != 'M' || file_data[1] != 'Z') {
        fprintf(stderr, "[pe] Not MZ\n"); free(file_data); return NULL;
    }
    uint32_t pe_off = *(uint32_t *)(file_data + 0x3C);
    
    /* Parse PE header */
    if (*(uint32_t *)(file_data + pe_off) != 0x00004550) {
        fprintf(stderr, "[pe] Bad PE signature\n"); free(file_data); return NULL;
    }
    
    uint16_t machine = *(uint16_t *)(file_data + pe_off + 4);
    if (machine != 0x8664) {
        fprintf(stderr, "[pe] Not x86_64\n"); free(file_data); return NULL;
    }
    
    uint16_t num_sections = *(uint16_t *)(file_data + pe_off + 6);
    uint16_t opt_header_size = *(uint16_t *)(file_data + pe_off + 20);
    
    /* Optional header */
    const uint8_t *opt = file_data + pe_off + 24;
    uint16_t magic = *(uint16_t *)opt;
    if (magic != 0x20B) {
        fprintf(stderr, "[pe] Not PE32+\n"); free(file_data); return NULL;
    }
    
    uint64_t preferred_base = *(uint64_t *)(opt + 24);
    uint32_t image_size = *(uint32_t *)(opt + 56);
    const uint32_t *dd = (const uint32_t *)(opt + 112);
    
    fprintf(stderr, "[pe] pe_load called\n");
    fprintf(stderr, "[pe] preferred_base=%#lx image_size=%u entry=%#x\n",
           (unsigned long)preferred_base, image_size);

    /* Try mapping at preferred base */
    void *image_base = mmap((void *)preferred_base, image_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                            -1, 0);
    
    if (image_base == MAP_FAILED) {
        /* Fall back to any address and apply relocations */
        image_base = mmap(NULL, image_size,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (image_base == MAP_FAILED) { perror("mmap"); free(file_data); return NULL; }
        
        fprintf(stderr, "[pe] Mapped at %p\n", image_base);
        
        /* Apply base relocations */
        if (dd[10]) { /* BaseRelocationTable */
            uint8_t *reloc_start = (uint8_t *)image_base + dd[5];
            uint32_t reloc_offset = 0;
            while (reloc_offset < dd[6]) {
                uint32_t page_rva = *(uint32_t *)(reloc_start + reloc_offset);
                uint32_t block_size = *(uint32_t *)(reloc_start + reloc_offset + 4);
                if (block_size == 0) break;
                
                uint16_t count = (block_size - 8) / sizeof(uint16_t);
                uint16_t *entries = (uint16_t *)(reloc_start + reloc_offset + 8);
                
                for (uint16_t j = 0; j < count; j++) {
                    uint16_t entry = entries[j];
                    uint16_t type = entry >> 12;
                    uint16_t offset = entry & 0xFFF;
                    
                    if (type == 10) { /* IMAGE_REL_BASED_DIR64 */
                        uint64_t *target = (uint64_t *)((uint8_t *)image_base +
                                                         page_rva + offset);
                        *target += ((uintptr_t)image_base - preferred_base);
                    }
                }
                reloc_offset += block_size;
            }
            printf("[pe] Relocations applied\n");
        }
    } else {
        fprintf(stderr, "[pe] Mapped at PREFERRED base\n");
    }

    /* Copy headers */
    pe_section_t *sections = calloc(num_sections, sizeof(pe_section_t));
    memcpy(sections, file_data + pe_off + 24 + opt_header_size,
           num_sections * sizeof(pe_section_t));
    
    uint32_t header_size = sections[0].virt_addr;
    memcpy(image_base, file_data, header_size);
    
    /* Copy sections */
    for (uint16_t i = 0; i < num_sections; i++) {
        if (sections[i].raw_size == 0 || sections[i].raw_ptr == 0) continue;
        memcpy((uint8_t *)image_base + sections[i].virt_addr,
               file_data + sections[i].raw_ptr,
               sections[i].raw_size);
    }
    fprintf(stderr, "[pe] Sections copied\n");
    
    /* Verify section copy */
    {
        uint8_t *verify_ptr = (uint8_t *)image_base + dd[0];
        
        /* Verify .text copy: first bytes should be same as file */
        fprintf(stderr, "[pe] .text verify: image=%02x%02x%02x%02x file=%02x%02x%02x%02x\n",
                ((uint8_t*)image_base)[0x1000], ((uint8_t*)image_base)[0x1001],
                ((uint8_t*)image_base)[0x1002], ((uint8_t*)image_base)[0x1003],
                file_data[0x400], file_data[0x401],
                file_data[0x402], file_data[0x403]);
        
        /* Dump export dir area in mapped memory */
        /* Dump bytes from -4 to +40 around export dir */
        fprintf(stderr, "[pe] Mapped exp_dir bytes:\n");
        for (int j = 0; j < 40; j += 16) {
            fprintf(stderr, "  +%02d: ", j);
            for (int k = 0; k < 16; k++) {
                fprintf(stderr, "%02x ", verify_ptr[j+k]);
            }
            fprintf(stderr, "\n");
        }
        
        /* Also dump from file for comparison */
        uint32_t rva_to_file_off = dd[0]; /* need section table to convert */
        fprintf(stderr, "[pe] File export dir (at .rdata offset):\n");
        /* Export dir is in .rdata: VA=0x142000 RawPtr=0x141000 */
        uint32_t file_exp_offset = 0x141000 + (dd[0] - 0x142000);
        for (int j = 0; j < 40; j += 16) {
            fprintf(stderr, "  +%02d: ", j);
            for (int k = 0; k < 16; k++) {
                fprintf(stderr, "%02x ", file_data[file_exp_offset+j+k]);
            }
            fprintf(stderr, "\n");
        }
    }

    /* Resolve imports by patching IAT */
    if (dd[2]) { /* Import Directory Table */
        fprintf(stderr, "[pe] Resolving imports...\n");
        fprintf(stderr, "[pe] dd[0]=%#x dd[1]=%#x dd[2]=%#x\n", 
                   dd[0], dd[1], dd[2]);
        fprintf(stderr, "[pe] opt=%p file_data=%p diff=%ld\n",
                (const void*)opt, (const void*)file_data, (long)(opt - file_data));
        fflush(stderr);
        
        import_desc_t *desc = (import_desc_t *)((uint8_t *)image_base + dd[2]);
        int resolved_count = 0, missing_count = 0;
        
        for (int i = 0; desc[i].name_rva != 0; i++) {
            const char *dll_name = (const char *)((uint8_t *)image_base + desc[i].name_rva);
            fprintf(stderr, "[pe-shim] Processing DLL: %s\n", dll_name);
            fflush(stderr);
            
            uint64_t *lookup = (uint64_t *)((uint8_t *)image_base + desc[i].lookup_rva);
            uint64_t *iat = (uint64_t *)((uint8_t *)image_base + desc[i].iat_rva);
            
            for (int j = 0; j < 200; j++) {
                uint64_t entry = lookup[j];
                if (entry == 0) break;
                
                if (entry & (1ULL << 63)) {
                    /* Ordinal import */
                    fprintf(stderr, "[pe-shim] WARNING: ordinal import #%u not supported\n",
                           (unsigned)(entry & 0xFFFF));
                    missing_count++;
                    continue;
                }
                
                const char *func_name = (const char *)((uint8_t *)image_base +
                                                        (entry & 0x7FFFFFFF) + 2);
                if (func_name) {
                    fprintf(stderr, "[pe-shim]   %s!%s\n", dll_name, func_name);
                    fflush(stderr);
                }
                
                void *shim_fn = pe_shim_lookup(func_name);
                
                if (shim_fn) {
                    iat[j] = (uint64_t)(uintptr_t)shim_fn;
                    resolved_count++;
                } else {
                    fprintf(stderr, "[pe-shim] MISSING: %s!%s -> using generic stub\n", 
                           dll_name, func_name);
                    /* Assign generic_stub so we don't crash on NULL function pointer */
                    extern intptr_t generic_stub(void);
                    iat[j] = (uint64_t)(uintptr_t)(void *)generic_stub;
                    missing_count++;
                }
            }
        }
        
        printf("[pe] Imports resolved: %d ok, %d missing\n", resolved_count, missing_count);
    }

    /* Set up module info */
    pe_module_t *mod = calloc(1, sizeof(pe_module_t));
    mod->base = image_base;
    mod->image_size = image_size;
    mod->num_functions = 0;
    mod->num_names = 0;
    mod->base_ordinal = 0;
    
    /* Parse exports */
    if (dd[0]) { /* Export Directory Table */
        /* Read with explicit offsets to avoid struct padding issues:
         * +0: Characteristics(2), +2: TimeDateStamp(4),
         * +6: MajorVer(2), MinorVer(2),
         * +10: NameRVA(4), +14: Base(4),
         * +18: NumFunctions(4), +22: NumNames(4),
         * +26: AddressTable(4), +30: NameTable(4), +34: OrdinalTable(4)
         */
        uint8_t *exp = (uint8_t *)image_base + dd[0];
        
        mod->base_ordinal    = *(uint32_t *)(exp + 16);
        mod->num_functions   = *(uint32_t *)(exp + 20);
        mod->num_names       = *(uint32_t *)(exp + 24);
        mod->addr_table_offset    = *(uint32_t *)(exp + 28);
        mod->name_table_offset    = *(uint32_t *)(exp + 32);
        mod->ordinal_table_offset = *(uint32_t *)(exp + 36);
        
        fprintf(stderr, "[dbg] Export dir at %p\n", (void*)exp);
        fprintf(stderr, "[dbg] exp+14=%#x exp+18=%u exp+22=%u\n",
                *(uint32_t *)(exp + 14),
                *(uint32_t *)(exp + 18),
                *(uint32_t *)(exp + 22));
        printf("[pe] Exports: %u functions, %u named\n",
               mod->num_functions, mod->num_names);
    }

    free(file_data);
    free(sections);
    return mod;
}

void *pe_get_export(pe_module_t *mod, uint32_t index) {
    if (!mod || index >= mod->num_functions) return NULL;
    
    uint32_t *addr_table = (uint32_t *)((uint8_t *)mod->base + mod->addr_table_offset);
    uint32_t func_rva = addr_table[index];
    return (uint8_t *)mod->base + func_rva;
}

void *pe_get_export_by_name(pe_module_t *mod, const char *name) {
    if (!mod || !name) return NULL;
    
    uint32_t *name_table = (uint32_t *)((uint8_t *)mod->base + mod->name_table_offset);
    uint16_t *ord_table = (uint16_t *)((uint8_t *)mod->base + mod->ordinal_table_offset);
    uint32_t *addr_table = (uint32_t *)((uint8_t *)mod->base + mod->addr_table_offset);
    
    size_t name_len = strlen(name);
    
    for (uint32_t i = 0; i < mod->num_names; i++) {
        const char *export_name = (const char *)((uint8_t *)mod->base + name_table[i]);
        if (strlen(export_name) == name_len && memcmp(export_name, name, name_len) == 0) {
            uint16_t ordinal_index = ord_table[i]; /* already 0-based into addr table */
            uint32_t func_rva = addr_table[ordinal_index];
            return (uint8_t *)mod->base + func_rva;
        }
    }
    return NULL;
}

void pe_unload(pe_module_t *mod) {
    if (!mod) return;
    munmap(mod->base, mod->image_size);
    free(mod);
}

void *pe_get_base(pe_module_t *mod) {
    return mod ? mod->base : NULL;
}
