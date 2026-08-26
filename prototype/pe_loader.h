/*
 * Copyright 2026 lazyeel (https://github.com/lazyeel)
 * SPDX-License-Identifier: Apache-2.0
 */

/* pe_loader.h — PE loader API */
#ifndef PE_LOADER_H
#define PE_LOADER_H

#include <stdint.h>

typedef struct pe_module pe_module_t;

pe_module_t *pe_load(const char *path);
void *pe_get_export(pe_module_t *mod, uint32_t index);
void *pe_get_export_by_name(pe_module_t *mod, const char *name);
void *pe_get_base(pe_module_t *mod);
void pe_unload(pe_module_t *mod);

#endif /* PE_LOADER_H */
