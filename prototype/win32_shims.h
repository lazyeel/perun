/*
 * Copyright 2026 lazyeel (https://github.com/lazyeel)
 * SPDX-License-Identifier: Apache-2.0
 */

/* win32_shims.h — Shim function declarations and handle management */
#ifndef WIN32_SHIMS_H
#define WIN32_SHIMS_H

#include "win32_types.h"

/* ── Handle system ──
 * Win32 HANDLEs are polymorphic: the same CloseHandle() can receive
 * a file descriptor, an event, a mutex, or a pseudo-handle.
 * We maintain our own typed handle table to avoid confusion.
 */
typedef enum {
    HT_NONE = 0,
    HT_FILE,
    HT_EVENT,
    HT_MUTEX,
    HT_PROCESS,   /* GetCurrentProcess() returns -1 */
    HT_THREAD,    /* GetCurrentThread() returns -2 */
} win_handle_type_t;

typedef struct {
    int used;
    win_handle_type_t type;
    union {
        int fd;  /* for files */
        struct { /* for events and mutexes */
            pthread_mutex_t lock;
            pthread_cond_t cond;
            int manual_reset;
            int signaled;
        };
    };
} win_handle_t;

#define WIN_HANDLE_TABLE_SIZE 512

/* Allocate a new handle slot of given type */
void *win_handle_alloc(win_handle_type_t type);

/* Get and validate a handle (returns NULL if invalid) */
win_handle_t *win_handle_get(void *h);

/* Free a handle slot */
void win_handle_free(void *h);

/* UTF-16LE to UTF-8 converter */
void utf16_to_utf8(const uint16_t *src, char *dst, size_t max_len);

/* FILETIME helpers */
void unix_time_to_filetime(struct timespec *ts, uint64_t *filetime);

#endif /* WIN32_SHIMS_H */
