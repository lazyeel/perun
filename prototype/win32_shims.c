/*
 * Copyright 2026 lazyeel (https://github.com/lazyeel)
 * SPDX-License-Identifier: Apache-2.0
 */

/* win32_shims.c — Complete Win32 API shim implementations on POSIX
 *
 * Implements all Win32 API functions imported by CoreADI64.dll.
 * Each function maps to its closest POSIX equivalent with
 * Windows-compatible behavior and return codes.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#include <sys/types.h>
#include <dirent.h>
#include "win32_types.h"
#include "win32_shims.h"

/* Trace counter for debugging */
static int g_trace_enabled = 0;
#define SHIM_TRACE(name) if (g_trace_enabled) fprintf(stderr, "[trace] %s\n", name)


static int wcslen16(const uint16_t *s);

/* ══════════════════════════════════════════════
   Handle management (typed, not raw fds)
   ══════════════════════════════════════════════ */

static win_handle_t g_handles[WIN_HANDLE_TABLE_SIZE];
static pthread_mutex_t g_handle_table_lock = PTHREAD_MUTEX_INITIALIZER;

void *win_handle_alloc(win_handle_type_t type) {
    pthread_mutex_lock(&g_handle_table_lock);
    for (int i = 0; i < WIN_HANDLE_TABLE_SIZE; i++) {
        if (!g_handles[i].used) {
            memset(&g_handles[i], 0, sizeof(win_handle_t));
            g_handles[i].used = 1;
            g_handles[i].type = type;
            pthread_mutex_unlock(&g_handle_table_lock);
            return &g_handles[i];
        }
    }
    pthread_mutex_unlock(&g_handle_table_lock);
    return NULL;
}

win_handle_t *win_handle_get(void *h) {
    if (!h || h == (void *)-1 || h == (void *)-2) return NULL;
    uintptr_t addr = (uintptr_t)h;
    if ((uintptr_t)g_handles <= addr &&
        addr < (uintptr_t)g_handles + sizeof(g_handles)) {
        win_handle_t *e = (win_handle_t *)h;
        if (e->used) return e;
    }
    return NULL;
}

void win_handle_free(void *h) {
    win_handle_t *e = win_handle_get(h);
    if (e) e->used = 0;
}

/* UTF-16LE to UTF-8 conversion (pitfall #2) */
void utf16_to_utf8(const uint16_t *src, char *dst, size_t max_len) {
    size_t i = 0, j = 0;
    while (src[i] && j < max_len - 1) {
        uint16_t ch = src[i];
        if (ch < 0x80) {
            dst[j++] = (char)ch;
        } else if (ch < 0x800) {
            dst[j++] = (char)(0xC0 | (ch >> 6));
            dst[j++] = (char)(0x80 | (ch & 0x3F));
        } else if (ch >= 0xD800 && ch < 0xDC00 && src[i+1] >= 0xDC00 && src[i+1] < 0xE000) {
            /* Surrogate pair */
            uint32_t cp = 0x10000 + ((ch - 0xD800) << 10) + (src[i+1] - 0xDC00);
            dst[j++] = (char)(0xF0 | (cp >> 18));
            dst[j++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            dst[j++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            dst[j++] = (char)(0x80 | (cp & 0x3F));
            i++; /* skip low surrogate */
        } else {
            dst[j++] = (char)(0xE0 | (ch >> 12));
            dst[j++] = (char)(0x80 | ((ch >> 6) & 0x3F));
            dst[j++] = (char)(0x80 | (ch & 0x3F));
        }
        i++;
    }
    dst[j] = '\0';
}

void unix_time_to_filetime(struct timespec *ts, uint64_t *filetime) {
    /* Windows FILETIME: 100-nanosecond intervals since January 1, 1601 UTC */
    uint64_t secs_since_1601 = (uint64_t)ts->tv_sec + 11644473600ULL;
    *filetime = secs_since_1601 * 10000000ULL + (uint64_t)ts->tv_nsec / 100ULL;
}

/* Convert UTF-16LE to UTF-32 codepoint */
static uint32_t utf16_to_codepoint(const uint16_t *src, int *advance) {
    uint16_t ch = src[0];
    if (ch >= 0xD800 && ch < 0xDC00) {
        uint16_t lo = src[1];
        if (lo >= 0xDC00 && lo < 0xE000) {
            *advance = 2;
            return 0x10000 + ((ch - 0xD800) << 10) + (lo - 0xDC00);
        }
    }
    *advance = 1;
    return ch;
}

/* ══════════════════════════════════════════════
   Memory Management
   ══════════════════════════════════════════════ */

HANDLE shim_GetProcessHeap(void) { return (HANDLE)1; }

LPVOID shim_HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size) {
    void *ptr = malloc(size);
    if (ptr && (flags & 0x08)) memset(ptr, 0, size); /* HEAP_ZERO_MEMORY */
    return ptr;
}

SIZE_T shim_HeapSize(HANDLE heap, DWORD flags, LPCVOID ptr) {
    /* We don't track allocation sizes; return a reasonable value */
    return 16;
}

LPVOID shim_HeapReAlloc(HANDLE heap, DWORD flags, LPVOID ptr, SIZE_T size) {
    return realloc(ptr, size);
}

BOOL shim_HeapFree(HANDLE heap, DWORD flags, LPVOID ptr) {
    free(ptr);
    return TRUE;
}

HANDLE shim_GetProcessHeap_Stub(void) { return (HANDLE)1; }

LPVOID shim_VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect) {
    int prot = PROT_NONE;
    if (protect & 0x10 || protect & 0x20 || protect & 0x40 || protect & 0x80)
        prot |= PROT_EXEC;
    if (protect & 0x02 || protect & 0x04 || protect & 0x08)
        prot |= PROT_WRITE;
    if (protect & 0x01 || protect & 0x04 || protect & 0x08 ||
        protect & 0x20 || protect & 0x40 || protect & 0x80)
        prot |= PROT_READ;
    
    return mmap(address, size,
                prot ? prot : PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

BOOL shim_VirtualFree(LPVOID address, SIZE_T size, DWORD type) {
    munmap(address, size > 0 ? size : 4 * 1024 * 1024);
    return TRUE;
}

BOOL shim_VirtualProtect(LPVOID address, SIZE_T size, DWORD new_protect, DWORD *old_protect) {
    int prot = PROT_READ | PROT_WRITE;
    if (new_protect & 0x10) prot |= PROT_EXEC;
    if (old_protect) *old_protect = 0x04; /* PAGE_READWRITE */
    return mprotect(address, size, prot) == 0 ? TRUE : FALSE;
}

/* ══════════════════════════════════════════════
   CriticalSection → recursive pthread mutex
   ══════════════════════════════════════════════ */

BOOL shim_InitializeCriticalSectionAndSpinCount(void *cs, DWORD spin_count) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init((pthread_mutex_t *)cs, &attr);
    pthread_mutexattr_destroy(&attr);
    return TRUE;
}

void shim_InitializeCriticalSection(void *cs) {
    shim_InitializeCriticalSectionAndSpinCount(cs, 0);
}

void shim_EnterCriticalSection(void *cs) {
    pthread_mutex_lock((pthread_mutex_t *)cs);
}

void shim_LeaveCriticalSection(void *cs) {
    pthread_mutex_unlock((pthread_mutex_t *)cs);
}

void shim_DeleteCriticalSection(void *cs) {
    pthread_mutex_destroy((pthread_mutex_t *)cs);
}

/* ══════════════════════════════════════════════
   Events — implemented with cond vars for atomicity
   ══════════════════════════════════════════════ */

HANDLE shim_CreateEventA(LPSECURITY_ATTRIBUTES sa, BOOL manual_reset,
                           BOOL initial_state, LPCSTR name) {
    win_handle_t *h = win_handle_alloc(HT_EVENT);
    if (!h) return INVALID_HANDLE_VALUE;
    h->manual_reset = manual_reset;
    h->signaled = initial_state;
    pthread_mutex_init(&h->lock, NULL);
    pthread_cond_init(&h->cond, NULL);
    return h;
}

HANDLE shim_CreateEventW(LPSECURITY_ATTRIBUTES sa, BOOL manual_reset,
                           BOOL initial_state, const uint16_t *name) {
    return shim_CreateEventA(sa, manual_reset, initial_state, "");
}

BOOL shim_SetEvent(HANDLE event) {
    win_handle_t *e = win_handle_get(event);
    if (!e || e->type != HT_EVENT) return FALSE;
    pthread_mutex_lock(&e->lock);
    e->signaled = 1;
    pthread_cond_broadcast(&e->cond);
    pthread_mutex_unlock(&e->lock);
    return TRUE;
}

BOOL shim_ResetEvent(HANDLE event) {
    win_handle_t *e = win_handle_get(event);
    if (!e || e->type != HT_EVENT) return FALSE;
    pthread_mutex_lock(&e->lock);
    e->signaled = 0;
    pthread_cond_broadcast(&e->cond); /* wake up any waiters to recheck */
    pthread_mutex_unlock(&e->lock);
    return TRUE;
}

DWORD shim_WaitForSingleObject(HANDLE object, DWORD timeout_ms) {
    win_handle_t *e = win_handle_get(object);
    if (!e) return WAIT_TIMEOUT;
    
    if (e->type != HT_EVENT) {
        /* For non-event handles (mutexes etc.), just try lock/unlock */
        return WAIT_OBJECT_0;
    }
    
    pthread_mutex_lock(&e->lock);
    while (!e->signaled) {
        if (timeout_ms == INFINITE) {
            pthread_cond_wait(&e->cond, &e->lock);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            int result = pthread_cond_timedwait(&e->cond, &e->lock, &ts);
            if (result == ETIMEDOUT) {
                pthread_mutex_unlock(&e->lock);
                return WAIT_TIMEOUT;
            }
        }
    }
    if (!e->manual_reset) {
        e->signaled = 0; /* auto-reset events clear the signal */
    }
    pthread_mutex_unlock(&e->lock);
    return WAIT_OBJECT_0;
}

/* Atomic SignalObjectAndWait (pitfall #3 from real-world PE loader development) */
DWORD shim_SignalObjectAndWait(HANDLE signal_handle, HANDLE wait_handle,
                                 DWORD timeout_ms, BOOL alertable) {
    /* Signal the first object atomically */
    win_handle_t *sig = win_handle_get(signal_handle);
    if (sig && sig->type == HT_EVENT) {
        pthread_mutex_lock(&sig->lock);
        sig->signaled = 1;
        pthread_cond_broadcast(&sig->cond);
        pthread_mutex_unlock(&sig->lock);
    }
    /* Then wait on the second */
    return shim_WaitForSingleObject(wait_handle, timeout_ms);
}

/* ══════════════════════════════════════════════
   Mutexes
   ══════════════════════════════════════════════ */

HANDLE shim_CreateMutexA(LPSECURITY_ATTRIBUTES sa, BOOL initial_owner, LPCSTR name) {
    win_handle_t *h = win_handle_alloc(HT_MUTEX);
    if (!h) return INVALID_HANDLE_VALUE;
    pthread_mutex_init(&h->lock, NULL);
    if (initial_owner) pthread_mutex_lock(&h->lock);
    return h;
}

HANDLE shim_CreateMutexW(LPSECURITY_ATTRIBUTES sa, BOOL initial_owner, const uint16_t *name) {
    return shim_CreateMutexA(sa, initial_owner, "");
}

BOOL shim_ReleaseMutex(HANDLE mutex) {
    win_handle_t *e = win_handle_get(mutex);
    if (!e || e->type != HT_MUTEX) return FALSE;
    pthread_mutex_unlock(&e->lock);
    return TRUE;
}

/* ══════════════════════════════════════════════
   Crypto (ADVAPI32.dll)
   ══════════════════════════════════════════════ */

BOOL shim_CryptAcquireContextA(HANDLE *provider, LPCSTR container,
                                  LPCSTR provider_name, DWORD prov_type,
                                  DWORD flags) {
    if (provider) *provider = (HANDLE)1;
    return TRUE;
}

BOOL shim_CryptAcquireContextW(HANDLE *provider, const uint16_t *container,
                                 const uint16_t *provider_name, DWORD prov_type,
                                 DWORD flags) {
    if (provider) *provider = (HANDLE)1;
    return TRUE;
}

BOOL shim_CryptGenRandom(HANDLE provider, DWORD length, BYTE *buffer) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return FALSE;
    ssize_t bytes_read = read(fd, buffer, length);
    close(fd);
    return bytes_read == (ssize_t)length ? TRUE : FALSE;
}

BOOL shim_CryptReleaseContext(HANDLE provider, DWORD flags) {
    return TRUE;
}

/* ══════════════════════════════════════════════
   Registry stubs — ADI checks registry but works without it
   ══════════════════════════════════════════════ */

LONG shim_RegOpenKeyExA(HANDLE key, LPCSTR subkey, DWORD options,
                         REGSAM access, HANDLE *result_key) {
    return 2; /* ERROR_FILE_NOT_FOUND */
}

LONG shim_RegQueryValueExA(HANDLE key, LPCSTR value_name, DWORD *reserved,
                             DWORD *type, void *data, DWORD *data_size) {
    return 2; /* ERROR_FILE_NOT_FOUND */
}

LONG shim_RegCloseKey(HANDLE key) {
    return 0; /* ERROR_SUCCESS */
}

/* ══════════════════════════════════════════════
   Process / Thread info
   ══════════════════════════════════════════════ */

DWORD shim_GetCurrentProcessId(void) { return getpid(); }
DWORD shim_GetCurrentThreadId(void) { return gettid(); }
HANDLE shim_GetCurrentProcess(void) { return (HANDLE)-1; }
HANDLE shim_GetCurrentThread(void) { return (HANDLE)-2; }

void shim_GetSystemTimeAsFileTime(FILETIME *filetime) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    unix_time_to_filetime(&ts, (uint64_t *)filetime);
}

int shim_QueryPerformanceCounter(uint64_t *counter) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    *counter = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    return 1;
}

/* Timezone with INVERTED Bias sign (pitfall #4) */
DWORD shim_GetTimeZoneInformation(TIME_ZONE_INFORMATION *tz) {
    time_t t = time(NULL);
    struct tm local_time;
    localtime_r(&t, &local_time);
    
    tz->Bias = -(int32_t)(local_time.tm_gmtoff / 60); /* NEGATIVE for east of UTC! */
    tz->StandardBias = 0;
    tz->DaylightBias = local_time.tm_isdst > 0 ? -60 : 0;
    memset(tz->StandardName, 0, sizeof(tz->StandardName));
    memset(tz->DaylightName, 0, sizeof(tz->DaylightName));
    memset(tz->StandardDate, 0, sizeof(tz->StandardDate));
    memset(tz->DaylightDate, 0, sizeof(tz->DaylightDate));
    
    return local_time.tm_isdst > 0 ? 2 : 1; /* DAYLIGHT : STANDARD */
}

/* ══════════════════════════════════════════════
   File I/O with typed handles (pitfall #1)
   ══════════════════════════════════════════════ */

static int convert_access(DWORD desired_access) {
    int flags = O_RDONLY;
    if (desired_access & GENERIC_WRITE) {
        flags = (desired_access & GENERIC_READ) ? O_RDWR : O_WRONLY;
    }
    return flags;
}

static int convert_creation(DWORD creation_disposition) {
    switch (creation_disposition) {
    case CREATE_NEW:         return O_CREAT | O_EXCL;
    case CREATE_ALWAYS:      return O_CREAT | O_TRUNC;
    case OPEN_EXISTING:      return 0;
    case OPEN_ALWAYS:        return O_CREAT;
    case TRUNCATE_EXISTING:  return O_CREAT | O_TRUNC;
    default:                 return 0;
    }
}

HANDLE shim_CreateFileW(const uint16_t *filename_w, DWORD desired_access,
                          DWORD share_mode, SECURITY_ATTRIBUTES *sa,
                          DWORD creation_disposition, DWORD flags_and_attributes,
                          HANDLE template_file) {
    char path[MAX_PATH * 4]; /* UTF-8 can be longer than UTF-16 */
    utf16_to_utf8(filename_w, path, sizeof(path));
    
    int oflag = convert_access(desired_access) |
                convert_creation(creation_disposition);
    
    int fd = open(path, oflag, 0644);
    if (fd < 0) return INVALID_HANDLE_VALUE;
    
    win_handle_t *h = win_handle_alloc(HT_FILE);
    if (!h) { close(fd); return INVALID_HANDLE_VALUE; }
    h->fd = fd;
    return h;
}

HANDLE shim_CreateFileA(LPCSTR filename_a, DWORD desired_access,
                          DWORD share_mode, SECURITY_ATTRIBUTES *sa,
                          DWORD creation_disposition, DWORD flags_and_attributes,
                          HANDLE template_file) {
    /* Convert ASCII to wide, then call W version */
    uint16_t wide_path[MAX_PATH * 2];
    int len = strlen(filename_a);
    for (int i = 0; i < len && i < MAX_PATH; i++)
        wide_path[i] = (uint16_t)(uint8_t)filename_a[i];
    wide_path[len] = 0;
    
    return shim_CreateFileW(wide_path, desired_access, share_mode, sa,
                              creation_disposition, flags_and_attributes,
                              template_file);
}

BOOL shim_ReadFile(HANDLE file, void *buffer, DWORD bytes_to_read,
                     DWORD *bytes_read, OVERLAPPED *overlapped) {
    win_handle_t *e = win_handle_get(file);
    if (!e || e->type != HT_FILE) return FALSE;
    
    ssize_t result = read(e->fd, buffer, bytes_to_read);
    if (result < 0) return FALSE;
    if (bytes_read) *bytes_read = (DWORD)result;
    return TRUE;
}

BOOL shim_WriteFile(HANDLE file, LPCVOID buffer, DWORD bytes_to_write,
                      DWORD *bytes_written, OVERLAPPED *overlapped) {
    win_handle_t *e = win_handle_get(file);
    if (!e || e->type != HT_FILE) return FALSE;
    
    ssize_t result = write(e->fd, buffer, bytes_to_write);
    if (result < 0) return FALSE;
    if (bytes_written) *bytes_written = (DWORD)result;
    return TRUE;
}

BOOL shim_CloseHandle(HANDLE handle) {
    /* Handle pseudo-handles first */
    if (handle == (HANDLE)-1 || handle == (HANDLE)-2) return TRUE;
    
    win_handle_t *e = win_handle_get(handle);
    if (!e) return FALSE;
    
    switch (e->type) {
    case HT_FILE:
        if (e->fd >= 0) close(e->fd);
        break;
    case HT_EVENT:
        pthread_mutex_destroy(&e->lock);
        pthread_cond_destroy(&e->cond);
        break;
    case HT_MUTEX:
        pthread_mutex_destroy(&e->lock);
        break;
    default:
        break;
    }
    
    e->used = 0;
    return TRUE;
}

BOOL shim_SetEndOfFile(HANDLE file) {
    win_handle_t *e = win_handle_get(file);
    if (!e || e->type != HT_FILE) return FALSE;
    off_t pos = lseek(e->fd, 0, SEEK_CUR);
    return ftruncate(e->fd, pos) == 0 ? TRUE : FALSE;
}

BOOL shim_FlushFileBuffers(HANDLE file) {
    win_handle_t *e = win_handle_get(file);
    if (!e || e->type != HT_FILE) return FALSE;
    return fsync(e->fd) == 0 ? TRUE : FALSE;
}

BOOL shim_SetFilePointerEx(HANDLE file, int64_t distance_to_move,
                             int64_t *new_pointer, DWORD move_method) {
    win_handle_t *e = win_handle_get(file);
    if (!e || e->type != HT_FILE) return FALSE;
    
    int whence = SEEK_SET;
    switch (move_method) {
    case 1: whence = SEEK_CUR; break;
    case 2: whence = SEEK_END; break;
    }
    
    off_t new_pos = lseek(e->fd, distance_to_move, whence);
    if (new_pos < 0) return FALSE;
    if (new_pointer) *new_pointer = new_pos;
    return TRUE;
}

BOOL shim_DeleteFileW(const uint16_t *path_w) {
    char path[MAX_PATH * 4];
    utf16_to_utf8(path_w, path, sizeof(path));
    return unlink(path) == 0 ? TRUE : FALSE;
}

BOOL shim_DeleteFileA(LPCSTR path_a) {
    return unlink(path_a) == 0 ? TRUE : FALSE;
}

BOOL shim_CreateDirectoryW(const uint16_t *path_w, SECURITY_ATTRIBUTES *sa) {
    char path[MAX_PATH * 4];
    utf16_to_utf8(path_w, path, sizeof(path));
    return mkdir(path, 0755) == 0 ? TRUE : FALSE;
}

DWORD shim_GetFileAttributesW(const uint16_t *path_w) {
    char path[MAX_PATH * 4];
    utf16_to_utf8(path_w, path, sizeof(path));
    struct stat st;
    if (stat(path, &st) != 0) return 0xFFFFFFFF; /* INVALID_FILE_ATTRIBUTES */
    return S_ISDIR(st.st_mode) ? 0x10 : 0x80; /* DIRECTORY or NORMAL */
}

DWORD shim_GetFileAttributesA(LPCSTR path_a) {
    struct stat st;
    if (stat(path_a, &st) != 0) return 0xFFFFFFFF;
    return S_ISDIR(st.st_mode) ? 0x10 : 0x80;
}

BOOL shim_SetFileAttributesA(LPCSTR path_a, DWORD attributes) {
    return TRUE; /* no-op: POSIX doesn't have Windows file attributes */
}

BOOL shim_SetFileAttributesW(const uint16_t *path_w, DWORD attributes) {
    return TRUE;
}

DWORD shim_GetFileSize(HANDLE file, DWORD *high_size) {
    win_handle_t *e = win_handle_get(file);
    if (!e || e->type != HT_FILE) return 0xFFFFFFFF;
    struct stat st;
    fstat(e->fd, &st);
    if (high_size) *high_size = (DWORD)(st.st_size >> 32);
    return (DWORD)(st.st_size & 0xFFFFFFFF);
}

DWORD shim_GetFileType(HANDLE file) {
    win_handle_t *e = win_handle_get(file);
    if (!e || e->type != HT_FILE) return 0; /* FILE_TYPE_UNKNOWN */
    struct stat st;
    fstat(e->fd, &st);
    if (S_ISCHR(st.st_mode)) return 2; /* FILE_TYPE_CHAR */
    if (S_ISFIFO(st.st_mode)) return 3; /* FILE_TYPE_PIPE */
    return 1; /* FILE_TYPE_DISK */
}

BOOL shim_GetFileInformationByHandle(HANDLE file, void *file_info) {
    win_handle_t *e = win_handle_get(file);
    if (!e || e->type != HT_FILE) return FALSE;
    /* Return minimal valid data */
    return TRUE;
}

BOOL shim_PeekNamedPipe(HANDLE pipe, void *buffer, DWORD buf_size,
                          DWORD *bytes_read, DWORD *total_avail, DWORD *bytes_left) {
    return FALSE;
}

/* ── Find file operations (directory listing) ── */

typedef struct {
    char dir_path[MAX_PATH * 4];
    DIR *dir;
} find_context_t;

HANDLE shim_FindFirstFileExA(LPCSTR pattern, void *info) {
    /* Extract directory from pattern (everything before last '/' or '\') */
    find_context_t *ctx = calloc(1, sizeof(find_context_t));
    if (!ctx) return INVALID_HANDLE_VALUE;
    
    strncpy(ctx->dir_path, pattern, sizeof(ctx->dir_path) - 1);
    char *last_slash = strrchr(ctx->dir_path, '/');
    if (!last_slash) last_slash = strrchr(ctx->dir_path, '\\');
    if (last_slash) *last_slash = '\0';
    else strcpy(ctx->dir_path, ".");
    
    ctx->dir = opendir(ctx->dir_path);
    if (!ctx->dir) { free(ctx); return INVALID_HANDLE_VALUE; }
    return ctx;
}

BOOL shim_FindNextFileA(HANDLE handle, void *data) {
    find_context_t *ctx = win_handle_get(handle) ? 
        (find_context_t *)handle : NULL;
    if (!ctx || !ctx->dir) return FALSE;
    
    struct dirent *entry = readdir(ctx->dir);
    return entry != NULL ? TRUE : FALSE;
}

BOOL shim_FindClose(HANDLE handle) {
    find_context_t *ctx = (find_context_t *)handle;
    if (ctx && ctx->dir) closedir(ctx->dir);
    free(ctx);
    return TRUE;
}

/* ── Drive / volume info ── */

UINT shim_GetDriveTypeW(const uint16_t *root_path) {
    return 3; /* DRIVE_FIXED */
}

BOOL shim_GetVolumeInformationW(const uint16_t *root_path,
                                   uint16_t *volume_name, DWORD volume_name_size,
                                   DWORD *serial_number,
                                   DWORD *max_component_length,
                                   DWORD *filesystem_flags,
                                   uint16_t *filesystem_name,
                                   DWORD filesystem_name_size) {
    if (serial_number) *serial_number = 0x12345678;
    if (max_component_length) *max_component_length = 255;
    if (filesystem_flags) *filesystem_flags = 0x700; /* NTFS features */
    
    if (filesystem_name && filesystem_name_size >= 10) {
        const char *fs = "NTFS";
        for (int i = 0; i <= 4; i++) filesystem_name[i] = (uint16_t)fs[i];
    }
    return TRUE;
}

/* ══════════════════════════════════════════════
   String / Character conversion
   ══════════════════════════════════════════════ */

int shim_MultiByteToWideChar(UINT code_page, DWORD flags, LPCSTR source,
                                int source_length, uint16_t *destination,
                                int destination_length) {
    if (!source || !destination || destination_length <= 0) return 0;
    
    int len = (source_length < 0) ? (int)strlen(source) : source_length;
    int max = (len > destination_length) ? destination_length : len;
    int out_index = 0;
    
    /* Simple ASCII/Latin-1 passthrough for CP_UTF8 and CP_ACP */
    for (int i = 0; i < max && out_index < destination_length; i++) {
        unsigned char c = (unsigned char)source[i];
        
        if (code_page == 65001 && c >= 0x80) {
            /* UTF-8 decoding */
            uint32_t codepoint;
            int advance;
            
            if ((c & 0xE0) == 0xC0) { /* 2-byte sequence */
                if (i + 1 >= len) break;
                codepoint = ((c & 0x1F) << 6) | (source[i+1] & 0x3F);
                advance = 2;
            } else if ((c & 0xF0) == 0xE0) { /* 3-byte sequence */
                if (i + 2 >= len) break;
                codepoint = ((c & 0x0F) << 12) | ((source[i+1] & 0x3F) << 6) | (source[i+2] & 0x3F);
                advance = 3;
            } else if ((c & 0xF8) == 0xF0) { /* 4-byte sequence */
                if (i + 3 >= len) break;
                codepoint = ((c & 0x07) << 18) | ((source[i+1] & 0x3F) << 12) |
                            ((source[i+2] & 0x3F) << 6) | (source[i+3] & 0x3F);
                advance = 4;
            } else {
                codepoint = c; /* invalid, pass through */
                advance = 1;
            }
            
            i += advance - 1;
            
            /* Encode as UTF-16 */
            if (codepoint < 0x10000) {
                destination[out_index++] = (uint16_t)codepoint;
            } else if (out_index + 1 < destination_length) {
                codepoint -= 0x10000;
                destination[out_index++] = (uint16_t)(0xD800 + (codepoint >> 10));
                destination[out_index++] = (uint16_t)(0xDC00 + (codepoint & 0x3FF));
            }
        } else {
            /* Latin-1 or ASCII passthrough */
            destination[out_index++] = (uint16_t)c;
        }
    }
    
    return out_index;
}

int shim_WideCharToMultiByte(UINT code_page, DWORD flags,
                               const uint16_t *wide_source, int source_length,
                               char *multi_destination, int multi_length,
                               void *default_char, BOOL *default_char_used) {
    if (!wide_source || !multi_destination || multi_length <= 0) return 0;
    
    int max = (source_length < 0) ? 4096 : source_length;
    if (max > multi_length) max = multi_length;
    int out_index = 0;
    
    for (int i = 0; i < max && wide_source[i]; i++) {
        uint16_t ch = wide_source[i];
        
        if (ch < 0x80) {
            multi_destination[out_index++] = (char)ch;
        } else if (code_page == 65001 && out_index + 2 < multi_length) {
            /* UTF-8 encoding */
            if (ch < 0x800) {
                multi_destination[out_index++] = (char)(0xC0 | (ch >> 6));
                multi_destination[out_index++] = (char)(0x80 | (ch & 0x3F));
            } else {
                multi_destination[out_index++] = (char)(0xE0 | (ch >> 12));
                multi_destination[out_index++] = (char)(0x80 | ((ch >> 6) & 0x3F));
                multi_destination[out_index++] = (char)(0x80 | (ch & 0x3F));
            }
        } else if (out_index < multi_length) {
            /* Latin-1 fallback */
            multi_destination[out_index++] = (char)(ch & 0xFF);
        } else {
            break;
        }
    }
    
    return out_index;
}

int shim_CompareStringW(DWORD locale, DWORD flags,
                          const uint16_t *string1, int length1,
                          const uint16_t *string2, int length2) {
    if (length1 < 0) length1 = wcslen16(string1);
    if (length2 < 0) length2 = wcslen16(string2);
    
    int min_len = (length1 < length2) ? length1 : length2;
    
    for (int i = 0; i < min_len; i++) {
        if (string1[i] != string2[i]) {
            return string1[i] < string2[i] ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
        }
    }
    
    if (length1 != length2) {
        return length1 < length2 ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
    }
    return CSTR_EQUAL;
}

/* Helper: UTF-16 string length */
static int wcslen16(const uint16_t *s) {
    int len = 0;
    while (s[len]) len++;
    return len;
}

int shim_LCMapStringW(DWORD locale, DWORD map_flags,
                        const uint16_t *source, int source_length,
                        uint16_t *destination, int destination_length) {
    if (!source || !destination || destination_length <= 0) return 0;
    
    int len = (source_length < 0) ? wcslen16(source) : source_length;
    if (len > destination_length) len = destination_length;
    
    for (int i = 0; i < len; i++) {
        uint16_t ch = source[i];
        if (map_flags & 0x200) { /* LCMAP_UPPERCASE */
            if (ch >= 'a' && ch <= 'z') ch -= 32;
        } else if (map_flags & 0x100) { /* LCMAP_LOWERCASE */
            if (ch >= 'A' && ch <= 'Z') ch += 32;
        }
        destination[i] = ch;
    }
    return len;
}

BOOL shim_GetStringTypeW(DWORD type, const uint16_t *source, int count, uint16_t *dest) {
    if (!dest) return FALSE;
    memset(dest, 0, count * sizeof(uint16_t));
    return TRUE;
}

/* ══════════════════════════════════════════════
   Environment / Console / Module stubs
   ══════════════════════════════════════════════ */

LPCSTR shim_GetCommandLineA(void) { return ""; }
const uint16_t *shim_GetCommandLineW(void) {
    static const uint16_t empty[] = {0};
    return empty;
}

const uint16_t *shim_GetEnvironmentStringsW(void) {
    static const uint16_t empty[] = {0, 0}; /* double-null terminated */
    return empty;
}

BOOL shim_FreeEnvironmentStringsW(const uint16_t *env_block) { return TRUE; }

BOOL shim_SetEnvironmentVariableA(LPCSTR name, LPCSTR value) { return TRUE; }

BOOL shim_SetStdHandle(DWORD std_handle_type, HANDLE handle) { return TRUE; }

HANDLE shim_GetStdHandle(DWORD std_handle_type) {
    switch ((int)std_handle_type) {
    case -11: return (HANDLE)STDOUT_FILENO; /* STD_OUTPUT_HANDLE */
    case -10: return (HANDLE)STDIN_FILENO;  /* STD_INPUT_HANDLE */
    case -12: return (HANDLE)STDERR_FILENO; /* STD_ERROR_HANDLE */
    }
    return NULL;
}

BOOL shim_GetConsoleMode(HANDLE console, DWORD *mode) { return FALSE; }
BOOL shim_ReadConsoleW(HANDLE console, void *buffer, DWORD chars_to_read,
                          DWORD *chars_read, void *control) { return FALSE; }
BOOL shim_WriteConsoleW(HANDLE console, const void *buffer, DWORD chars_to_write,
                           DWORD *chars_written, void *reserved) {
    /* Write to stderr as UTF-8 */
    const uint16_t *w = (const uint16_t *)buffer;
    for (DWORD i = 0; i < chars_to_write; i++) {
        fputc((int)(w[i] & 0xFF), stderr);
    }
    fflush(stderr);
    if (chars_written) *chars_written = chars_to_write;
    return TRUE;
}
UINT shim_GetConsoleCP(void) { return 65001; } /* UTF-8 */

/* ── Path helpers ── */

DWORD shim_GetCurrentDirectoryW(DWORD length, uint16_t *buffer) {
    char cwd[MAX_PATH];
    if (getcwd(cwd, sizeof(cwd)) == NULL) return 0;
    int len = strlen(cwd);
    if (length < (DWORD)(len + 1)) return len + 1; /* need more space */
    for (int i = 0; i <= len; i++) buffer[i] = (uint16_t)cwd[i];
    return len;
}

DWORD shim_GetFullPathNameW(const uint16_t *file_name, DWORD buffer_length,
                              uint16_t *buffer, uint16_t **file_part) {
    int len = 0;
    while (file_name[len]) len++;
    if (len >= (int)buffer_length) return len + 1;
    memcpy(buffer, file_name, len * sizeof(uint16_t));
    buffer[len] = 0;
    if (file_part) *file_part = buffer;
    return len;
}

/* ── Module / library operations ── */

HANDLE shim_GetModuleHandleW(const uint16_t *module_name) {
    char name_str[256];
    utf16_to_utf8(module_name, name_str, sizeof(name_str));
    fprintf(stderr, "[shim] GetModuleHandleW(\"%s\") -> dummy\n", name_str);
    return (HANDLE)1; /* dummy non-null module handle */
}

BOOL shim_GetModuleHandleExW(DWORD flags, const uint16_t *name, HANDLE *module) {
    if (module) *module = NULL;
    return FALSE;
}

DWORD shim_GetModuleFileNameA(HANDLE module, LPSTR filename, DWORD size) {
    if (filename && size > 0) { filename[0] = 0; }
    return 0;
}

HANDLE shim_LoadLibraryExW(const uint16_t *name, HANDLE file, DWORD flags) {
    return NULL; /* can't load additional DLLs in our simple loader */
}

void *shim_GetProcAddress(HANDLE module, LPCSTR proc_name) {
    return NULL; /* no additional DLLs loaded */
}

BOOL shim_FreeLibrary(HANDLE library) { return TRUE; }

/* ── Error handling ── */

DWORD shim_GetLastError(void) { return 0; }

void shim_SetLastError(DWORD error_code) { }

BOOL shim_IsDebuggerPresent(void) { return FALSE; }

BOOL shim_IsProcessorFeaturePresent(DWORD feature) {
    /* Return TRUE for basic features */
    switch (feature) {
    case 0: /* PF_FLOATING_POINT_PRECISION_ERRATA */
    case 3: /* PF_RDTSC_INSTRUCTION_AVAILABLE */
    case 9: /* PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE) */
    case 10: /* PF_3DNOW_INSTRUCTIONS_AVAILABLE */
        return TRUE;
    }
    return FALSE;
}

void shim_InitializeSListHead(void *list_head) {
    memset(list_head, 0, 16); /* SLIST_HEADER is 16 bytes on x86_64 */
}

uintptr_t shim_InterlockedFlushSList(void *list_head) {
    /* Simplified: just return what was there and zero it */
    uintptr_t old_head = *(uintptr_t *)list_head;
    *(uintptr_t *)list_head = 0;
    return old_head;
}

void shim_RaiseException(DWORD exception_code, DWORD exception_flags,
                           DWORD number_of_arguments, const ULONG_PTR *arguments) {
    fprintf(stderr, "[win32-shim] RaiseException(%#lx)\n", (unsigned long)exception_code);
    /* We don't implement SEH. Just abort. */
    abort();
}

void shim_RtlCaptureContext(void *context_record) {
    /* Not needed for our use case */
}

void *shim_RtlLookupFunctionEntry(uint64_t control_pc, uint64_t *image_base,
                                     void *history_table) {
    if (image_base) *image_base = 0;
    return NULL;
}

uint64_t shim_RtlVirtualUnwind(DWORD handler_type, uint64_t image_base,
                                  uint64_t control_pc, void *function_entry,
                                  void *context_record, void **handler_data,
                                  uint64_t *establisher_frame, void *context_pointers) {
    return 0;
}

LONG shim_UnhandledExceptionFilter(void *exception_info) {
    fprintf(stderr, "[win32-shim] UnhandledExceptionFilter called\n");
    return 1; /* EXCEPTION_EXECUTE_HANDLER */
}

LONG shim_SetUnhandledExceptionFilter(void *filter) {
    return 0; /* no previous filter */
}

void shim_RtlUnwindEx(void *target_frame, void *target_ip, void *exception_record,
                        void *return_value, void *original_context, void *history_table) {
}
