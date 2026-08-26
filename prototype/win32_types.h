/*
 * Copyright 2026 lazyeel (https://github.com/lazyeel)
 * SPDX-License-Identifier: Apache-2.0
 */

/* win32_types.h — Windows type definitions for the shim layer */
#ifndef WIN32_TYPES_H
#define WIN32_TYPES_H

#include <stdint.h>
#include <stddef.h>
typedef size_t SIZE_T;
typedef uint64_t REGSAM;
typedef uint32_t UINT;
#include <pthread.h>

typedef void *HANDLE;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint64_t ULONG_PTR;
typedef uintptr_t UINT_PTR;
typedef int BOOL;
typedef unsigned char BYTE;
typedef char CHAR;
typedef uint16_t WCHAR;
typedef const char *LPCSTR;
typedef const WCHAR *LPCWSTR;
typedef char *LPSTR;
typedef WCHAR *LPWSTR;
typedef void *LPVOID;
typedef const void *LPCVOID;

#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define INFINITE 0xFFFFFFFF
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 0x102
#define MAX_PATH 260
#define GENERIC_READ  0x80000000L
#define GENERIC_WRITE 0x40000000L
#define CREATE_NEW 1
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define OPEN_ALWAYS 4
#define TRUNCATE_EXISTING 5
#define FILE_ATTRIBUTE_NORMAL 0x80
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3
#define DLL_PROCESS_DETACH 0
#define TLS_OUT_OF_INDEXES 0xFFFFFFFF
#define CSTR_LESS_THAN 1
#define CSTR_EQUAL 2
#define CSTR_GREATER_THAN 3

/* TIME_ZONE_INFORMATION */
typedef struct {
    LONG Bias;
    uint16_t StandardName[32];
    uint16_t StandardDate[8];
    LONG StandardBias;
    uint16_t DaylightName[32];
    uint16_t DaylightDate[8];
    LONG DaylightBias;
} TIME_ZONE_INFORMATION, *LPTIME_ZONE_INFORMATION;

/* SYSTEMTIME */
typedef struct {
    uint16_t wYear, wMonth, wDayOfWeek, wDay;
    uint16_t wHour, wMinute, wSecond, wMilliseconds;
} SYSTEMTIME, *LPSYSTEMTIME;

/* FILETIME */
typedef struct {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *LPFILETIME;

/* WIN32_FILE_ATTRIBUTE_DATA */
typedef struct {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA;

/* OVERLAPPED (minimal) */
typedef struct {
    uintptr_t Internal;
    uintptr_t InternalHigh;
    union { struct { DWORD Offset; DWORD OffsetHigh; }; void *Pointer; };
    HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

/* SECURITY_ATTRIBUTES */
typedef struct {
    DWORD nLength;
    void *lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

#endif /* WIN32_TYPES_H */
