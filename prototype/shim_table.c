/*
 * Copyright 2026 lazyeel (https://github.com/lazyeel)
 * SPDX-License-Identifier: Apache-2.0
 */

/* shim_table.c — Maps Win32 function names to our POSIX implementations.
 * Used by pe_loader.c to resolve IAT entries during DLL loading.
 */
#include <string.h>
#include "win32_shims.h"

typedef struct {
    const char *name;
    void *func;
} shim_entry_t;

/* All implementations are in win32_shims.c */
extern HANDLE shim_GetProcessHeap(void);
extern LPVOID shim_HeapAlloc(HANDLE,DWORD,SIZE_T);
extern SIZE_T shim_HeapSize(HANDLE,DWORD,LPCVOID);
extern LPVOID shim_HeapReAlloc(HANDLE,DWORD,LPVOID,SIZE_T);
extern BOOL shim_HeapFree(HANDLE,DWORD,LPVOID);
extern LPVOID shim_VirtualAlloc(LPVOID,SIZE_T,DWORD,DWORD);
extern BOOL shim_VirtualFree(LPVOID,SIZE_T,DWORD);
extern BOOL shim_VirtualProtect(LPVOID,SIZE_T,DWORD,DWORD*);
extern BOOL shim_InitializeCriticalSectionAndSpinCount(void*,DWORD);
extern void shim_InitializeCriticalSection(void*);
extern void shim_EnterCriticalSection(void*);
extern void shim_LeaveCriticalSection(void*);
extern void shim_DeleteCriticalSection(void*);
extern HANDLE shim_CreateEventA(LPSECURITY_ATTRIBUTES,BOOL,BOOL,LPCSTR);
extern HANDLE shim_CreateEventW(LPSECURITY_ATTRIBUTES,BOOL,BOOL,const uint16_t*);
extern BOOL shim_SetEvent(HANDLE);
extern BOOL shim_ResetEvent(HANDLE);
extern DWORD shim_WaitForSingleObject(HANDLE,DWORD);
extern DWORD shim_SignalObjectAndWait(HANDLE,HANDLE,DWORD,BOOL);
extern HANDLE shim_CreateMutexA(LPSECURITY_ATTRIBUTES,BOOL,LPCSTR);
extern HANDLE shim_CreateMutexW(LPSECURITY_ATTRIBUTES,BOOL,const uint16_t*);
extern BOOL shim_ReleaseMutex(HANDLE);
extern BOOL shim_CryptAcquireContextA(HANDLE*,LPCSTR,LPCSTR,DWORD,DWORD);
extern BOOL shim_CryptAcquireContextW(HANDLE*,const uint16_t*,const uint16_t*,DWORD,DWORD);
extern BOOL shim_CryptGenRandom(HANDLE,DWORD,BYTE*);
extern BOOL shim_CryptReleaseContext(HANDLE,DWORD);
extern LONG shim_RegOpenKeyExA(HANDLE,LPCSTR,DWORD,uint64_t,HANDLE*);
extern LONG shim_RegQueryValueExA(HANDLE,LPCSTR,DWORD*,DWORD*,void*,DWORD*);
extern LONG shim_RegCloseKey(HANDLE);
extern DWORD shim_GetCurrentProcessId(void);
extern DWORD shim_GetCurrentThreadId(void);
extern HANDLE shim_GetCurrentProcess(void);
extern HANDLE shim_GetCurrentThread(void);
extern void shim_GetSystemTimeAsFileTime(FILETIME*);
extern int shim_QueryPerformanceCounter(uint64_t*);
extern DWORD shim_GetTimeZoneInformation(TIME_ZONE_INFORMATION*);
extern HANDLE shim_CreateFileW(const uint16_t*,DWORD,DWORD,SECURITY_ATTRIBUTES*,DWORD,DWORD,HANDLE);
extern HANDLE shim_CreateFileA(LPCSTR,DWORD,DWORD,SECURITY_ATTRIBUTES*,DWORD,DWORD,HANDLE);
extern BOOL shim_ReadFile(HANDLE,void*,DWORD,DWORD*,OVERLAPPED*);
extern BOOL shim_WriteFile(HANDLE,LPCVOID,DWORD,DWORD*,OVERLAPPED*);
extern BOOL shim_CloseHandle(HANDLE);
extern BOOL shim_SetEndOfFile(HANDLE);
extern BOOL shim_FlushFileBuffers(HANDLE);
extern BOOL shim_SetFilePointerEx(HANDLE,int64_t,int64_t*,DWORD);
extern BOOL shim_DeleteFileW(const uint16_t*);
extern BOOL shim_DeleteFileA(LPCSTR);
extern BOOL shim_CreateDirectoryW(const uint16_t*,SECURITY_ATTRIBUTES*);
extern DWORD shim_GetFileAttributesW(const uint16_t*);
extern DWORD shim_GetFileAttributesA(LPCSTR);
extern BOOL shim_SetFileAttributesA(LPCSTR,DWORD);
extern BOOL shim_SetFileAttributesW(const uint16_t*,DWORD);
extern DWORD shim_GetFileSize(HANDLE,DWORD*);
extern DWORD shim_GetFileType(HANDLE);
extern BOOL shim_GetFileInformationByHandle(HANDLE,void*);
extern BOOL shim_PeekNamedPipe(HANDLE,void*,DWORD,DWORD*,DWORD*,DWORD*);
extern HANDLE shim_FindFirstFileExA(LPCSTR,void*);
extern BOOL shim_FindNextFileA(HANDLE,void*);
extern BOOL shim_FindClose(HANDLE);
extern UINT shim_GetDriveTypeW(const uint16_t*);
extern BOOL shim_GetVolumeInformationW(const uint16_t*,uint16_t*,DWORD,DWORD*,DWORD*,DWORD*,uint16_t*,DWORD);
extern int shim_MultiByteToWideChar(UINT,DWORD,LPCSTR,int,uint16_t*,int);
extern int shim_WideCharToMultiByte(UINT,DWORD,const uint16_t*,int,char*,int,void*,BOOL*);
extern int shim_CompareStringW(DWORD,DWORD,const uint16_t*,int,const uint16_t*,int);
extern int shim_LCMapStringW(DWORD,DWORD,const uint16_t*,int,uint16_t*,int);
extern BOOL shim_GetStringTypeW(DWORD,const uint16_t*,int,uint16_t*);
extern LPCSTR shim_GetCommandLineA(void);
extern const uint16_t*shim_GetCommandLineW(void);
extern const uint16_t*shim_GetEnvironmentStringsW(void);
extern BOOL shim_FreeEnvironmentStringsW(const uint16_t*);
extern BOOL shim_SetEnvironmentVariableA(LPCSTR,LPCSTR);
extern BOOL shim_SetStdHandle(DWORD,HANDLE);
extern HANDLE shim_GetStdHandle(DWORD);
extern BOOL shim_GetConsoleMode(HANDLE,DWORD*);
extern BOOL shim_ReadConsoleW(HANDLE,void*,DWORD,DWORD*,void*);
extern BOOL shim_WriteConsoleW(HANDLE,const void*,DWORD,DWORD*,void*);
extern UINT shim_GetConsoleCP(void);
extern DWORD shim_GetCurrentDirectoryW(DWORD,uint16_t*);
extern DWORD shim_GetFullPathNameW(const uint16_t*,DWORD,uint16_t*,uint16_t**);
extern HANDLE shim_GetModuleHandleW(const uint16_t*);
extern BOOL shim_GetModuleHandleExW(DWORD,const uint16_t*,HANDLE*);
extern DWORD shim_GetModuleFileNameA(HANDLE,char*,DWORD);
extern HANDLE shim_LoadLibraryExW(const uint16_t*,HANDLE,DWORD);
extern void*shim_GetProcAddress(HANDLE,LPCSTR);
extern BOOL shim_FreeLibrary(HANDLE);
extern DWORD shim_GetLastError(void);
extern void shim_SetLastError(DWORD);
extern BOOL shim_IsDebuggerPresent(void);
extern BOOL shim_IsProcessorFeaturePresent(DWORD);
extern void shim_InitializeSListHead(void*);
extern uintptr_t shim_InterlockedFlushSList(void*);
extern void shim_RaiseException(DWORD,DWORD,DWORD,const ULONG_PTR*);
extern void shim_RtlCaptureContext(void*);
extern void*shim_RtlLookupFunctionEntry(uint64_t,uint64_t*,void*);
extern uint64_t shim_RtlVirtualUnwind(DWORD,uint64_t,uint64_t,void*,void*,void**,uint64_t*,void*);
extern LONG shim_UnhandledExceptionFilter(void*);
extern LONG shim_SetUnhandledExceptionFilter(void*);
extern void shim_RtlUnwindEx(void*,void*,void*,void*,void*,void*);

static shim_entry_t g_shim_table[] = {
    /* KERNEL32.dll — Memory */
    {"GetProcessHeap",                      shim_GetProcessHeap},
    {"HeapAlloc",                           shim_HeapAlloc},
    {"HeapSize",                            shim_HeapSize},
    {"HeapReAlloc",                         shim_HeapReAlloc},
    {"HeapFree",                            shim_HeapFree},
    {"VirtualAlloc",                        shim_VirtualAlloc},
    {"VirtualFree",                         shim_VirtualFree},
    {"VirtualProtect",                      shim_VirtualProtect},
    
    /* KERNEL32.dll — Synchronization */
    {"InitializeCriticalSection",            shim_InitializeCriticalSection},
    {"InitializeCriticalSectionAndSpinCount",shim_InitializeCriticalSectionAndSpinCount},
    {"EnterCriticalSection",                 shim_EnterCriticalSection},
    {"LeaveCriticalSection",                 shim_LeaveCriticalSection},
    {"DeleteCriticalSection",                shim_DeleteCriticalSection},
    {"CreateEventA",                         shim_CreateEventA},
    {"CreateEventW",                         shim_CreateEventW},
    {"SetEvent",                             shim_SetEvent},
    {"ResetEvent",                           shim_ResetEvent},
    {"WaitForSingleObject",                  shim_WaitForSingleObject},
    {"SignalObjectAndWait",                  shim_SignalObjectAndWait},
    {"CreateMutexA",                         shim_CreateMutexA},
    {"CreateMutexW",                         shim_CreateMutexW},
    {"ReleaseMutex",                         shim_ReleaseMutex},
    
    /* ADVAPI32.dll — Crypto */
    {"CryptAcquireContextA",                 shim_CryptAcquireContextA},
    {"CryptAcquireContextW",                 shim_CryptAcquireContextW},
    {"CryptGenRandom",                       shim_CryptGenRandom},
    {"CryptReleaseContext",                  shim_CryptReleaseContext},
    
    /* ADVAPI32.dll — Registry (stubs) */
    {"RegOpenKeyExA",                        shim_RegOpenKeyExA},
    {"RegQueryValueExA",                     shim_RegQueryValueExA},
    {"RegCloseKey",                          shim_RegCloseKey},
    
    /* KERNEL32.dll — Process/Thread info */
    {"GetCurrentProcessId",                  shim_GetCurrentProcessId},
    {"GetCurrentThreadId",                   shim_GetCurrentThreadId},
    {"GetCurrentProcess",                    shim_GetCurrentProcess},
    {"GetCurrentThread",                     shim_GetCurrentThread},
    {"GetSystemTimeAsFileTime",              shim_GetSystemTimeAsFileTime},
    {"QueryPerformanceCounter",               shim_QueryPerformanceCounter},
    {"GetTimeZoneInformation",                shim_GetTimeZoneInformation},
    
    /* KERNEL32.dll — File I/O */
    {"CreateFileW",                          shim_CreateFileW},
    {"CreateFileA",                          shim_CreateFileA},
    {"ReadFile",                             shim_ReadFile},
    {"WriteFile",                            shim_WriteFile},
    {"CloseHandle",                          shim_CloseHandle},
    {"SetEndOfFile",                          shim_SetEndOfFile},
    {"FlushFileBuffers",                      shim_FlushFileBuffers},
    {"SetFilePointerEx",                      shim_SetFilePointerEx},
    {"DeleteFileW",                           shim_DeleteFileW},
    {"DeleteFileA",                           shim_DeleteFileA},
    {"CreateDirectoryW",                      shim_CreateDirectoryW},
    {"GetFileAttributesW",                    shim_GetFileAttributesW},
    {"GetFileAttributesA",                    shim_GetFileAttributesA},
    {"SetFileAttributesA",                    shim_SetFileAttributesA},
    {"SetFileAttributesW",                    shim_SetFileAttributesW},
    {"GetFileSize",                           shim_GetFileSize},
    {"GetFileType",                           shim_GetFileType},
    {"GetFileInformationByHandle",             shim_GetFileInformationByHandle},
    {"PeekNamedPipe",                         shim_PeekNamedPipe},
    {"FindFirstFileExA",                      shim_FindFirstFileExA},
    {"FindNextFileA",                         shim_FindNextFileA},
    {"FindClose",                             shim_FindClose},
    {"GetDriveTypeW",                         shim_GetDriveTypeW},
    {"GetVolumeInformationW",                  shim_GetVolumeInformationW},
    
    /* KERNEL32.dll — String conversion */
    {"MultiByteToWideChar",                    shim_MultiByteToWideChar},
    {"WideCharToMultiByte",                    shim_WideCharToMultiByte},
    {"CompareStringW",                         shim_CompareStringW},
    {"LCMapStringW",                           shim_LCMapStringW},
    {"GetStringTypeW",                         shim_GetStringTypeW},
    
    /* KERNEL32.dll — Environment/Console */
    {"GetCommandLineA",                        shim_GetCommandLineA},
    {"GetCommandLineW",                        shim_GetCommandLineW},
    {"GetEnvironmentStringsW",                 shim_GetEnvironmentStringsW},
    {"FreeEnvironmentStringsW",                 shim_FreeEnvironmentStringsW},
    {"SetEnvironmentVariableA",                 shim_SetEnvironmentVariableA},
    {"SetStdHandle",                            shim_SetStdHandle},
    {"GetStdHandle",                            shim_GetStdHandle},
    {"GetConsoleMode",                          shim_GetConsoleMode},
    {"ReadConsoleW",                            shim_ReadConsoleW},
    {"WriteConsoleW",                           shim_WriteConsoleW},
    {"GetConsoleCP",                            shim_GetConsoleCP},
    {"GetCurrentDirectoryW",                     shim_GetCurrentDirectoryW},
    {"GetFullPathNameW",                        shim_GetFullPathNameW},
    
    /* KERNEL32.dll — Module operations */
    {"GetModuleHandleW",                        shim_GetModuleHandleW},
    {"GetModuleHandleExW",                      shim_GetModuleHandleExW},
    {"GetModuleFileNameA",                       shim_GetModuleFileNameA},
    {"LoadLibraryExW",                           shim_LoadLibraryExW},
    {"GetProcAddress",                           shim_GetProcAddress},
    {"FreeLibrary",                              shim_FreeLibrary},
    
    /* KERNEL32.dll — Error handling */
    {"GetLastError",                             shim_GetLastError},
    {"SetLastError",                             shim_SetLastError},
    {"IsDebuggerPresent",                        shim_IsDebuggerPresent},
    {"IsProcessorFeaturePresent",                 shim_IsProcessorFeaturePresent},
    
    /* KERNEL32.dll — Exception handling */
    {"InitializeSListHead",                       shim_InitializeSListHead},
    {"InterlockedFlushSList",                     shim_InterlockedFlushSList},
    {"RaiseException",                            shim_RaiseException},
    {"RtlCaptureContext",                         shim_RtlCaptureContext},
    {"RtlLookupFunctionEntry",                     shim_RtlLookupFunctionEntry},
    {"RtlVirtualUnwind",                          shim_RtlVirtualUnwind},
    {"UnhandledExceptionFilter",                   shim_UnhandledExceptionFilter},
    {"SetUnhandledExceptionFilter",                 shim_SetUnhandledExceptionFilter},
    {"RtlUnwindEx",                                shim_RtlUnwindEx},
    
    /* ADVAPI32.dll — User info stub */
    {"GetUserNameA",                               NULL}, /* stub: returns FALSE */
    
    /* SHLWAPI.dll — Path helpers (stub) */
    {"PathAppendW",                                 NULL},
    {"PathIsDirectoryW",                            NULL},
    
    /* SHELL32.dll — Shell folders (stub) */
    {"SHGetFolderPathW",                            NULL},
};

#define SHIM_TABLE_SIZE (sizeof(g_shim_table) / sizeof(g_shim_table[0]))

void *pe_shim_lookup(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < SHIM_TABLE_SIZE; i++) {
        if (strcmp(g_shim_table[i].name, name) == 0)
            return g_shim_table[i].func;
    }
    return NULL; /* caller will use generic_stub */
}
