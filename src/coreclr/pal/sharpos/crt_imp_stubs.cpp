// crt_imp_stubs.cpp — both direct + __imp_<name> overrides for
// api-ms-win-crt-*.dll imports. Phase 6.1.b empirical enumerator.
//
// NativeAOT pulls /DEFAULTLIB:ucrt.lib which adds 124 imports from
// api-ms-win-crt-{string,stdio,runtime,heap,math,time,utility,convert,
// environment}-l1-1-0.dll. Under UEFI these DLLs aren't loaded → IAT
// thunks point to .rdata Hint/Name structs → indirect call lands on
// non-executable .rdata → HW #PF.
//
// Strategy: provide BOTH forms of each symbol:
//   - `NAME` as static function (resolves `call NAME` direct call sites)
//   - `__imp_NAME` as data pointer to that function (resolves
//     `call qword ptr [__imp_NAME]` dllimport call sites)
//
// /FORCE:MULTIPLE makes linker pick first defined. coreclrpal.lib
// precedes ucrt.lib in linker resolution order, so ours win.
//
// When CoreCLR runtime actually calls one of these, the trap fires with
// the name printed via SharpOSHost_DebugPrint → empirical list of which
// CRT functions coreclr_initialize touches. Replace traps with real
// impls one by one.
//
// PER FORK INVARIANT: C++ is allowed в submodule (not main repo).

#include <stddef.h>
#include <stdint.h>

// Forwards to host-side diagnostic (defined в OS/src/PAL/SharpOSHost/
// Diagnostics.cs). Weak fallback for coreclr.dll smoke build target.
extern "C" __attribute__((weak)) void SharpOSHost_DebugPrint(const char* /*msg*/) {}
extern "C" __attribute__((weak)) void SharpOSHost_DebugPrintHex(uint64_t /*v*/) {}
extern "C" __attribute__((weak)) void SharpOSHost_Panic(const char* /*msg*/) {}

// Forwards к host-side heap (defined в CrtHeapStubs.cs). Used by HeapAlloc
// и HeapFree real impls below. Weak fallback для coreclr.dll smoke target.
extern "C" __attribute__((weak)) void* SharpOSHost_HeapAlloc(size_t /*size*/) { return nullptr; }
extern "C" __attribute__((weak)) void  SharpOSHost_HeapFree(void* /*ptr*/) {}

static void __sharpos_crt_trap_common(const char* name, uint64_t caller_rip)
{
    SharpOSHost_DebugPrint("[CRT trap] ");
    SharpOSHost_DebugPrint(name);
    SharpOSHost_DebugPrint(" caller=0x");
    SharpOSHost_DebugPrintHex(caller_rip);
    SharpOSHost_DebugPrint("\n");
    SharpOSHost_Panic(name);
    for (;;) {
        __asm__ volatile("hlt");
    }
}

// Macro: declare both direct function AND __imp_ pointer for a CRT symbol.
// Compiler emits the function with no fixed signature — args passed in
// regs/stack are ignored, we just trap. Linker resolution unifies both
// callsite styles to our trap.
// __builtin_return_address(0) gives caller's RIP — printed by trap для
// localization of which CoreCLR fn called the unimplemented stub.
#define CRT_STUB(NAME)                                                    \
    extern "C" void NAME() {                                              \
        __sharpos_crt_trap_common(#NAME, (uint64_t)__builtin_return_address(0)); \
    }                                                                     \
    extern "C" void* __imp_##NAME = (void*)&NAME;

// --- 124 imports from /tmp/imports-ucrt.txt ---
// Sources: api-ms-win-crt-{string,stdio,runtime,heap,math,time,utility,
// convert,environment}-l1-1-0.dll. Regen with llvm-readobj --coff-imports
// against OS.exe; see work/PAL/symbol-audit/ for tooling.

CRT_STUB(__acrt_iob_func)
CRT_STUB(__stdio_common_vfprintf)
CRT_STUB(__stdio_common_vsnprintf_s)
CRT_STUB(__stdio_common_vsprintf)
CRT_STUB(__stdio_common_vsprintf_s)
CRT_STUB(__stdio_common_vsscanf)
CRT_STUB(_atoi64)
CRT_STUB(_callnewh)
CRT_STUB(_dup)
CRT_STUB(_errno)
CRT_STUB(_fdopen)
CRT_STUB(_fileno)
CRT_STUB(_flushall)
CRT_STUB(_invalid_parameter_noinfo)
CRT_STUB(_setmode)
CRT_STUB(_strdup)
CRT_STUB(_stricmp)
CRT_STUB(_time64)
CRT_STUB(_wassert)
CRT_STUB(_wcsicmp)
CRT_STUB(_wcstoui64)
CRT_STUB(_wfopen)
CRT_STUB(_write)
CRT_STUB(acos)
CRT_STUB(acosf)
CRT_STUB(acosh)
CRT_STUB(acoshf)
CRT_STUB(asin)
CRT_STUB(asinf)
CRT_STUB(asinh)
CRT_STUB(asinhf)
CRT_STUB(atan)
CRT_STUB(atan2)
CRT_STUB(atan2f)
CRT_STUB(atanf)
CRT_STUB(atanh)
CRT_STUB(atanhf)
CRT_STUB(atoi)
CRT_STUB(atol)
CRT_STUB(bsearch)
CRT_STUB(cbrt)
CRT_STUB(cbrtf)
CRT_STUB(ceil)
CRT_STUB(ceilf)
CRT_STUB(cos)
CRT_STUB(cosf)
CRT_STUB(cosh)
CRT_STUB(coshf)
CRT_STUB(exp)
CRT_STUB(expf)
CRT_STUB(fclose)
CRT_STUB(fflush)
CRT_STUB(fgets)
CRT_STUB(floor)
CRT_STUB(floorf)
CRT_STUB(fmod)
CRT_STUB(fmodf)
CRT_STUB(fopen)
CRT_STUB(fopen_s)
CRT_STUB(fputs)
CRT_STUB(fseek)
CRT_STUB(ftell)
CRT_STUB(fwrite)
CRT_STUB(getenv)
CRT_STUB(ilogbf)
// isalpha/isdigit/isprint/isspace/iswprint/iswspace/iswupper — real impls below
// towlower — real impl below
CRT_STUB(ldiv)
CRT_STUB(log)
CRT_STUB(log10)
CRT_STUB(log10f)
CRT_STUB(log2)
CRT_STUB(log2f)
CRT_STUB(logf)
CRT_STUB(modf)
CRT_STUB(modff)
CRT_STUB(perror)
CRT_STUB(pow)
CRT_STUB(powf)
CRT_STUB(qsort)
CRT_STUB(setvbuf)
CRT_STUB(sin)
CRT_STUB(sinf)
CRT_STUB(sinh)
CRT_STUB(sinhf)
CRT_STUB(sqrt)
CRT_STUB(sqrtf)
// strlen / strnlen / strcmp / strncmp / strcpy / strncpy / strcpy_s /
// strncpy_s / strcat / strcat_s / strncat_s / strpbrk — real impls below
CRT_STUB(strtod)
CRT_STUB(strtok_s)
CRT_STUB(strtoul)
CRT_STUB(strtoull)
CRT_STUB(tan)
CRT_STUB(tanf)
CRT_STUB(tanh)
CRT_STUB(tanhf)
// towlower — real impl below
CRT_STUB(trunc)
CRT_STUB(truncf)
// wcslen / wcsnlen / wcscmp / wcsncmp / wcscpy_s / wcsncpy_s /
// wcscat_s / wcsncat_s — real impls below
CRT_STUB(wcstoul)

// --- Win32 imports (kernel32.dll / advapi32.dll / user32.dll / ole32.dll) ---
// Same trap mechanism — name printed на first call, then Panic.
// Generated from llvm-readobj --coff-imports filtered to non-CRT DLLs.

// AcquireSRWLockExclusive — real impl below
CRT_STUB(AdjustTokenPrivileges)
CRT_STUB(CancelIoEx)
CRT_STUB(CloseHandle)
CRT_STUB(CoCreateGuid)
CRT_STUB(CoTaskMemAlloc)
CRT_STUB(CoTaskMemFree)
CRT_STUB(ConnectNamedPipe)
CRT_STUB(CreateEventW)
CRT_STUB(CreateFileA)
CRT_STUB(CreateFileMappingA)
CRT_STUB(CreateFileMappingW)
CRT_STUB(CreateFileW)
CRT_STUB(CreateNamedPipeA)
CRT_STUB(CreateProcessW)
CRT_STUB(CreateSemaphoreExW)
CRT_STUB(CreateThread)
CRT_STUB(DebugBreak)
// DecodePointer — real impl below
// DeleteCriticalSection — real impl below
CRT_STUB(DisconnectNamedPipe)
CRT_STUB(DuplicateHandle)
// EncodePointer — real impl below
// EnterCriticalSection — real impl below
CRT_STUB(ExitProcess)
CRT_STUB(ExitThread)
CRT_STUB(FlushFileBuffers)
CRT_STUB(FlushInstructionCache)
CRT_STUB(FlushProcessWriteBuffers)
CRT_STUB(FormatMessageW)
// FreeEnvironmentStringsW — real impl below
CRT_STUB(FreeLibrary)
// GetCPInfo / GetCommandLineW / GetConsoleOutputCP — real impls below
// GetCurrentProcess / GetCurrentProcessId / GetCurrentThread /
// GetCurrentThreadId — real impls below
// GetEnabledXStateFeatures — real impl below
// GetEnvironmentStringsW / GetEnvironmentVariableA / GetEnvironmentVariableW —
// real impls below (no env → all return 0 or null)
CRT_STUB(GetExitCodeProcess)
CRT_STUB(GetFileSize)
CRT_STUB(GetFullPathNameW)
// GetLargePageMinimum — real impl below
// GetLastError — real impl below
// GetLogicalProcessorInformation / GetLogicalProcessorInformationEx —
// real impls below
// GetModuleFileNameW / GetModuleHandleA / GetModuleHandleW — real impls below
// GetNumaHighestNodeNumber — real impl below
CRT_STUB(GetOverlappedResult)
// GetProcAddress / GetProcessAffinityMask / GetProcessGroupAffinity —
// real impls below
// GetProcessHeap — real impl below
CRT_STUB(GetSidSubAuthority)
CRT_STUB(GetSidSubAuthorityCount)
CRT_STUB(GetStdHandle)
// GetSystemInfo — real impl below
// GetSystemTime — real impl below
// GetSystemTimeAsFileTime — real impl below
CRT_STUB(GetThreadContext)
// GetThreadGroupAffinity — real impl below
CRT_STUB(GetThreadPriority)
// GetTickCount64 — real impl below
CRT_STUB(GetTokenInformation)
CRT_STUB(GetWriteWatch)
CRT_STUB(GlobalMemoryStatusEx)
// HeapAlloc / HeapCreate / HeapDestroy / HeapFree — real impls below
// InitializeCriticalSection — real impl below
// IsDebuggerPresent — real impl below
// IsProcessInJob — real impl below
// IsProcessorFeaturePresent — real impl below
CRT_STUB(K32GetProcessMemoryInfo)
// LeaveCriticalSection — real impl below
CRT_STUB(LoadLibraryExW)
CRT_STUB(LoadStringW)
CRT_STUB(LocalFree)
CRT_STUB(LookupPrivilegeValueW)
CRT_STUB(MapViewOfFile)
CRT_STUB(MapViewOfFileEx)
CRT_STUB(MultiByteToWideChar)
CRT_STUB(OpenProcessToken)
CRT_STUB(OpenThreadToken)
CRT_STUB(OutputDebugStringA)
CRT_STUB(OutputDebugStringW)
// QueryInformationJobObject — real impl below
// QueryPerformanceCounter / QueryPerformanceFrequency — real impls below
CRT_STUB(QueryThreadCycleTime)
CRT_STUB(QueueUserAPC)
CRT_STUB(RaiseException)
CRT_STUB(RaiseFailFastException)
CRT_STUB(ReadFile)
CRT_STUB(ReadProcessMemory)
CRT_STUB(RegCloseKey)
CRT_STUB(RegOpenKeyExW)
CRT_STUB(RegQueryValueExW)
// ReleaseSRWLockExclusive — real impl below
CRT_STUB(ReleaseSemaphore)
CRT_STUB(ResetEvent)
CRT_STUB(ResetWriteWatch)
CRT_STUB(ResumeThread)
CRT_STUB(RevertToSelf)
CRT_STUB(RtlCaptureContext)
CRT_STUB(RtlDeleteFunctionTable)
CRT_STUB(RtlInstallFunctionTableCallback)
CRT_STUB(RtlLookupFunctionEntry)
CRT_STUB(RtlRestoreContext)
CRT_STUB(RtlUnwind)
CRT_STUB(RtlVirtualUnwind)
CRT_STUB(SetEnvironmentVariableW)
CRT_STUB(SetEvent)
CRT_STUB(SetFilePointer)
// SetLastError — real impl below
CRT_STUB(SetThreadContext)
CRT_STUB(SetThreadErrorMode)
CRT_STUB(SetThreadPriority)
CRT_STUB(SetThreadToken)
CRT_STUB(SetUnhandledExceptionFilter)
CRT_STUB(SignalObjectAndWait)
CRT_STUB(Sleep)
// SleepConditionVariableSRW — real impl below
CRT_STUB(SleepEx)
CRT_STUB(SwitchToThread)
CRT_STUB(TerminateProcess)
CRT_STUB(UnhandledExceptionFilter)
CRT_STUB(UnmapViewOfFile)
CRT_STUB(VirtualAlloc)
CRT_STUB(VirtualAllocExNuma)
CRT_STUB(VirtualFree)
CRT_STUB(VirtualProtect)
CRT_STUB(VirtualQuery)
CRT_STUB(VirtualUnlock)
CRT_STUB(WaitForMultipleObjects)
CRT_STUB(WaitForMultipleObjectsEx)
CRT_STUB(WaitForSingleObject)
CRT_STUB(WaitForSingleObjectEx)
// WakeAllConditionVariable — real impl below
CRT_STUB(WideCharToMultiByte)
CRT_STUB(WriteFile)

// --- Real impls (replace traps as we discover them empirically) ---
//
// Macro for symbol pair: function NAME + __imp_NAME data pointing to it.
#define CRT_REAL(NAME) extern "C" void* __imp_##NAME = (void*)&NAME

// --- string length ---

extern "C" size_t strlen(const char* s) {
    if (!s) return 0; size_t n = 0; while (s[n]) ++n; return n;
}
CRT_REAL(strlen);

extern "C" size_t strnlen(const char* s, size_t maxN) {
    if (!s) return 0; size_t n = 0; while (n < maxN && s[n]) ++n; return n;
}
CRT_REAL(strnlen);

extern "C" size_t wcslen(const wchar_t* s) {
    if (!s) return 0; size_t n = 0; while (s[n]) ++n; return n;
}
CRT_REAL(wcslen);

extern "C" size_t wcsnlen(const wchar_t* s, size_t maxN) {
    if (!s) return 0; size_t n = 0; while (n < maxN && s[n]) ++n; return n;
}
CRT_REAL(wcsnlen);

// --- string compare ---

extern "C" int strcmp(const char* a, const char* b) {
    while (*a && (*a == *b)) { ++a; ++b; }
    return (unsigned char)*a - (unsigned char)*b;
}
CRT_REAL(strcmp);

extern "C" int strncmp(const char* a, const char* b, size_t n) {
    while (n && *a && (*a == *b)) { ++a; ++b; --n; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}
CRT_REAL(strncmp);

extern "C" int wcscmp(const wchar_t* a, const wchar_t* b) {
    while (*a && (*a == *b)) { ++a; ++b; }
    return (int)*a - (int)*b;
}
CRT_REAL(wcscmp);

extern "C" int wcsncmp(const wchar_t* a, const wchar_t* b, size_t n) {
    while (n && *a && (*a == *b)) { ++a; ++b; --n; }
    if (n == 0) return 0;
    return (int)*a - (int)*b;
}
CRT_REAL(wcsncmp);

// --- string copy / cat (returns error code; 0 = success) ---

extern "C" char* strcpy(char* dst, const char* src) {
    char* d = dst; while ((*d++ = *src++)) {} return dst;
}
CRT_REAL(strcpy);

extern "C" char* strncpy(char* dst, const char* src, size_t n) {
    size_t i = 0;
    for (; i < n && src[i]; i++) dst[i] = src[i];
    for (; i < n; i++) dst[i] = 0;
    return dst;
}
CRT_REAL(strncpy);

extern "C" int strcpy_s(char* dst, size_t dstSize, const char* src) {
    if (!dst || !src || dstSize == 0) return 22; // EINVAL
    size_t i = 0;
    while (src[i]) {
        if (i + 1 >= dstSize) { dst[0] = 0; return 34; } // ERANGE
        dst[i] = src[i]; ++i;
    }
    dst[i] = 0;
    return 0;
}
CRT_REAL(strcpy_s);

extern "C" int strncpy_s(char* dst, size_t dstSize, const char* src, size_t n) {
    if (!dst || dstSize == 0) return 22;
    if (!src) { dst[0] = 0; return 22; }
    size_t i = 0;
    while (i < n && src[i]) {
        if (i + 1 >= dstSize) { dst[0] = 0; return 34; }
        dst[i] = src[i]; ++i;
    }
    if (i >= dstSize) { dst[0] = 0; return 34; }
    dst[i] = 0;
    return 0;
}
CRT_REAL(strncpy_s);

extern "C" char* strcat(char* dst, const char* src) {
    char* d = dst; while (*d) ++d;
    while ((*d++ = *src++)) {}
    return dst;
}
CRT_REAL(strcat);

extern "C" int strcat_s(char* dst, size_t dstSize, const char* src) {
    if (!dst || !src || dstSize == 0) return 22;
    size_t i = 0; while (i < dstSize && dst[i]) ++i;
    if (i >= dstSize) return 22;
    while (*src) {
        if (i + 1 >= dstSize) { dst[0] = 0; return 34; }
        dst[i++] = *src++;
    }
    dst[i] = 0;
    return 0;
}
CRT_REAL(strcat_s);

extern "C" int strncat_s(char* dst, size_t dstSize, const char* src, size_t n) {
    if (!dst || dstSize == 0) return 22;
    if (!src && n != 0) return 22;
    size_t i = 0; while (i < dstSize && dst[i]) ++i;
    if (i >= dstSize) return 22;
    size_t j = 0;
    while (j < n && src[j]) {
        if (i + 1 >= dstSize) { dst[0] = 0; return 34; }
        dst[i++] = src[j++];
    }
    dst[i] = 0;
    return 0;
}
CRT_REAL(strncat_s);

extern "C" int wcscpy_s(wchar_t* dst, size_t dstSize, const wchar_t* src) {
    if (!dst || !src || dstSize == 0) return 22;
    size_t i = 0;
    while (src[i]) {
        if (i + 1 >= dstSize) { dst[0] = 0; return 34; }
        dst[i] = src[i]; ++i;
    }
    dst[i] = 0;
    return 0;
}
CRT_REAL(wcscpy_s);

extern "C" int wcsncpy_s(wchar_t* dst, size_t dstSize, const wchar_t* src, size_t n) {
    if (!dst || dstSize == 0) return 22;
    if (!src) { dst[0] = 0; return 22; }
    size_t i = 0;
    while (i < n && src[i]) {
        if (i + 1 >= dstSize) { dst[0] = 0; return 34; }
        dst[i] = src[i]; ++i;
    }
    if (i >= dstSize) { dst[0] = 0; return 34; }
    dst[i] = 0;
    return 0;
}
CRT_REAL(wcsncpy_s);

extern "C" int wcscat_s(wchar_t* dst, size_t dstSize, const wchar_t* src) {
    if (!dst || !src || dstSize == 0) return 22;
    size_t i = 0; while (i < dstSize && dst[i]) ++i;
    if (i >= dstSize) return 22;
    while (*src) {
        if (i + 1 >= dstSize) { dst[0] = 0; return 34; }
        dst[i++] = *src++;
    }
    dst[i] = 0;
    return 0;
}
CRT_REAL(wcscat_s);

extern "C" int wcsncat_s(wchar_t* dst, size_t dstSize, const wchar_t* src, size_t n) {
    if (!dst || dstSize == 0) return 22;
    if (!src && n != 0) return 22;
    size_t i = 0; while (i < dstSize && dst[i]) ++i;
    if (i >= dstSize) return 22;
    size_t j = 0;
    while (j < n && src[j]) {
        if (i + 1 >= dstSize) { dst[0] = 0; return 34; }
        dst[i++] = src[j++];
    }
    dst[i] = 0;
    return 0;
}
CRT_REAL(wcsncat_s);

// strpbrk: find first char in s1 that matches any char in s2.
extern "C" char* strpbrk(const char* s1, const char* s2) {
    while (*s1) {
        for (const char* p = s2; *p; ++p) {
            if (*s1 == *p) return (char*)s1;
        }
        ++s1;
    }
    return nullptr;
}
CRT_REAL(strpbrk);

// --- ctype (ASCII-only impls, sufficient для CoreCLR init) ---

extern "C" int isalpha(int c)  { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
CRT_REAL(isalpha);
extern "C" int isdigit(int c)  { return c >= '0' && c <= '9'; }
CRT_REAL(isdigit);
extern "C" int isspace(int c)  { return c == ' ' || (c >= 9 && c <= 13); }
CRT_REAL(isspace);
extern "C" int isprint(int c)  { return c >= 0x20 && c < 0x7F; }
CRT_REAL(isprint);
extern "C" int iswprint(int c) { return c >= 0x20 && c != 0x7F; }
CRT_REAL(iswprint);
extern "C" int iswspace(int c) { return c == ' ' || (c >= 9 && c <= 13) || c == 0x00A0; }
CRT_REAL(iswspace);
extern "C" int iswupper(int c) { return c >= 'A' && c <= 'Z'; }
CRT_REAL(iswupper);
extern "C" int towlower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
CRT_REAL(towlower);

// --- Win32 trivial: timing / identity / state / no-op ---
//
// All single-thread, no-op or constant impls. Sufficient для CoreCLR init.
// Real implementations (when threading/timer/files materialize) must come
// later — these get past startup walls only.

// LARGE_INTEGER ≡ int64_t pointer.
// Per-call trace for real-impl stubs (Phase 6.1.b diagnostic).
// Prints fn name + caller RIP. Caller must pass __builtin_return_address(0)
// from itself (NOT from inside trace_real which would return trace_real's
// caller = the wrapper, not the original CoreCLR site).
static inline void trace_real(const char* fn, uint64_t caller)
{
    SharpOSHost_DebugPrint("[real] ");
    SharpOSHost_DebugPrint(fn);
    SharpOSHost_DebugPrint(" caller=0x");
    SharpOSHost_DebugPrintHex(caller);
    SharpOSHost_DebugPrint("\n");
}

#define TRACE_REAL(NAME) trace_real(#NAME, (uint64_t)__builtin_return_address(0))

extern "C" int QueryPerformanceCounter(int64_t* out) {
    TRACE_REAL(QueryPerformanceCounter);
    static int64_t ticks = 0;
    if (out) *out = ++ticks;
    return 1;
}
CRT_REAL(QueryPerformanceCounter);

extern "C" int QueryPerformanceFrequency(int64_t* out) {
    TRACE_REAL(QueryPerformanceFrequency);
    if (out) *out = 10000000;
    return 1;
}
CRT_REAL(QueryPerformanceFrequency);

extern "C" uint64_t GetTickCount64(void) {
    TRACE_REAL(GetTickCount64);
    static uint64_t t = 0;
    return ++t;
}
CRT_REAL(GetTickCount64);

extern "C" void GetSystemTimeAsFileTime(void* out) {
    TRACE_REAL(GetSystemTimeAsFileTime);
    if (out) *(uint64_t*)out = 0;
}
CRT_REAL(GetSystemTimeAsFileTime);

extern "C" void GetSystemTime(void* out) {
    TRACE_REAL(GetSystemTime);
    if (out) {
        uint16_t* p = (uint16_t*)out;
        for (int i = 0; i < 8; i++) p[i] = 0;
    }
}
CRT_REAL(GetSystemTime);

extern "C" void* GetCurrentProcess(void)      { TRACE_REAL(GetCurrentProcess);   return (void*)(intptr_t)-1; }
CRT_REAL(GetCurrentProcess);
extern "C" void* GetCurrentThread(void)       { TRACE_REAL(GetCurrentThread);    return (void*)(intptr_t)-2; }
CRT_REAL(GetCurrentThread);
extern "C" uint32_t GetCurrentProcessId(void) { TRACE_REAL(GetCurrentProcessId); return 1; }
CRT_REAL(GetCurrentProcessId);
extern "C" uint32_t GetCurrentThreadId(void)  { TRACE_REAL(GetCurrentThreadId);  return 1; }
CRT_REAL(GetCurrentThreadId);

static uint32_t g_LastError = 0;
extern "C" uint32_t GetLastError(void)  { /* TRACE_REAL too noisy */ return g_LastError; }
CRT_REAL(GetLastError);
extern "C" void SetLastError(uint32_t e) { g_LastError = e; }
CRT_REAL(SetLastError);

extern "C" int IsDebuggerPresent(void) { TRACE_REAL(IsDebuggerPresent); return 0; }
CRT_REAL(IsDebuggerPresent);

// CRITICAL_SECTION = 40 bytes on x64:
//   +0x00: PRTL_CRITICAL_SECTION_DEBUG DebugInfo  (8)
//   +0x08: LONG LockCount                          (4)
//   +0x0C: LONG RecursionCount                     (4)
//   +0x10: HANDLE OwningThread                     (8)
//   +0x18: HANDLE LockSemaphore                    (8)
//   +0x20: ULONG_PTR SpinCount                     (8)
//
// Real Win32 init sets DebugInfo to a per-CS allocated struct AND
// LockCount = -1 (sentinel "unlocked"). Our no-op left struct zero,
// which CoreCLR may interpret as "locked by someone else" or "broken".
//
// Phase 6.1.b: set LockCount = -1 (unlocked sentinel). DebugInfo стайс 0
// — CoreCLR typically checks LockCount, not DebugInfo, для lock state.
extern "C" void InitializeCriticalSection(void* cs) {
    TRACE_REAL(InitializeCriticalSection);
    // Phase 6.1.b: scan stack upward looking for .text-range return addr =
    // CoreCLR site that called minipal_mutex_init. We can't directly know
    // RSP at entry (prologue moved it), но local var's address is near
    // current SP. Scan up to 32 qwords looking for plausible code address.
    volatile uint8_t marker;
    uint64_t* sp = (uint64_t*)((uintptr_t)&marker & ~(uintptr_t)7);
    SharpOSHost_DebugPrint("  scan:");
    for (int i = 0; i < 32; i++) {
        uint64_t v = sp[i];
        // Heuristic — .text loaded range 0xC1AA000..0xCE5E8DC (this build).
        if (v >= 0xC1AA000ULL && v < 0xCE5F000ULL) {
            SharpOSHost_DebugPrint(" [");
            SharpOSHost_DebugPrintHex((uint64_t)(i * 8));
            SharpOSHost_DebugPrint("]=0x");
            SharpOSHost_DebugPrintHex(v);
        }
    }
    SharpOSHost_DebugPrint("\n");

    if (cs) {
        uint8_t* p = (uint8_t*)cs;
        for (int i = 0; i < 40; i++) p[i] = 0;
        *(int32_t*)(p + 0x08) = -1;
    }
}
CRT_REAL(InitializeCriticalSection);
extern "C" void EnterCriticalSection(void* /*cs*/)      { /* noisy */ }
CRT_REAL(EnterCriticalSection);
extern "C" void LeaveCriticalSection(void* /*cs*/)      { /* noisy */ }
CRT_REAL(LeaveCriticalSection);
extern "C" void DeleteCriticalSection(void* /*cs*/)     { TRACE_REAL(DeleteCriticalSection); }
CRT_REAL(DeleteCriticalSection);

extern "C" void AcquireSRWLockExclusive(void* /*l*/) { /* noisy */ }
CRT_REAL(AcquireSRWLockExclusive);
extern "C" void ReleaseSRWLockExclusive(void* /*l*/) { /* noisy */ }
CRT_REAL(ReleaseSRWLockExclusive);
extern "C" void WakeAllConditionVariable(void* /*cv*/) { TRACE_REAL(WakeAllConditionVariable); }
CRT_REAL(WakeAllConditionVariable);
extern "C" int SleepConditionVariableSRW(void* /*cv*/, void* /*lock*/,
                                         uint32_t /*ms*/, uint32_t /*flags*/) { TRACE_REAL(SleepConditionVariableSRW); return 1; }
CRT_REAL(SleepConditionVariableSRW);

extern "C" void* EncodePointer(void* p) { /* noisy */ return p; }
CRT_REAL(EncodePointer);
extern "C" void* DecodePointer(void* p) { /* noisy */ return p; }
CRT_REAL(DecodePointer);

// IsProcessorFeaturePresent / GetEnabledXStateFeatures — return 0 (no
// extended state features advertised).
extern "C" int IsProcessorFeaturePresent(uint32_t /*feat*/) { TRACE_REAL(IsProcessorFeaturePresent); return 0; }
CRT_REAL(IsProcessorFeaturePresent);
extern "C" uint64_t GetEnabledXStateFeatures(void) { TRACE_REAL(GetEnabledXStateFeatures); return 0; }
CRT_REAL(GetEnabledXStateFeatures);

extern "C" uint64_t GetLargePageMinimum(void) { TRACE_REAL(GetLargePageMinimum); return 0; }
CRT_REAL(GetLargePageMinimum);
extern "C" int GetNumaHighestNodeNumber(uint32_t* out) {
    TRACE_REAL(GetNumaHighestNodeNumber);
    if (out) *out = 0;
    return 1;
}
CRT_REAL(GetNumaHighestNodeNumber);

extern "C" void GetSystemInfo(void* out) {
    TRACE_REAL(GetSystemInfo);
    if (!out) return;
    uint32_t* p = (uint32_t*)out;
    for (int i = 0; i < 12; i++) p[i] = 0;
    p[0] = 9;       // wProcessorArchitecture = AMD64
    p[1] = 0x1000;  // dwPageSize
    p[8] = 1;       // dwNumberOfProcessors
}
CRT_REAL(GetSystemInfo);

extern "C" void* GetProcessHeap(void) { TRACE_REAL(GetProcessHeap); return (void*)(intptr_t)1; }
CRT_REAL(GetProcessHeap);

// HeapAlloc(handle, flags, size) → SharpOSHost-routed alloc.
extern "C" void* HeapAlloc(void* /*h*/, uint32_t /*flags*/, size_t size) {
    SharpOSHost_DebugPrint("[crt] HeapAlloc(0x");
    SharpOSHost_DebugPrintHex(size);
    SharpOSHost_DebugPrint(") caller=0x");
    SharpOSHost_DebugPrintHex((uint64_t)__builtin_return_address(0));
    SharpOSHost_DebugPrint("\n");
    return SharpOSHost_HeapAlloc(size);
}
CRT_REAL(HeapAlloc);

extern "C" int HeapFree(void* /*h*/, uint32_t /*flags*/, void* p) {
    SharpOSHost_HeapFree(p);
    return 1;
}
CRT_REAL(HeapFree);

extern "C" void* HeapCreate(uint32_t /*opts*/, size_t /*initSize*/, size_t /*maxSize*/) {
    TRACE_REAL(HeapCreate);
    return (void*)(intptr_t)1;
}
CRT_REAL(HeapCreate);

extern "C" int HeapDestroy(void* /*h*/) { TRACE_REAL(HeapDestroy); return 1; }
CRT_REAL(HeapDestroy);

// --- Win32 env / module / console (all empty / not-found) ---
//
// CoreCLR queries DOTNET_*/COMPlus_* env vars for config tuning. Returning
// 0 (var not found) makes CoreCLR fall back to baked-in defaults.
// GetCommandLineW returns empty wstr. Module handles return null (no
// modules loaded — kernel image is the only one).

static const wchar_t k_empty_w[] = { 0 };
static uint32_t k_ERROR_ENVVAR_NOT_FOUND = 203;

extern "C" uint32_t GetEnvironmentVariableW(const wchar_t* /*name*/, wchar_t* /*buf*/, uint32_t /*size*/) {
    TRACE_REAL(GetEnvironmentVariableW);
    g_LastError = k_ERROR_ENVVAR_NOT_FOUND;
    return 0;
}
CRT_REAL(GetEnvironmentVariableW);

extern "C" uint32_t GetEnvironmentVariableA(const char* /*name*/, char* /*buf*/, uint32_t /*size*/) {
    TRACE_REAL(GetEnvironmentVariableA);
    g_LastError = k_ERROR_ENVVAR_NOT_FOUND;
    return 0;
}
CRT_REAL(GetEnvironmentVariableA);

extern "C" wchar_t* GetEnvironmentStringsW(void) { TRACE_REAL(GetEnvironmentStringsW); return nullptr; }
CRT_REAL(GetEnvironmentStringsW);
extern "C" int FreeEnvironmentStringsW(wchar_t* /*p*/) { TRACE_REAL(FreeEnvironmentStringsW); return 1; }
CRT_REAL(FreeEnvironmentStringsW);

extern "C" const wchar_t* GetCommandLineW(void) { TRACE_REAL(GetCommandLineW); return k_empty_w; }
CRT_REAL(GetCommandLineW);

extern "C" uint32_t GetConsoleOutputCP(void) { TRACE_REAL(GetConsoleOutputCP); return 437; }
CRT_REAL(GetConsoleOutputCP);

extern "C" int GetCPInfo(uint32_t /*cp*/, void* out) {
    TRACE_REAL(GetCPInfo);
    if (!out) return 0;
    uint8_t* p = (uint8_t*)out;
    for (int i = 0; i < 4 + 2 + 12; i++) p[i] = 0;
    *(uint32_t*)p = 1;
    return 1;
}
CRT_REAL(GetCPInfo);

extern "C" void* GetModuleHandleW(const wchar_t* /*name*/) { TRACE_REAL(GetModuleHandleW); return (void*)(intptr_t)1; }
CRT_REAL(GetModuleHandleW);
extern "C" void* GetModuleHandleA(const char* /*name*/)    { TRACE_REAL(GetModuleHandleA); return (void*)(intptr_t)1; }
CRT_REAL(GetModuleHandleA);

extern "C" uint32_t GetModuleFileNameW(void* /*mod*/, wchar_t* buf, uint32_t size) {
    TRACE_REAL(GetModuleFileNameW);
    if (buf && size > 0) buf[0] = 0;
    return 0;
}
CRT_REAL(GetModuleFileNameW);

extern "C" void* GetProcAddress(void* /*mod*/, const char* /*name*/) { TRACE_REAL(GetProcAddress); return nullptr; }
CRT_REAL(GetProcAddress);

// --- Win32 CPU topology (single CPU / single group / 1 logical core) ---

extern "C" int GetProcessAffinityMask(void* /*proc*/, size_t* procMask, size_t* sysMask) {
    TRACE_REAL(GetProcessAffinityMask);
    if (procMask) *procMask = 1;
    if (sysMask) *sysMask = 1;
    return 1;
}
CRT_REAL(GetProcessAffinityMask);

extern "C" int GetProcessGroupAffinity(void* /*proc*/, uint16_t* groupCount, uint16_t* groupArray) {
    TRACE_REAL(GetProcessGroupAffinity);
    if (!groupCount) return 0;
    if (*groupCount < 1) { *groupCount = 1; g_LastError = 122; return 0; }
    *groupCount = 1;
    if (groupArray) groupArray[0] = 0;
    return 1;
}
CRT_REAL(GetProcessGroupAffinity);

extern "C" int GetThreadGroupAffinity(void* /*thread*/, void* groupAffinity) {
    TRACE_REAL(GetThreadGroupAffinity);
    if (!groupAffinity) return 0;
    uint8_t* p = (uint8_t*)groupAffinity;
    for (int i = 0; i < 16; i++) p[i] = 0;
    *(size_t*)p = 1;
    *(uint16_t*)(p + 8) = 0;
    return 1;
}
CRT_REAL(GetThreadGroupAffinity);

extern "C" int GetLogicalProcessorInformation(void* /*buf*/, uint32_t* needed) {
    TRACE_REAL(GetLogicalProcessorInformation);
    g_LastError = 122;
    if (needed) *needed = 0;
    return 0;
}
CRT_REAL(GetLogicalProcessorInformation);

extern "C" int GetLogicalProcessorInformationEx(uint32_t /*relationship*/, void* /*buf*/, uint32_t* needed) {
    TRACE_REAL(GetLogicalProcessorInformationEx);
    g_LastError = 122;
    if (needed) *needed = 0;
    return 0;
}
CRT_REAL(GetLogicalProcessorInformationEx);

extern "C" int IsProcessInJob(void* /*proc*/, void* /*job*/, int* result) {
    TRACE_REAL(IsProcessInJob);
    if (result) *result = 0;
    return 1;
}
CRT_REAL(IsProcessInJob);

extern "C" int QueryInformationJobObject(void* /*job*/, uint32_t /*infoClass*/,
                                          void* /*info*/, uint32_t /*infoLen*/,
                                          uint32_t* returnLen) {
    TRACE_REAL(QueryInformationJobObject);
    if (returnLen) *returnLen = 0;
    g_LastError = 6;
    return 0;
}
CRT_REAL(QueryInformationJobObject);
