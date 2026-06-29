// SharpOS port: WinAPI shim — stubs для функций которые vm/utilcode expects
// от Linux PAL или from missing Windows-side libs. На HOST_WINDOWS routed
// на native Win32 API; при kernel link нужно replace на kernel-native impls.
//
// См. work/PAL/CORECLR_PORT_WINAPI_DEBT.md для context.
//
// IMPORTANT: linkage должен match call-site declarations.
// - Если header declares без extern "C" (C++ linkage, mangled) → здесь тоже без.
// - Если header declares extern "C" (unmangled) → здесь с extern "C".

#include <windows.h>
#include <stdint.h>

// inc/clrhost.h:69 — `HANDLE ClrGetProcessExecutableHeap();` (C++ linkage)
HANDLE ClrGetProcessExecutableHeap()
{
    return GetProcessHeap();
}

// inc/winwrap.h / clrhost.h — `HMODULE CLRLoadLibraryEx(...)` (C++ linkage)
HMODULE CLRLoadLibraryEx(LPCWSTR fileName, HANDLE hReservedNull, DWORD flags)
{
    return ::LoadLibraryExW(fileName, hReservedNull, flags);
}

// RtlVirtualUnwind_Unsafe — now provided by vm/rtlfunctions.cpp (gated for SharpOS).
// Stub removed to avoid duplicate symbol with EnsureRtlFunctions().

// System.Globalization.Native ICU resolver — declared extern "C" в native lib.
extern "C" void* GlobalizationResolveDllImport(const char*)
{
    return nullptr;
}

// vm/comwaithandle QCall — `extern "C" QCALLTYPE WaitHandle_WaitOnePrioritized(...)`.
extern "C" INT32 __stdcall WaitHandle_WaitOnePrioritized(HANDLE handle, INT32 timeoutMs)
{
    return (INT32)::WaitForSingleObject(handle, (DWORD)timeoutMs);
}

// vm/threadstatics Linux-AMD64 path — C++ linkage (static method-like).
void* GetTlsIndexObjectAddress()
{
    return nullptr;
}

// vm/threads.cpp:71 — TARGET_UNIX path, C++ linkage.
//
// Async-safe map is a signal-handler-safe lookup used on Unix to find
// the managed Thread* from an OS thread ID inside signal handlers. SharpOS
// is single-threaded boot + no Unix signals → no map needed. Return true
// so CoreCLR thinks the insert succeeded (otherwise EE fatal-errors
// per threads.cpp:396).
bool InsertThreadIntoAsyncSafeMap(uint64_t, void*)
{
    return true;
}

void RemoveThreadFromAsyncSafeMap(uint64_t, void*)
{
}

// ---------------------------------------------------------------------------
// CRT heap forwarders — per D9 (memory forward to SharpOSHost) + 3-tier
// architecture. CoreCLR's libcmtd/ucrt malloc family is unresolved
// (api-ms-win-crt-heap-l1-1-0.dll not loaded under UEFI). We replace
// with thin forwarders to SharpOSHost C-ABI exports — host owns the
// real kernel heap.
//
// Real implementations live в OS/src/PAL/SharpOSHost/CrtHeapStubs.cs
// (C# [RuntimeExport]). For kernel link they override fork-side
// fallbacks via /FORCE:MULTIPLE.
//
// Fork build also produces coreclr.dll (host-Windows smoke target) from
// the same .obj files. That link path lacks the C# host, so we provide
// these fallbacks returning nullptr — they keep the DLL linkable but
// are unreachable at smoke runtime (no allocation paths exercised).
// ---------------------------------------------------------------------------

extern "C" __attribute__((weak)) void* SharpOSHost_HeapAlloc(size_t /*size*/) { return nullptr; }
extern "C" __attribute__((weak)) void  SharpOSHost_HeapFree(void* /*ptr*/) {}
extern "C" __attribute__((weak)) void* SharpOSHost_HeapRealloc(void* /*old*/, size_t /*size*/) { return nullptr; }
extern "C" __attribute__((weak)) void SharpOSHost_DebugPrint(const char* /*msg*/) {}
extern "C" __attribute__((weak)) void SharpOSHost_DebugPrintHex(uint64_t /*v*/) {}
// Always-on diagnostic — weak fallback for coreclr.dll smoke build target.
// Real impl in OS/src/PAL/SharpOSHost/Diagnostics.cs (kernel link wins).
extern "C" __attribute__((weak)) void SharpOSHost_DebugPrintForced(const char* /*msg*/) {}
// step 71 — weak fallback so coreclr.dll links the [MDLM] probe's ungated
// sink; the kernel's real (non-Verbose-gated) [RuntimeExport] overrides it
// at runtime. Reverted with the probe after diagnosis.
extern "C" __attribute__((weak)) void SharpOSHost_DebugWrite(const char* /*buf*/, int /*len*/) {}

// step126.8 — weak fallbacks for all kernel-side policy exports added
// during PowerShell bring-up. Real impls live in:
//   OS/src/PAL/SharpOSHost/ThreadApartment.cs
//   OS/src/PAL/SharpOSHost/TokenSecurity.cs
//   OS/src/PAL/SharpOSHost/ShellFolders.cs
//   OS/src/PAL/SharpOSHost/LockdownPolicy.cs
//   OS/src/PAL/SharpOSHost/FileSystemPolicy.cs
// Kernel link wins at final OS.exe link.

// Thread apartment (QCALL)
extern "C" __attribute__((weak)) int SharpOSHost_ThreadSetApartmentState(int /*state*/) { return 2 /*Unknown*/; }
extern "C" __attribute__((weak)) int SharpOSHost_ThreadGetApartmentState(void) { return 2; }

// advapi32 Token/Privilege
extern "C" __attribute__((weak)) int SharpOSHost_LookupPrivilegeValue(unsigned long long* /*luid*/) { return 1313; }
extern "C" __attribute__((weak)) int SharpOSHost_LookupPrivilegeName(unsigned long* /*outLen*/) { return 1313; }
extern "C" __attribute__((weak)) int SharpOSHost_OpenProcessToken(void** /*tok*/) { return 6; }
extern "C" __attribute__((weak)) int SharpOSHost_OpenThreadToken(void** /*tok*/) { return 6; }
extern "C" __attribute__((weak)) int SharpOSHost_AdjustTokenPrivileges(void) { return 6; }
extern "C" __attribute__((weak)) int SharpOSHost_GetTokenInformation(unsigned long* /*outLen*/) { return 6; }
extern "C" __attribute__((weak)) int SharpOSHost_ImpersonateLoggedOnUser(void) { return 6; }
extern "C" __attribute__((weak)) int SharpOSHost_RevertToSelf(void) { return 0; }
extern "C" __attribute__((weak)) int SharpOSHost_CheckTokenMembership(int* /*isMem*/) { return 6; }
extern "C" __attribute__((weak)) int SharpOSHost_DuplicateTokenEx(void** /*tok*/) { return 6; }

// shell32 known folders
extern "C" __attribute__((weak)) int SharpOSHost_ShellGetKnownFolderPath(void** /*outPath*/) { return (int)0x80004005; }
extern "C" __attribute__((weak)) int SharpOSHost_ShellGetFolderPath(wchar_t* /*path*/) { return (int)0x80004005; }

// wldp (Lockdown Policy)
extern "C" __attribute__((weak)) int SharpOSHost_WldpGetLockdownPolicy(unsigned long* /*s*/) { return 0; }
extern "C" __attribute__((weak)) int SharpOSHost_WldpQueryDynamicCodeTrust(void) { return 0; }
extern "C" __attribute__((weak)) int SharpOSHost_WldpSetDynamicCodeTrust(void) { return 0; }
extern "C" __attribute__((weak)) int SharpOSHost_WldpIsClassInApprovedList(int* /*a*/) { return 0; }
extern "C" __attribute__((weak)) int SharpOSHost_WldpQueryWindowsLockdownMode(unsigned long* /*m*/) { return 0; }
extern "C" __attribute__((weak)) int SharpOSHost_WldpIsDynamicCodePolicyEnabled(int* /*e*/) { return 0; }
extern "C" __attribute__((weak)) int SharpOSHost_WldpCanExecuteFile(int* /*r*/) { return 0; }

// File system policy (CreateDirectory / RemoveDirectory / SetEnvVar / FormatMessage / CONOUT$)
extern "C" __attribute__((weak)) int SharpOSHost_CreateDirectory(void) { return 183; }
extern "C" __attribute__((weak)) int SharpOSHost_RemoveDirectory(void) { return 2; }
extern "C" __attribute__((weak)) int SharpOSHost_SetEnvironmentVariable(void) { return 0; }
extern "C" __attribute__((weak)) int SharpOSHost_FormatMessage(void) { return 1815; }
extern "C" __attribute__((weak)) int SharpOSHost_ClassifyConsoleFileName(const unsigned char* /*name*/, int /*len*/) { return 0; }

// step126.9 — console control + startup info + AMSI weak fallbacks.
extern "C" __attribute__((weak)) int  SharpOSHost_SetConsoleCtrlHandler(void) { return 1; }
extern "C" __attribute__((weak)) void SharpOSHost_GetStartupInfo(unsigned int* p, unsigned int sz) {
    if (p == nullptr || sz == 0) return;
    unsigned int n = sz / 4;
    for (unsigned int i = 0; i < n; i++) p[i] = 0;
    p[0] = sz;
}
extern "C" __attribute__((weak)) int  SharpOSHost_AmsiInitialize(unsigned long long* ctx) { if (ctx) *ctx = 1; return 0; }
extern "C" __attribute__((weak)) void SharpOSHost_AmsiUninitialize(void) {}
extern "C" __attribute__((weak)) int  SharpOSHost_AmsiOpenSession(unsigned long long* s) { if (s) *s = 1; return 0; }
extern "C" __attribute__((weak)) void SharpOSHost_AmsiCloseSession(void) {}
extern "C" __attribute__((weak)) int  SharpOSHost_AmsiScan(unsigned int* r) { if (r) *r = 0; return 0; }

// step126.10 — ole32/combase COM init weak fallbacks.
extern "C" __attribute__((weak)) int   SharpOSHost_CoInitializeEx(int /*ci*/) { return 0; }
extern "C" __attribute__((weak)) int   SharpOSHost_CoInitialize(void) { return 0; }
extern "C" __attribute__((weak)) void  SharpOSHost_CoUninitialize(void) {}
extern "C" __attribute__((weak)) int   SharpOSHost_CoCreateInstance(void** p) { if (p) *p = nullptr; return (int)0x80040154; }
extern "C" __attribute__((weak)) void* SharpOSHost_CoTaskMemAlloc(unsigned long long /*sz*/) { return nullptr; }
extern "C" __attribute__((weak)) void  SharpOSHost_CoTaskMemFree(void* /*p*/) {}

// step126.11 — user32 UI/accessibility weak fallbacks.
extern "C" __attribute__((weak)) int   SharpOSHost_SystemParametersInfo(unsigned int /*a*/, unsigned int /*p*/, unsigned char* pv, unsigned int /*w*/) {
    if (pv != nullptr) { for (int i = 0; i < 32; i++) pv[i] = 0; }
    return 1;
}
extern "C" __attribute__((weak)) int   SharpOSHost_GetSystemMetrics(int /*idx*/) { return 0; }
extern "C" __attribute__((weak)) void* SharpOSHost_GetConsoleWindow(void) { return nullptr; }

// step126.12 — type equivalence weak fallback.
extern "C" __attribute__((weak)) int SharpOSHost_TypeIsEquivalentTo(void) { return 0; }

// step126.13 — process/codepage/account weak fallbacks.
extern "C" __attribute__((weak)) void* SharpOSHost_OpenProcess(unsigned int /*pid*/) { return nullptr; }
extern "C" __attribute__((weak)) int   SharpOSHost_GetCPInfoEx(void) { return 1; }
extern "C" __attribute__((weak)) int   SharpOSHost_LookupAccountName(unsigned int* a, unsigned int* b, int* c) {
    if (a) *a = 0; if (b) *b = 0; if (c) *c = 0; return 1332;
}

// step126.14 — ReadConsole weak fallback (writes \r\n only).
extern "C" __attribute__((weak)) int   SharpOSHost_ReadConsole(wchar_t* buf, unsigned int n, unsigned int* outN) {
    unsigned int w = 0;
    if (buf != nullptr && n > 0) buf[w++] = L'\r';
    if (buf != nullptr && w < n) buf[w++] = L'\n';
    if (outN) *outN = w;
    return 1;
}
// step 72 / Frontier-B root fix — weak fallback so the fork links if the
// kernel doesn't provide the real [RuntimeExport]. No-op leaves *out=…
// untouched; the threads.cpp caller pre-zeroes and only trusts non-zero
// base>limit, so absence cleanly falls back to the original path.
extern "C" __attribute__((weak)) void SharpOSHost_GetStackBounds(uint64_t* /*outBase*/, uint64_t* /*outLimit*/) {}
// step 73 — weak fallbacks for the CMOS wall-clock bridge. Absent kernel
// export → FILETIME 0 (DateTime.UtcNow stays 1601, old behavior) and
// SYSTEMTIME left as the caller's zero-fill. No fault either way.
extern "C" __attribute__((weak)) long long SharpOSHost_GetUtcFileTime(void) { return 0; }
extern "C" __attribute__((weak)) void SharpOSHost_GetSystemTime(unsigned short* /*out8*/) {}

// ---------------------------------------------------------------------------
// PAL_LOAD* — Unix-style PE loader entry points.
//
// vm/peimagelayout.cpp's TARGET_UNIX path (now enabled для SharpOS) calls
// PAL_LOADLoadPEFile(hFile, offset) to obtain a pointer to the mapped PE
// image base. CoreCLR opens the file через CreateFileW (routed к
// SharpOSHost_FileOpen → FileState* in-memory buffer), then passes that
// HANDLE here.
//
// FileState layout (from SharpOSHost/CrtHeapStubs.cs):
//   +0x00: void* Buffer
//   +0x08: uint32_t Size
//   +0x0C: uint32_t Position
//
// Lives в coreclrpal.lib (used by BOTH kernel link AND coreclr.dll smoke
// target) — kernel CRT lib (coreclrpal_kernel_crt) is excluded from smoke
// link, so PAL_LOAD* must live elsewhere. Smoke target never exercises
// PE load paths at runtime, so functional behaviour is for the kernel
// build only.
// ---------------------------------------------------------------------------
extern "C" void* PAL_LOADLoadPEFile(HANDLE hFile, size_t offset)
{
    if (hFile == nullptr || hFile == (HANDLE)(intptr_t)-1) return nullptr;
    void* buf = *(void**)((char*)hFile + 0x00);
    uint32_t size = *(uint32_t*)((char*)hFile + 0x08);
    if (offset >= size) return nullptr;
    return (char*)buf + offset;
}

extern "C" BOOL PAL_LOADUnloadPEFile(void* /*ptr*/)
{
    // No-op — GC reclaims the FileState и its buffer when handle is dropped.
    return TRUE;
}

extern "C" BOOL PAL_LOADMarkSectionAsNotNeeded(void* /*ptr*/)
{
    // Hint that a PE section's pages are no longer needed (e.g. reloc table
    // after relocations applied). No-op for us — memory stays committed
    // until GC sweep.
    return TRUE;
}

// Per-call trace: one serial line per heap op.
//   [crt] <fn>(0x<arg>) c1=0x<caller> c2=0x<caller2> => 0x<result>
// c1 is the immediate caller (typically libcmtd's operator new for malloc),
// c2 is the caller-of-caller (the CoreCLR site that did `new T()`).
//
// SHARPOS_HEAP_TRACE=1 — print every call (verbose, baseline debugging).
// SHARPOS_HEAP_TRACE=0 — silent (when chasing higher-level events like
// TypeLoad/EH where per-malloc noise drowns the signal).
#ifndef SHARPOS_HEAP_TRACE
#define SHARPOS_HEAP_TRACE 0
#endif
static inline void trace_heap_call(const char* fn, uint64_t caller, uint64_t caller2,
                                   uint64_t arg, uint64_t result)
{
#if SHARPOS_HEAP_TRACE
    SharpOSHost_DebugPrint("[crt] ");
    SharpOSHost_DebugPrint(fn);
    SharpOSHost_DebugPrint("(0x");
    SharpOSHost_DebugPrintHex(arg);
    SharpOSHost_DebugPrint(") c1=0x");
    SharpOSHost_DebugPrintHex(caller);
    SharpOSHost_DebugPrint(" c2=0x");
    SharpOSHost_DebugPrintHex(caller2);
    SharpOSHost_DebugPrint(" => 0x");
    SharpOSHost_DebugPrintHex(result);
    SharpOSHost_DebugPrint("\n");
#else
    (void)fn; (void)caller; (void)caller2; (void)arg; (void)result;
#endif
}

extern "C" void* malloc(size_t size)
{
    uint64_t c1 = (uint64_t)__builtin_return_address(0);
    uint64_t c2 = (uint64_t)__builtin_return_address(1);
    void* p = SharpOSHost_HeapAlloc(size);
    trace_heap_call("malloc", c1, c2, size, (uint64_t)p);
    return p;
}
extern "C" void  free(void* p)
{
    uint64_t c1 = (uint64_t)__builtin_return_address(0);
    uint64_t c2 = (uint64_t)__builtin_return_address(1);
    SharpOSHost_HeapFree(p);
    trace_heap_call("free", c1, c2, (uint64_t)p, 0);
}
extern "C" void* realloc(void* old, size_t s)
{
    uint64_t c1 = (uint64_t)__builtin_return_address(0);
    uint64_t c2 = (uint64_t)__builtin_return_address(1);
    void* p = SharpOSHost_HeapRealloc(old, s);
    trace_heap_call("realloc", c1, c2, s, (uint64_t)p);
    return p;
}
extern "C" void* calloc(size_t n, size_t sz)
{
    size_t total = n * sz;
    uint64_t c1 = (uint64_t)__builtin_return_address(0);
    uint64_t c2 = (uint64_t)__builtin_return_address(1);
    void* p = SharpOSHost_HeapAlloc(total);
    if (p) {
        char* c = (char*)p;
        for (size_t i = 0; i < total; i++) c[i] = 0;
    }
    trace_heap_call("calloc", c1, c2, total, (uint64_t)p);
    return p;
}

// __imp_<name> data symbols — IAT thunks override. CoreCLR code emitted
// `call qword ptr [__imp_malloc]` for dllimport-declared CRT functions.
// We provide __imp_<name> as a data pointer to our function; /FORCE:MULTIPLE
// picks ours over ucrt.lib's IAT thunk (which points to unloaded DLL).
extern "C" void* (*__imp_malloc)(size_t)        = &malloc;
extern "C" void  (*__imp_free)(void*)            = &free;
extern "C" void* (*__imp_calloc)(size_t, size_t) = &calloc;
extern "C" void* (*__imp_realloc)(void*, size_t) = &realloc;

// ---------------------------------------------------------------------------
// __atomic_compare_exchange_16: clang emits builtin для 16-byte CAS.
// clang_rt.builtins-x86_64.lib on Windows не provides — implement via
// MSVC `_InterlockedCompareExchange128` intrinsic (lock cmpxchg16b).
// ---------------------------------------------------------------------------
#include <intrin.h>

extern "C" bool __atomic_compare_exchange_16(
    void *ptr, void *expected, __int64 desired_lo, __int64 desired_hi,
    bool /*weak*/, int /*success_memorder*/, int /*failure_memorder*/)
{
    return _InterlockedCompareExchange128(
        (__int64 volatile *)ptr, desired_hi, desired_lo,
        (__int64 *)expected) != 0;
}

// ---------------------------------------------------------------------------
// SharpOSHost_RunCxxCtors — bootstrap C++ static initializers.
//
// CoreCLR (C++) is full of globals with constructors. MSVC linker places
// pointers к ctor functions в `.CRT` section в region $XCA..$XCZ. Normal
// programs run них via __scrt_initialize_crt called from mainCRTStartup.
//
// SharpOS kernel entry is `EfiMain`, не mainCRTStartup — __scrt_initialize_crt
// never runs. C++ globals stay zero-init → vtables empty → first virtual
// call crashes (HW #PF on instruction fetch from .rdata).
//
// This helper walks $XCA..$XCZ manually and invokes each ctor. Called
// from kernel C# code (via SharpOSHost_RunCxxCtors C-ABI) BEFORE first
// coreclr_initialize call.
//
// Pragma trick: declare sentinel pointers $XCA + $XCZ. Linker sorts CRT
// section by suffix alphabetically — ours bracket all $XCC, $XCL, $XCU
// entries contributed by other .obj files.

#pragma section(".CRT$XIA", read)
#pragma section(".CRT$XIZ", read)
#pragma section(".CRT$XCA", read)
#pragma section(".CRT$XCZ", read)
typedef void (__cdecl *_PVFV)(void);
typedef int  (__cdecl *_PIFV)(void);  // C init callbacks return int (error code)

__declspec(allocate(".CRT$XIA")) _PIFV __xi_a_sentinel[] = { nullptr };
__declspec(allocate(".CRT$XIZ")) _PIFV __xi_z_sentinel[] = { nullptr };
__declspec(allocate(".CRT$XCA")) _PVFV __xc_a_sentinel[] = { nullptr };
__declspec(allocate(".CRT$XCZ")) _PVFV __xc_z_sentinel[] = { nullptr };

// Diagnostic globals — kernel C# code reads these через
// SharpOSHost_GetCtorDiag to see how far walker got before fault.
extern "C" volatile int g_SharpOSHost_XiPhase = 0;     // -1 = entry, count = how many called
extern "C" volatile int g_SharpOSHost_XcPhase = 0;     // -1 = entry, count = how many called
extern "C" volatile uint64_t g_SharpOSHost_LastCtorAddr = 0;  // last ptr value we tried to call

// Optional limit для bisecting failing ctor — kernel C# probe sets via
// SharpOSHost_SetCtorLimit. 0 = no limit (run все).
extern "C" volatile int g_SharpOSHost_CtorLimit = 0;

// Skip mask — bitmask of ctor indices (1-based, capped at 64) to SKIP.
// E.g. bit 3 set → skip ctor 4 (the 4th).
extern "C" volatile uint64_t g_SharpOSHost_CtorSkipMask = 0;

extern "C" void SharpOSHost_SetCtorLimit(int limit)
{
    g_SharpOSHost_CtorLimit = limit;
}

extern "C" void SharpOSHost_SetCtorSkipMask(uint64_t mask)
{
    g_SharpOSHost_CtorSkipMask = mask;
}

extern "C" void SharpOSHost_RunCxxCtors()
{
    int total_so_far = 0;
    int limit = g_SharpOSHost_CtorLimit;
    uint64_t skip = g_SharpOSHost_CtorSkipMask;

    // Phase 1: C initialization ($XIA..$XIZ).
    g_SharpOSHost_XiPhase = 0;
    for (_PIFV *p = __xi_a_sentinel; p < __xi_z_sentinel; ++p)
    {
        if (*p != nullptr) {
            if (limit > 0 && total_so_far >= limit) return;
            total_so_far++;
            if (total_so_far <= 64 && (skip & (1ULL << (total_so_far - 1)))) {
                // skip this one
            } else {
                g_SharpOSHost_LastCtorAddr = (uint64_t)(*p);
                (void)(*p)();
            }
            g_SharpOSHost_XiPhase = total_so_far;
        }
    }

    // Phase 2: C++ constructors ($XCA..$XCZ).
    g_SharpOSHost_XcPhase = 0;
    for (_PVFV *p = __xc_a_sentinel; p < __xc_z_sentinel; ++p)
    {
        if (*p != nullptr) {
            if (limit > 0 && total_so_far >= limit) return;
            total_so_far++;
            if (total_so_far <= 64 && (skip & (1ULL << (total_so_far - 1)))) {
                // skip
            } else {
                g_SharpOSHost_LastCtorAddr = (uint64_t)(*p);
                (*p)();
            }
            g_SharpOSHost_XcPhase = total_so_far;
        }
    }
}

// Diagnostic accessor — kernel C# probe calls this AFTER fault to learn
// how many ctors ran successfully и which address был current.
extern "C" void SharpOSHost_GetCtorDiag(int* xiPhase, int* xcPhase, uint64_t* lastAddr)
{
    if (xiPhase != nullptr) *xiPhase = g_SharpOSHost_XiPhase;
    if (xcPhase != nullptr) *xcPhase = g_SharpOSHost_XcPhase;
    if (lastAddr != nullptr) *lastAddr = g_SharpOSHost_LastCtorAddr;
}

// Diagnostic — expose .CRT$XCA/XCZ sentinel addresses + first few ctor
// pointers so kernel C# probe can inspect WITHOUT calling them.
extern "C" void SharpOSHost_GetCtorTable(
    uint64_t* xiAStart, uint64_t* xiZEnd,
    uint64_t* xcAStart, uint64_t* xcZEnd,
    uint64_t* firstFive)
{
    if (xiAStart) *xiAStart = (uint64_t)__xi_a_sentinel;
    if (xiZEnd)   *xiZEnd   = (uint64_t)__xi_z_sentinel;
    if (xcAStart) *xcAStart = (uint64_t)__xc_a_sentinel;
    if (xcZEnd)   *xcZEnd   = (uint64_t)__xc_z_sentinel;
    if (firstFive) {
        // Just dump first 5 pointer values starting at $XCA sentinel.
        _PVFV* p = __xc_a_sentinel;
        for (int i = 0; i < 5; i++) {
            firstFive[i] = (uint64_t)p[i];
        }
    }
}
