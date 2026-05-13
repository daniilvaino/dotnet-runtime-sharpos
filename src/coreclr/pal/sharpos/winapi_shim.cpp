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
bool InsertThreadIntoAsyncSafeMap(uint64_t, void*)
{
    return false;
}

void RemoveThreadFromAsyncSafeMap(uint64_t, void*)
{
}

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
