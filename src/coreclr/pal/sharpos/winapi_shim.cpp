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
