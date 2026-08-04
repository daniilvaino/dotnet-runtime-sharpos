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

// CRT allocators live in winapi_shim.cpp. Declared here rather than pulled in
// via <stdlib.h>, whose declarations conflict with the stubs below; the ucrtbase
// GetProcAddress branch hands these out to Interop.Ucrtbase.
extern "C" void* malloc(size_t size);
extern "C" void  free(void* p);
extern "C" void* calloc(size_t n, size_t sz);
extern "C" void* realloc(void* old, size_t s);

// Per-thread LastError via gs:[0x68] (NT_TIB.LastErrorValue). clang-cl
// intrinsics __readgsdword / __writegsdword are inline-expanded only
// when <intrin.h> is included -- but that header transitively pulls
// in <stdlib.h>/<stdio.h>, whose declarations conflict with our
// CRT_STUB-emitted forward decls (atoi/strtod/perror/etc., signatureless
// `extern "C" void NAME()`).
//
// Workaround: tiny inline GCC-style asm. clang-cl accepts __asm__
// even in MSVC-compat mode. Offset is hardcoded 0x68 (no parameter
// substitution needed here -- only one user).
static inline uint32_t sharpos_gs_read_lasterr() {
    uint32_t v;
    __asm__ volatile ("mov %%gs:0x68, %0" : "=r"(v));
    return v;
}
static inline void sharpos_gs_write_lasterr(uint32_t v) {
    __asm__ volatile ("mov %0, %%gs:0x68" : : "r"(v) : "memory");
}

// Forwards to host-side diagnostic (defined в OS/src/PAL/SharpOSHost/
// Diagnostics.cs). Weak fallback for coreclr.dll smoke build target.
extern "C" __attribute__((weak)) void SharpOSHost_DebugPrint(const char* /*msg*/) {}
extern "C" __attribute__((weak)) void SharpOSHost_DebugPrintHex(uint64_t /*v*/) {}
extern "C" __attribute__((weak)) void SharpOSHost_Panic(const char* /*msg*/) {}
extern "C" __attribute__((weak)) void SharpOSHost_DebugWrite(const void* /*buf*/, int32_t /*len*/) {}
// Always-on diagnostic (ignores Verbose). Use sparingly — only for missing-import
// surfaces (P/Invoke / QCALL) that must surface even with silent kernel.
extern "C" __attribute__((weak)) void SharpOSHost_DebugPrintForced(const char* /*msg*/) {}

// Forwards к host-side heap (defined в CrtHeapStubs.cs). Used by HeapAlloc
// и HeapFree real impls below. Weak fallback для coreclr.dll smoke target.
extern "C" __attribute__((weak)) void* SharpOSHost_HeapAlloc(size_t /*size*/) { return nullptr; }
extern "C" __attribute__((weak)) void  SharpOSHost_HeapFree(void* /*ptr*/) {}
extern "C" __attribute__((weak)) void  SharpOSHost_CreateGuid(void* /*guid16*/) {}
extern "C" __attribute__((weak)) void  SharpOSHost_FillRandom(void* /*buf*/, int /*n*/) {}
extern "C" __attribute__((weak)) void  SharpOSHost_RegisterStaticFunctionTable(
    uint64_t /*base*/, void* /*funcTable*/, uint32_t /*count*/) {}
extern "C" __attribute__((weak)) uint32_t SharpOSHost_GetFullPathName(const wchar_t* /*in*/, uint32_t /*nBuf*/, wchar_t* /*out*/) { return 0; }
extern "C" __attribute__((weak)) void* SharpOSHost_FileOpen(const wchar_t* /*path*/) { return nullptr; }
extern "C" __attribute__((weak)) int SharpOSHost_FileRead(void* /*h*/, void* /*buf*/, uint32_t /*n*/, uint32_t* /*read*/) { return 0; }
extern "C" __attribute__((weak)) uint32_t SharpOSHost_FileGetSize(void* /*h*/) { return 0xFFFFFFFFu; }
extern "C" __attribute__((weak)) int64_t SharpOSHost_FileSetPosition(void* /*h*/, int64_t /*dist*/, uint32_t /*origin*/) { return -1; }
extern "C" __attribute__((weak)) void SharpOSHost_FileClose(void* /*h*/) {}

// Phase E9.a — threading PAL bridge. Defined in OS/src/PAL/SharpOSHost/
// ThreadStubs.cs (kernel-side). Weak fallbacks for the standalone
// coreclr.dll smoke target keep the symbols resolvable; in the SharpOS
// kernel image the strong managed exports win and these are dropped.
extern "C" __attribute__((weak)) uint64_t SharpOSHost_CreateThread(void* /*startAddr*/, void* /*param*/, uint32_t /*creationFlags*/, uint32_t* /*tid*/) { return 0; }
extern "C" __attribute__((weak)) uint32_t SharpOSHost_ResumeThread(uint64_t /*h*/) { return 0; }
extern "C" __attribute__((weak)) void     SharpOSHost_ExitThread(uint32_t /*code*/) { for (;;) __asm__ volatile("hlt"); }
extern "C" __attribute__((weak)) uint32_t SharpOSHost_GetCurrentThreadId() { return 1; }
extern "C" __attribute__((weak)) void*    SharpOSHost_GetCurrentThread() { return (void*)(intptr_t)-2; }
extern "C" __attribute__((weak)) uint32_t SharpOSHost_WaitForSingleObject(uint64_t /*h*/, uint32_t /*ms*/) { return 0; }
extern "C" __attribute__((weak)) uint32_t SharpOSHost_WaitForMultipleObjects(uint32_t /*n*/, uint64_t* /*h*/, int /*all*/, uint32_t /*ms*/) { return 0xFFFFFFFFu; }
extern "C" __attribute__((weak)) uint32_t SharpOSHost_GetLogicalDrives(void) { return 4u; }
extern "C" __attribute__((weak)) int      SharpOSHost_GetVolumeInformation(uint32_t* /*s*/, uint32_t* /*m*/, uint32_t* /*f*/) { return 0; }
extern "C" __attribute__((weak)) int      SharpOSHost_EnumProcesses(uint32_t* /*p*/) { return 0; }
extern "C" __attribute__((weak)) int      SharpOSHost_AmsiNotifyOperation(void) { return 0; }
extern "C" __attribute__((weak)) uint32_t SharpOSHost_GetDriveType(int /*c*/) { return 3; }
extern "C" __attribute__((weak)) uint32_t SharpOSHost_FindDirEntry(const uint8_t* /*p*/, uint32_t /*i*/, wchar_t* /*o*/, uint32_t /*c*/, uint32_t* /*a*/, uint32_t* /*s*/) { return 0; }
extern "C" __attribute__((weak)) uint32_t SharpOSHost_GetEnvVar(const uint8_t* /*n*/, int32_t /*nl*/, uint8_t* /*o*/, uint32_t /*c*/, uint32_t* outErr) { if (outErr) *outErr = 203; return 0; }
extern "C" __attribute__((weak)) int      SharpOSHost_CloseHandle(uint64_t /*h*/) { return 1; }
extern "C" __attribute__((weak)) void     SharpOSHost_Sleep(uint32_t /*ms*/) {}
extern "C" __attribute__((weak)) int      SharpOSHost_SwitchToThread() { return 1; }

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

// __acrt_iob_func — real impl below (returns fake stream for fprintf chain)
// __stdio_common_v* — real impls below (silent no-op; CoreCLR uses these
// only for diagnostic log lines we don't surface).
CRT_STUB(_atoi64)
// _callnewh — real impl below (Release operator-new failure path).
CRT_STUB(_dup)
// _errno — real impl below (returns ptr to global errno)
CRT_STUB(_fdopen)
// _fileno — real impl below (resolves our fake FILE* sentinels to 0/1/2)
// _flushall — real impl below (no-op, return 0)
// _invalid_parameter_noinfo — real impl below (no-op return)
CRT_STUB(_setmode)
// _strdup — real impl below (malloc + copy)
CRT_STUB(_stricmp)
CRT_STUB(_time64)
// _wassert — real impl below (print + continue, not fatal)
CRT_STUB(_wcsicmp)
// _wcstoui64 — real impl below (GC config INT parse: HeapHardLimit etc.)
CRT_STUB(_wfopen)
// _write — real impl below (POSIX write to fd; surfaces fd 1/2 to console)
// acos..tanh, ceil/floor/fmod/trunc/log*/exp*/pow*/sin*/cos*/sqrt* —
// compact libm below (non-fatal: trap-stub panicked the BCL on first
// internal call, e.g. `log` during string/Number init). Algebraic ones
// exact; transcendental ~1e-9. Real high-accuracy libm is a later pillar.
// acos acosf acosh acoshf — libm below
// asin asinf asinh asinhf — libm below
// atan atan2 atan2f atanf atanh atanhf — libm below
CRT_STUB(atoi)
CRT_STUB(atol)
// bsearch — real impl below (used by LoadNativeStringResource)
// cbrt cbrtf ceil ceilf cos cosf cosh coshf exp expf — libm below
CRT_STUB(fclose)
// fflush — real impl below (no-op)
CRT_STUB(fgets)
// floor floorf fmod fmodf — libm below
CRT_STUB(fopen)
CRT_STUB(fopen_s)
// fputs — real impl below (surface to console)
CRT_STUB(fseek)
CRT_STUB(ftell)
// fwrite — real impl below (surface to console)
CRT_STUB(getenv)
// ilogbf — libm below
// isalpha/isdigit/isprint/isspace/iswprint/iswspace/iswupper — real impls below
// towlower — real impl below
CRT_STUB(ldiv)
// log log10 log10f log2 log2f logf modf modff — libm below
CRT_STUB(perror)
// pow powf — libm below
// qsort — real impl below (Lomuto-partition recursive qsort).
CRT_STUB(setvbuf)
// sin sinf sinh sinhf sqrt sqrtf — libm below
// strlen / strnlen / strcmp / strncmp / strcpy / strncpy / strcpy_s /
// strncpy_s / strcat / strcat_s / strncat_s / strpbrk — real impls below
CRT_STUB(strtod)
CRT_STUB(strtok_s)
CRT_STUB(strtoul)
// strtoull — real impl below (shared sharpos_str2u64 with _wcstoui64)
// tan tanf tanh tanhf — libm below
// towlower — real impl below
// trunc truncf — libm below
// wcslen / wcsnlen / wcscmp / wcsncmp / wcscpy_s / wcsncpy_s /
// wcscat_s / wcsncat_s — real impls below
CRT_STUB(wcstoul)

// --- Win32 imports (kernel32.dll / advapi32.dll / user32.dll / ole32.dll) ---
// Same trap mechanism — name printed на first call, then Panic.
// Generated from llvm-readobj --coff-imports filtered to non-CRT DLLs.

// AcquireSRWLockExclusive — real impl below
// AdjustTokenPrivileges - real impl below (step126)
CRT_STUB(CancelIoEx)
// CloseHandle — real impl below (no-op for our fake handles)
// CoCreateGuid — real impl below (rdtsc-mixed pseudo-random v4 GUID)
// CoTaskMemAlloc / CoTaskMemFree — real impls below (step126.10)
CRT_STUB(ConnectNamedPipe)
// CreateEventW — real impl below (single-thread fake handle)
CRT_STUB(CreateFileA)
// CreateFileMappingA/W — real impl below (wraps FileState as mapping handle)
CRT_STUB(CreateFileMappingA)
// CreateFileW — real impl below (forwarder to Platform.FileReadAll via SharpOSHost)
// CreateNamedPipeA — real impl below (always fails: DiagnosticServer disabled)
CRT_STUB(CreateProcessW)
// CreateSemaphoreExW — real impl below (single-thread fake handle)
// CreateThread — real impl below (fake handle; thread function never runs)
// DebugBreak — CoreCLR `_DbgBreak()` macro expands to this. In a real
// Windows env this would trap to attached debugger; we have none.
// Pre-E9.a we kept CRT_STUB (halt) but that was OK only because fake
// threading never tripped Debug asserts. Real threading exposes hot
// _ASSERTE paths -- halting on first hit is useless. Log caller RIP
// and CONTINUE; lets us see which assert fires and whether the runtime
// survives it. Accepts the risk that continuing past a violated
// invariant may cause downstream weirdness -- that's the diagnostic
// signal we want.
//
// CRT_REAL is defined later in the file; expand it inline here so the
// __imp_ alias is emitted at the same point as the function body.
extern "C" void DebugBreak() {
    SharpOSHost_DebugPrint("[DbgBrk] caller=0x");
    SharpOSHost_DebugPrintHex((uint64_t)__builtin_return_address(0));
    SharpOSHost_DebugPrint("\n");
    // no halt
}
extern "C" void* __imp_DebugBreak = (void*)&DebugBreak;
// DecodePointer — real impl below
// DeleteCriticalSection — real impl below
CRT_STUB(DisconnectNamedPipe)
// DuplicateHandle — real impl below (returns same handle)
// EncodePointer — real impl below
// EnterCriticalSection — real impl below
CRT_STUB(ExitProcess)
// ExitThread — real impl below (no-op, can't actually terminate single-thread)
CRT_STUB(FlushFileBuffers)
// FlushInstructionCache — real impl below (no-op on coherent x86/x64 I-cache)
// FlushProcessWriteBuffers — real impl below (no-op: single-core / no
// background managed threads on bring-up; SMP would need an IPI barrier).
// NtQuerySystemInformation — real impl below (ntdll P/Invoke from
// DateTime leap-second check via reflection-mode System.Text.Json).
// FormatMessageW — real impl below (used by SString::FormatMessage +
// EEException::GetResourceMessage to substitute %1..%9 args into
// mscorrc templates). Step103d.
// FreeEnvironmentStringsW — real impl below
// FreeLibrary — real impl below (no-op; we don't load DLLs)
// GetCPInfo / GetCommandLineW / GetConsoleOutputCP — real impls below
// GetCurrentProcess / GetCurrentProcessId / GetCurrentThread /
// GetCurrentThreadId — real impls below
// GetEnabledXStateFeatures — real impl below
// GetEnvironmentStringsW / GetEnvironmentVariableA / GetEnvironmentVariableW —
// real impls below (no env → all return 0 or null)
CRT_STUB(GetExitCodeProcess)
// GetFileSize — real impl below (forwarder to SharpOSHost_FileGetSize)
// GetFullPathNameW — real impl below (forwarder to BCL System.IO.Path.GetFullPath)
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
// GetStdHandle — real impl below (step126 console facade)
// GetSystemInfo — real impl below
// GetSystemTime — real impl below
// GetSystemTimeAsFileTime — real impl below
CRT_STUB(GetThreadContext)
// GetThreadGroupAffinity — real impl below
// GetThreadPriority — real impl below (returns THREAD_PRIORITY_NORMAL)
// GetTickCount64 — real impl below
// GetTokenInformation - real impl below (step126)
CRT_STUB(GetWriteWatch)
// GlobalMemoryStatusEx — real impl below (plausible defaults for GC sizing)
// HeapAlloc / HeapCreate / HeapDestroy / HeapFree — real impls below
// InitializeCriticalSection — real impl below
// IsDebuggerPresent — real impl below
// IsProcessInJob — real impl below
// IsProcessorFeaturePresent — real impl below
CRT_STUB(K32GetProcessMemoryInfo)
// LeaveCriticalSection — real impl below
// LoadLibraryExW — real impl below (returns NULL + ERROR_MOD_NOT_FOUND)
CRT_STUB(LoadStringW)
// LocalFree — real impl below (forwards to SharpOSHost_HeapFree, paired with LocalAlloc)
// LookupPrivilegeValueW - real impl below (step126)
// MapViewOfFile — real impl below (returns the file's in-memory buffer)
// MapViewOfFileEx — real impl below (ignores base hint, returns buf+offset)
// MultiByteToWideChar — real impl below (ASCII identity fast path)
// OpenProcessToken - real impl below (step126)
// OpenThreadToken - real impl below (step126)
// OutputDebugStringA/W — real impls below (silent no-op; no debugger attached)
// QueryInformationJobObject — real impl below
// QueryPerformanceCounter / QueryPerformanceFrequency — real impls below
CRT_STUB(QueryThreadCycleTime)
CRT_STUB(QueueUserAPC)
CRT_STUB(RaiseException)
// RaiseFailFastException — real impl below (print + continue, non-fatal)
// ReadFile — real impl below (forwarder to SharpOSHost_FileRead)
CRT_STUB(ReadProcessMemory)
// RegCloseKey / RegOpenKeyExW / RegQueryValueExW — real impls below
// (step125 forwarders to SharpOSHost_Reg* in C# kernel).
// RegEnumKeyExW / RegEnumValueW / RegQueryInfoKeyW / RegCreateKeyExW /
// RegFlushKey — also real impls (no CRT_STUB record was needed; advapi32
// SDK provides them so linker resolves either way).
// ReleaseSRWLockExclusive — real impl below
// ReleaseSemaphore — real impl below (no-op)
// ResetEvent — real impl below (no-op)
CRT_STUB(ResetWriteWatch)
// ResumeThread — real impl below (no-op, returns prev suspend count 0)
// RevertToSelf - real impl below (step126)
// RtlCaptureContext — real impl below (naked asm, captures GP regs + flags)
// RtlDeleteFunctionTable / RtlInstallFunctionTableCallback — real impls below
// RtlLookupFunctionEntry / RtlVirtualUnwind — implemented C#-side
// (SehUnwind.cs, Phase 6.1.b SEH port). Re-emit CRT_STUB so __imp_NAME
// data pointer aliases exist для IAT-style indirect calls (`call rsi`
// where rsi was loaded from __imp_RtlVirtualUnwind). /FORCE:MULTIPLE
// picks the C# function definition (OS.obj first in link order); fork's
// trap body is dead, only the __imp_ alias matters.
CRT_STUB(RtlLookupFunctionEntry)
CRT_STUB(RtlRestoreContext)
CRT_STUB(RtlUnwind)
CRT_STUB(RtlVirtualUnwind)
// SetEnvironmentVariableW - real impl below (step126.5)
// SetEvent — real impl below (no-op)
// SetFilePointer — real impl below (forwarder to SharpOSHost_FileSetPosition)
// SetLastError — real impl below
CRT_STUB(SetThreadContext)
// SetThreadErrorMode — real impl below (no-op, success)
// SetThreadPriority — real impl below (no-op success)
CRT_STUB(SetThreadToken)
CRT_STUB(SetUnhandledExceptionFilter)
CRT_STUB(SignalObjectAndWait)
// Sleep / SleepEx / SwitchToThread — real impl below (Phase E9.a, routed
// to SharpOSHost_Sleep / SharpOSHost_SwitchToThread).
// SleepConditionVariableSRW — real impl below
// TerminateProcess — real impl below (no-op; would otherwise tear kernel down)
CRT_STUB(UnhandledExceptionFilter)
// UnmapViewOfFile — real impl below (no-op; GC reclaims when handle dropped)
// VirtualAlloc — real impl below (routed to SharpOSHost_HeapAlloc for kernel)
CRT_STUB(VirtualAllocExNuma)
// VirtualFree — real impl below (no-op; SharpOS GC reclaims)
// VirtualProtect — real impl below (no-op; SharpOS doesn't enforce page-level W^X)
// VirtualQuery — real impl below (returns plausible MEMORY_BASIC_INFORMATION)
CRT_STUB(VirtualUnlock)
// WaitForMultipleObjects[Ex] — real impl below (returns WAIT_OBJECT_0)
// WaitForSingleObject[Ex] — real impl below (returns WAIT_OBJECT_0)
// WakeAllConditionVariable — real impl below
// WideCharToMultiByte — real impl below (ASCII identity fast path)
// WriteFile — real impl below (step126 console facade, std-handle route)

// --- Real impls (replace traps as we discover them empirically) ---
//
// Macro for symbol pair: function NAME + __imp_NAME data pointing to it.
#define CRT_REAL(NAME) extern "C" void* __imp_##NAME = (void*)&NAME

// _callnewh: MSVC CRT new-handler invoker. The Release operator-new
// failure path calls it (Debug took a different path, so this only
// surfaced under -Configuration Release). Returns nonzero if a new
// handler was registered and wants the allocation retried; 0 otherwise.
// We don't support _set_new_handler, so return 0 -- operator new then
// fails normally (throws bad_alloc / returns null) instead of trapping.
extern "C" int _callnewh(size_t /*size*/) { return 0; }
CRT_REAL(_callnewh);

// ─── Compact libm (non-fatal replacement for the trap-stubs) ────────────
// CoreCLR/BCL calls C math internally (e.g. `log` during string/Number
// init) — the trap-stub panicked. Algebraic fns exact; transcendental
// ~1e-9 (exp/log), sin/cos single-const reduction (fine for typical
// args). NOT a high-accuracy libm — that's a later pillar; this just
// keeps real programs running for the coverage map.
namespace {
union DBits { double d; unsigned long long u; };
static double lm_trunc(double x){
    if(x!=x) return x;
    if(!(x>-9.007199254740992e15 && x<9.007199254740992e15)) return x;
    long long i=(long long)x; return (double)i;
}
static double lm_floor(double x){ double t=lm_trunc(x); return (t>x)?t-1.0:t; }
static double lm_ceil (double x){ double t=lm_trunc(x); return (t<x)?t+1.0:t; }
static double lm_fabs (double x){ DBits v; v.d=x; v.u&=0x7FFFFFFFFFFFFFFFULL; return v.d; }
static double lm_fmod (double x,double y){ if(y==0.0) return (x-x)/(y-y); return x - lm_trunc(x/y)*y; }
static double lm_ldexp(double x,int e){
    if(x==0.0||x!=x) return x; DBits v; v.d=x;
    long long ex=(long long)((v.u>>52)&0x7FF)+e;
    if(ex<=0) return x*0.0; if(ex>=0x7FF) return x*1e308*1e308;
    v.u=(v.u & ~(0x7FFULL<<52)) | ((unsigned long long)ex<<52); return v.d;
}
static double lm_exp(double x){
    if(x!=x) return x;
    if(x>709.78) return 1e308*1e308; if(x<-745.13) return 0.0;
    double k=lm_trunc(x*1.4426950408889634 + (x>=0?0.5:-0.5));
    double r=x - k*0.6931471805599453;
    double p=1.0+r*(1.0+r*(0.5+r*(0.16666666666666666+r*(0.041666666666666664
            +r*(0.008333333333333333+r*0.001388888888888889)))));
    return lm_ldexp(p,(int)k);
}
static double lm_log(double x){
    if(x!=x) return x;
    if(x<0.0) return (x-x)/0.0;
    if(x==0.0) return -1e308*1e308;
    DBits v; v.d=x;
    long long e=(long long)((v.u>>52)&0x7FF)-1023;
    v.u=(v.u & 0x000FFFFFFFFFFFFFULL) | (1023ULL<<52);
    double f=v.d; if(f>1.4142135623730951){ f*=0.5; e+=1; }
    double t=(f-1.0)/(f+1.0), t2=t*t;
    double s=2.0*t*(1.0+t2*(0.3333333333333333+t2*(0.2+t2*(0.14285714285714285
            +t2*(0.1111111111111111+t2*0.09090909090909091)))));
    return (double)e*0.6931471805599453 + s;
}
static double lm_pow(double x,double y){
    if(y==0.0||x==1.0) return 1.0;
    if(x==0.0) return (y>0.0)?0.0:1e308*1e308;
    if(x>0.0) return lm_exp(y*lm_log(x));
    double yt=lm_trunc(y); if(yt!=y) return (x-x)/0.0;
    double m=lm_exp(y*lm_log(-x)); return ((long long)yt & 1)? -m : m;
}
static void lm_sc(double x,double*ps,double*pc){
    double k=lm_trunc(x*0.6366197723675814 + (x>=0?0.5:-0.5));
    double r=x - k*1.5707963267948966, r2=r*r;
    double s=r*(1.0+r2*(-0.16666666666666666+r2*(0.008333333333333333
            +r2*(-0.0001984126984126984+r2*2.755731922398589e-06))));
    double c=1.0+r2*(-0.5+r2*(0.041666666666666664
            +r2*(-0.001388888888888889+r2*2.48015873015873e-05)));
    long long q=((long long)k)&3; if(q<0) q+=4;
    switch(q){ case 0:*ps=s;*pc=c;break; case 1:*ps=c;*pc=-s;break;
               case 2:*ps=-s;*pc=-c;break; default:*ps=-c;*pc=s;break; }
}
static double lm_sin(double x){ double s,c; lm_sc(x,&s,&c); return s; }
static double lm_cos(double x){ double s,c; lm_sc(x,&s,&c); return c; }
static double lm_tan(double x){ double s,c; lm_sc(x,&s,&c); return s/c; }
// NB: must NOT use __builtin_sqrt here. In a Debug (/Od) build clang-cl
// does not lower __builtin_sqrt to the sqrtsd instruction -- it emits a
// `call sqrt`, which lands in our own sqrt() stub below (line ~446),
// which calls lm_sqrt() again -> infinite mutual recursion -> 1 MiB
// stack overflow -> #PF -> #DF -> triple fault. Surfaced step112-followup
// SYM-002 (ThreadPool hill-climbing Complex.Abs -> Math.Sqrt was the
// first heavy libc-path sqrt consumer). Emit sqrtsd directly so there is
// never a library call back into sqrt().
static double lm_sqrt(double x){
    double r;
    __asm__ ("sqrtsd %1, %0" : "=x"(r) : "x"(x));
    return r;
}
static double lm_atan(double x){
    int neg=0,inv=0; if(x<0){x=-x;neg=1;} if(x>1.0){x=1.0/x;inv=1;}
    double x2=x*x;
    double a=x*(1.0+x2*(-0.3333333333333333+x2*(0.2+x2*(-0.14285714285714285
            +x2*(0.1111111111111111+x2*(-0.09090909090909091+x2*0.07692307692))))));
    if(inv) a=1.5707963267948966-a; return neg?-a:a;
}
static double lm_asin(double x){ if(x>=1.0)return 1.5707963267948966; if(x<=-1.0)return -1.5707963267948966; return lm_atan(x/lm_sqrt(1.0-x*x)); }
static double lm_acos(double x){ return 1.5707963267948966 - lm_asin(x); }
static double lm_atan2(double y,double x){
    if(x>0.0) return lm_atan(y/x);
    if(x<0.0) return lm_atan(y/x) + (y>=0.0?3.141592653589793:-3.141592653589793);
    return (y>0.0)?1.5707963267948966:(y<0.0?-1.5707963267948966:0.0);
}
static double lm_sinh(double x){ double e=lm_exp(x); return (e-1.0/e)*0.5; }
static double lm_cosh(double x){ double e=lm_exp(x); return (e+1.0/e)*0.5; }
static double lm_tanh(double x){ if(x>20.0)return 1.0; if(x<-20.0)return -1.0; double e=lm_exp(2.0*x); return (e-1.0)/(e+1.0); }
static double lm_cbrt(double x){ if(x==0.0)return 0.0; double s=x<0?-1.0:1.0; return s*lm_exp(lm_log(s*x)*0.3333333333333333); }
}
extern "C" double trunc (double x){ return lm_trunc(x); }   CRT_REAL(trunc);
extern "C" double floor (double x){ return lm_floor(x); }   CRT_REAL(floor);
extern "C" double ceil  (double x){ return lm_ceil(x);  }   CRT_REAL(ceil);
extern "C" double fmod  (double x,double y){ return lm_fmod(x,y);} CRT_REAL(fmod);
extern "C" double exp   (double x){ return lm_exp(x);   }   CRT_REAL(exp);
extern "C" double log   (double x){ return lm_log(x);   }   CRT_REAL(log);
extern "C" double log2  (double x){ return lm_log(x)*1.4426950408889634; } CRT_REAL(log2);
extern "C" double log10 (double x){ return lm_log(x)*0.4342944819032518; } CRT_REAL(log10);
extern "C" double pow   (double x,double y){ return lm_pow(x,y);} CRT_REAL(pow);
extern "C" double sin   (double x){ return lm_sin(x);   }   CRT_REAL(sin);
extern "C" double cos   (double x){ return lm_cos(x);   }   CRT_REAL(cos);
extern "C" double tan   (double x){ return lm_tan(x);   }   CRT_REAL(tan);
extern "C" double sqrt  (double x){ return lm_sqrt(x);  }   CRT_REAL(sqrt);
extern "C" double atan  (double x){ return lm_atan(x);  }   CRT_REAL(atan);
extern "C" double atan2 (double y,double x){ return lm_atan2(y,x);} CRT_REAL(atan2);
extern "C" double asin  (double x){ return lm_asin(x);  }   CRT_REAL(asin);
extern "C" double acos  (double x){ return lm_acos(x);  }   CRT_REAL(acos);
extern "C" double sinh  (double x){ return lm_sinh(x);  }   CRT_REAL(sinh);
extern "C" double cosh  (double x){ return lm_cosh(x);  }   CRT_REAL(cosh);
extern "C" double tanh  (double x){ return lm_tanh(x);  }   CRT_REAL(tanh);
extern "C" double cbrt  (double x){ return lm_cbrt(x);  }   CRT_REAL(cbrt);
extern "C" double acosh (double x){ return lm_log(x+lm_sqrt(x*x-1.0)); } CRT_REAL(acosh);
extern "C" double asinh (double x){ return lm_log(x+lm_sqrt(x*x+1.0)); } CRT_REAL(asinh);
extern "C" double atanh (double x){ return 0.5*lm_log((1.0+x)/(1.0-x)); } CRT_REAL(atanh);
extern "C" double modf  (double x,double* ip){ double t=lm_trunc(x); *ip=t; return x-t; } CRT_REAL(modf);
extern "C" float  truncf(float x){ return (float)lm_trunc(x); }   CRT_REAL(truncf);
extern "C" float  floorf(float x){ return (float)lm_floor(x); }   CRT_REAL(floorf);
extern "C" float  ceilf (float x){ return (float)lm_ceil(x);  }   CRT_REAL(ceilf);
extern "C" float  fmodf (float x,float y){ return (float)lm_fmod(x,y);} CRT_REAL(fmodf);
extern "C" float  expf  (float x){ return (float)lm_exp(x);   }   CRT_REAL(expf);
extern "C" float  logf  (float x){ return (float)lm_log(x);   }   CRT_REAL(logf);
extern "C" float  log2f (float x){ return (float)(lm_log(x)*1.4426950408889634); } CRT_REAL(log2f);
extern "C" float  log10f(float x){ return (float)(lm_log(x)*0.4342944819032518); } CRT_REAL(log10f);
extern "C" float  powf  (float x,float y){ return (float)lm_pow(x,y);} CRT_REAL(powf);
extern "C" float  sinf  (float x){ return (float)lm_sin(x);   }   CRT_REAL(sinf);
extern "C" float  cosf  (float x){ return (float)lm_cos(x);   }   CRT_REAL(cosf);
extern "C" float  tanf  (float x){ return (float)lm_tan(x);   }   CRT_REAL(tanf);
extern "C" float  sqrtf (float x){ return (float)lm_sqrt(x);  }   CRT_REAL(sqrtf);
extern "C" float  atanf (float x){ return (float)lm_atan(x);  }   CRT_REAL(atanf);
extern "C" float  atan2f(float y,float x){ return (float)lm_atan2(y,x);} CRT_REAL(atan2f);
extern "C" float  asinf (float x){ return (float)lm_asin(x);  }   CRT_REAL(asinf);
extern "C" float  acosf (float x){ return (float)lm_acos(x);  }   CRT_REAL(acosf);
extern "C" float  sinhf (float x){ return (float)lm_sinh(x);  }   CRT_REAL(sinhf);
extern "C" float  coshf (float x){ return (float)lm_cosh(x);  }   CRT_REAL(coshf);
extern "C" float  tanhf (float x){ return (float)lm_tanh(x);  }   CRT_REAL(tanhf);
extern "C" float  cbrtf (float x){ return (float)lm_cbrt(x);  }   CRT_REAL(cbrtf);
extern "C" float  acoshf(float x){ return (float)lm_log(x+lm_sqrt(x*x-1.0)); } CRT_REAL(acoshf);
extern "C" float  asinhf(float x){ return (float)lm_log(x+lm_sqrt(x*x+1.0)); } CRT_REAL(asinhf);
extern "C" float  atanhf(float x){ return (float)(0.5*lm_log((1.0+x)/(1.0-x))); } CRT_REAL(atanhf);
extern "C" float  modff (float x,float* ip){ float t=(float)lm_trunc(x); *ip=t; return x-t; } CRT_REAL(modff);
extern "C" int    ilogbf(float x){ DBits v; v.d=(double)lm_fabs(x); if(v.d==0.0) return -2147483647; return (int)((v.u>>52)&0x7FF)-1023; } CRT_REAL(ilogbf);

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

// Step103d: portable binary search. Used by LoadNativeStringResource
// (nativeresources/resourcestring.cpp) to look up resource IDs in the
// compiled-in mscorrc table. No state, no allocations.
extern "C" void* bsearch(const void* key, const void* base, size_t nmemb,
                         size_t size, int (*compar)(const void*, const void*)) {
    if (!key || !base || !compar || nmemb == 0 || size == 0) return nullptr;
    const unsigned char* base_ptr = (const unsigned char*)base;
    size_t lo = 0, hi = nmemb;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const void* p = base_ptr + mid * size;
        int cmp = compar(key, p);
        if (cmp == 0) return (void*)p;
        if (cmp < 0) hi = mid;
        else lo = mid + 1;
    }
    return nullptr;
}
CRT_REAL(bsearch);

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
//
// SHARPOS_REAL_TRACE=1 — print every call. Default 0 — too noisy for
// higher-level signal chasing (TypeLoad, EH). Flip on when validating
// new stub coverage.
#ifndef SHARPOS_REAL_TRACE
#define SHARPOS_REAL_TRACE 0
#endif
static inline void trace_real(const char* fn, uint64_t caller)
{
#if SHARPOS_REAL_TRACE
    SharpOSHost_DebugPrint("[real] ");
    SharpOSHost_DebugPrint(fn);
    SharpOSHost_DebugPrint(" caller=0x");
    SharpOSHost_DebugPrintHex(caller);
    SharpOSHost_DebugPrint("\n");
#else
    (void)fn; (void)caller;
#endif
}

#define TRACE_REAL(NAME) trace_real(#NAME, (uint64_t)__builtin_return_address(0))

extern "C" long long SharpOSHost_GetUtcFileTime(void);
extern "C" int QueryPerformanceCounter(int64_t* out) {
    TRACE_REAL(QueryPerformanceCounter);
    // Tie QPC to the host's real 100ns clock so timing-sensitive BCL paths
    // (Stopwatch.GetTimestamp, ProcessorIdCache.ProcessorNumberSpeedCheck,
    //  SpinWait, TimerQueue scheduling) observe forward progress.
    // QueryPerformanceFrequency reports 10_000_000 below, matching FILETIME's
    // 100ns resolution exactly. Monotonic by construction (UTC FILETIME).
    if (out) *out = (int64_t)SharpOSHost_GetUtcFileTime();
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
    // Real-time milliseconds since boot (FILETIME / 10_000 = ms since 1601;
    // monotonicity is what callers care about, absolute origin doesn't).
    return (uint64_t)SharpOSHost_GetUtcFileTime() / 10000ULL;
}
CRT_REAL(GetTickCount64);

// step 73 — wall clock bridged to the kernel CMOS RTC. Was: write 0 →
// DateTime.UtcNow == 1601-01-01. Now: FILETIME / SYSTEMTIME from CMOS
// (treated as UTC — bare metal has no tz DB). Weak fallback (winapi_shim)
// returns 0 / leaves zero-fill if the kernel export is absent.
extern "C" long long SharpOSHost_GetUtcFileTime(void);
extern "C" void SharpOSHost_GetSystemTime(unsigned short* out8);

extern "C" void GetSystemTimeAsFileTime(void* out) {
    TRACE_REAL(GetSystemTimeAsFileTime);
    if (out) *(uint64_t*)out = (uint64_t)SharpOSHost_GetUtcFileTime();
}
CRT_REAL(GetSystemTimeAsFileTime);

// GetSystemTimePreciseAsFileTime -- Win8+ variant returning a higher-
// resolution FILETIME. We don't have sub-CMOS-tick resolution on
// SharpOS yet (the kernel.Rtc resolves to seconds); forward to the
// coarse variant. BCL accepts the lower precision.
extern "C" void GetSystemTimePreciseAsFileTime(void* out) {
    TRACE_REAL(GetSystemTimePreciseAsFileTime);
    if (out) *(uint64_t*)out = (uint64_t)SharpOSHost_GetUtcFileTime();
}
CRT_REAL(GetSystemTimePreciseAsFileTime);

// SetThreadDescription -- Win10+ thread naming API. SharpOS has no
// thread-description registry; ignore. Returns success (S_OK).
extern "C" int32_t SetThreadDescription(void* /*hThread*/, const wchar_t* /*lpThreadDescription*/) {
    TRACE_REAL(SetThreadDescription);
    return 0;
}
CRT_REAL(SetThreadDescription);

extern "C" void GetSystemTime(void* out) {
    TRACE_REAL(GetSystemTime);
    if (out) {
        uint16_t* p = (uint16_t*)out;
        for (int i = 0; i < 8; i++) p[i] = 0;
        SharpOSHost_GetSystemTime((unsigned short*)p);
    }
}
CRT_REAL(GetSystemTime);

extern "C" void* GetCurrentProcess(void)      { TRACE_REAL(GetCurrentProcess);   return (void*)(intptr_t)-1; }
CRT_REAL(GetCurrentProcess);
extern "C" void* GetCurrentThread(void)       { TRACE_REAL(GetCurrentThread);    return SharpOSHost_GetCurrentThread(); }
CRT_REAL(GetCurrentThread);
extern "C" uint32_t GetCurrentProcessId(void) { TRACE_REAL(GetCurrentProcessId); return 1; }
CRT_REAL(GetCurrentProcessId);
extern "C" uint32_t GetCurrentThreadId(void)  { TRACE_REAL(GetCurrentThreadId);  return SharpOSHost_GetCurrentThreadId(); }
CRT_REAL(GetCurrentThreadId);

// step111-followup: PortableThreadPool.WorkerThread.IsIOPending P/Invokes
// this on the worker-exit path (ShouldExitWorker -> IsIOPending). Without
// a stub the P/Invoke resolution throws EntryPointNotFoundException on a
// background ThreadPool worker thread; no catch above worker root frame
// means uncaught propagation -> kernel HALT during shutdown. We don't
// actually track per-thread IO, so always report "no IO pending" -- the
// worker proceeds to its normal exit logic. Out-param is Win32 BOOL
// (4 bytes); return value is BOOL too.
extern "C" int GetThreadIOPendingFlag(void* /*hThread*/, int* lpIOIsPending) {
    if (lpIOIsPending) *lpIOIsPending = 0; // FALSE
    return 1; // TRUE = success
}
CRT_REAL(GetThreadIOPendingFlag);

// Phase E9.b step 102 -- per-thread LastError via TEB+0x68
// (NT_TIB.LastErrorValue, sage-2 add per docs/threading-architecture.md
// §12). Pre-E9.b LastError was a single global -- on multi-thread
// CoreCLR (E9.a+) two threads racing through PAL calls could clobber
// each other's error. NT_TIB at offset 0x68 is the canonical Win32
// per-thread last-error slot; BCL P/Invoke marshalers and the CRT
// already assume this layout.
//
// All 144 g_LastError write-sites elsewhere in this file go through
// this proxy struct's operator= so the textual signature stays the
// same (literally `g_LastError = X`). Read-sites likewise unchanged.
//
// gs base is set up by CoreClrProbe.SetupTebFacade (boot thread) and
// CoreClrTeb.Allocate (per-hosted-thread) BEFORE any CRT call enters
// from CoreCLR, so the gs:[0x68] access is safe at all of them.
// Initial value is 0 -- GcHeap.AllocateRaw zeroes the TEB box.
struct LastErrorRef {
    operator uint32_t() const { return sharpos_gs_read_lasterr(); }
    LastErrorRef& operator=(uint32_t v) {
        sharpos_gs_write_lasterr(v);
        return *this;
    }
};
static LastErrorRef g_LastError;

extern "C" uint32_t GetLastError(void)  { /* TRACE_REAL too noisy */ return sharpos_gs_read_lasterr(); }
CRT_REAL(GetLastError);
extern "C" void SetLastError(uint32_t e) { sharpos_gs_write_lasterr(e); }
CRT_REAL(SetLastError);

extern "C" int IsDebuggerPresent(void) { TRACE_REAL(IsDebuggerPresent); return 0; }
CRT_REAL(IsDebuggerPresent);

// QueryUnbiasedInterruptTime — Win32 monotonic counter (100-ns ticks).
// "Unbiased" = excludes sleep time. ThreadPool.Timer uses this for
// wait deadlines. Each call advances by 1 ms equivalent so the runtime
// sees monotone progress. Placed after g_LastError decl (line ~835).
extern "C" int QueryUnbiasedInterruptTime(uint64_t* out) {
    // Tie to host UTC FILETIME (100-ns, HPET-mixed for sub-second res) so
    // TimerQueue.TickCount64 and other consumers observe true elapsed time
    // rather than a per-call counter that breaks SpinWait/timeout math.
    if (out) *out = (uint64_t)SharpOSHost_GetUtcFileTime();
    g_LastError = 0;
    return 1;
}
CRT_REAL(QueryUnbiasedInterruptTime);

// GetCurrentProcessorNumberEx — fills PROCESSOR_NUMBER struct (Group:USHORT,
// Number:UCHAR, Reserved:UCHAR). Single-CPU kernel → group 0, number 0.
extern "C" void GetCurrentProcessorNumberEx(void* procNum) {
    if (procNum) {
        uint8_t* p = (uint8_t*)procNum;
        p[0] = 0; p[1] = 0;  // Group = 0
        p[2] = 0;            // Number = 0
        p[3] = 0;            // Reserved
    }
}
CRT_REAL(GetCurrentProcessorNumberEx);

// --- Diagnostic surface helpers ---

static void diag_print_ascii_w(const wchar_t* s) {
    if (!s) { SharpOSHost_DebugPrint("(null)"); return; }
    char buf[2] = { 0, 0 };
    for (const wchar_t* p = s; *p; p++) {
        wchar_t wc = *p;
        if ((wc >= 0x20 && wc < 0x7F) || wc == '\n' || wc == '\t' || wc == '\r') {
            buf[0] = (char)wc;
            SharpOSHost_DebugPrint(buf);
        } else {
            SharpOSHost_DebugPrint("?");
        }
    }
}

// Minimal printf-style format engine. Handles %d %i %u %x %X %p %s %S %c %%
// and 'l'/'ll' length prefixes. Skips numeric width/precision specifiers
// (cosmetic). Used to render CoreCLR diagnostic messages with their args
// expanded so we see what assertion fired / what module loaded / etc.
//
// On x64 Windows va_list = char* pointing to 8-byte aligned arg slots.
// Each slot consumed sequentially regardless of arg type width.
static void diag_format(const char* fmt, void* va) {
    if (!fmt) { SharpOSHost_DebugPrint("(null fmt)"); return; }
    uintptr_t* args = (uintptr_t*)va;
    char buf[2] = { 0, 0 };
    while (*fmt) {
        if (*fmt != '%') {
            buf[0] = *fmt++;
            SharpOSHost_DebugPrint(buf);
            continue;
        }
        fmt++;
        // Skip flags (- + space # 0) and width/precision digits + '.'
        while (*fmt == '-' || *fmt == '+' || *fmt == ' ' || *fmt == '#' ||
               *fmt == '0' || *fmt == '.' || (*fmt >= '1' && *fmt <= '9'))
            fmt++;
        // Length prefix
        bool isLongLong = false;
        bool isLong = false;
        if (*fmt == 'l' && fmt[1] == 'l') { isLongLong = true; fmt += 2; }
        else if (*fmt == 'l') { isLong = true; fmt++; }
        else if (*fmt == 'I' && fmt[1] == '6' && fmt[2] == '4') { isLongLong = true; fmt += 3; }
        else if (*fmt == 'z' || *fmt == 't' || *fmt == 'j') { isLongLong = true; fmt++; }
        char c = *fmt++;
        if (c == 0) break;
        switch (c) {
            case '%': SharpOSHost_DebugPrint("%"); break;
            case 'd': case 'i': {
                int64_t v;
                if (isLongLong) v = (int64_t)*args++;
                else            v = (int32_t)(uintptr_t)*args++;
                if (v < 0) { SharpOSHost_DebugPrint("-"); v = -v; }
                char d[24]; int n = 0;
                if (v == 0) d[n++] = '0';
                else while (v && n < 24) { d[n++] = (char)('0' + (v % 10)); v /= 10; }
                while (n > 0) { buf[0] = d[--n]; SharpOSHost_DebugPrint(buf); }
                break;
            }
            case 'u': {
                uint64_t v;
                if (isLongLong) v = (uint64_t)*args++;
                else            v = (uint32_t)(uintptr_t)*args++;
                char d[24]; int n = 0;
                if (v == 0) d[n++] = '0';
                else while (v && n < 24) { d[n++] = (char)('0' + (v % 10)); v /= 10; }
                while (n > 0) { buf[0] = d[--n]; SharpOSHost_DebugPrint(buf); }
                break;
            }
            case 'x': case 'X': case 'p': {
                uint64_t v;
                if (c == 'p' || isLongLong) v = (uint64_t)*args++;
                else                        v = (uint32_t)(uintptr_t)*args++;
                if (c == 'p') SharpOSHost_DebugPrint("0x");
                SharpOSHost_DebugPrintHex(v);
                break;
            }
            case 's': {
                const char* s = (const char*)*args++;
                if (s) SharpOSHost_DebugPrint(s); else SharpOSHost_DebugPrint("(null)");
                break;
            }
            case 'S': case 'w': {  // wide string
                const wchar_t* s = (const wchar_t*)*args++;
                diag_print_ascii_w(s);
                break;
            }
            case 'c': {
                buf[0] = (char)(uintptr_t)*args++;
                SharpOSHost_DebugPrint(buf);
                break;
            }
            default:
                // unknown conversion - skip slot to stay synced
                args++;
                buf[0] = c;
                SharpOSHost_DebugPrint("%");
                SharpOSHost_DebugPrint(buf);
                break;
        }
        (void)isLong; // unused for now; reserved
    }
}

// --- stdio_common_v* family ---
//
// CoreCLR (Debug build) routes printf/sprintf/fprintf through these UCRT
// internals. We share the `diag_format` format vocabulary (see above)
// but write to the caller's buffer. Without a real impl here the CRT
// "Undefined resource string ID:0x?" cascade hides every diagnostic
// string CoreCLR tries to emit — see docs/pal-minimal-audit.md.
//
// Supports: %d %i %u %x %X %p %s %S %c %% + l/ll/I64/z/t/j length
//           prefixes; skips numeric width/precision (cosmetic). Stays
//           within bufCount; always NUL-terminates; returns chars
//           written (NOT including NUL). Caller passes va_list as
//           `void*` pointing at the first 8-byte stack slot (x64
//           Windows convention; matches CoreCLR call sites).
static int vsnprintf_impl(char* buffer, size_t bufCount, const char* fmt, void* va) {
    if (!buffer || bufCount == 0) return 0;
    if (!fmt) { buffer[0] = 0; return 0; }
    uintptr_t* args = (uintptr_t*)va;
    size_t w = 0;
    auto put_ch = [&](char c) {
        if (w + 1 < bufCount) buffer[w++] = c;
    };
    auto put_str = [&](const char* s) {
        if (!s) { for (const char* k = "(null)"; *k; ++k) put_ch(*k); return; }
        for (; *s; ++s) put_ch(*s);
    };
    auto put_wstr_ascii = [&](const wchar_t* s) {
        if (!s) { for (const char* k = "(null)"; *k; ++k) put_ch(*k); return; }
        for (; *s; ++s) {
            wchar_t wc = *s;
            if ((wc >= 0x20 && wc < 0x7F) || wc == '\n' || wc == '\t' || wc == '\r')
                put_ch((char)wc);
            else
                put_ch('?');
        }
    };
    auto put_dec = [&](int64_t v, bool sgn) {
        if (sgn && v < 0) { put_ch('-'); v = -v; }
        uint64_t u = (uint64_t)v;
        char d[24]; int n = 0;
        if (u == 0) d[n++] = '0';
        else while (u && n < 24) { d[n++] = (char)('0' + (u % 10)); u /= 10; }
        while (n > 0) put_ch(d[--n]);
    };
    auto put_hex = [&](uint64_t v, bool upper) {
        char d[18]; int n = 0;
        if (v == 0) d[n++] = '0';
        else while (v && n < 18) {
            int nib = (int)(v & 0xF);
            d[n++] = (char)(nib < 10 ? '0' + nib : (upper ? 'A' : 'a') + nib - 10);
            v >>= 4;
        }
        while (n > 0) put_ch(d[--n]);
    };
    while (*fmt) {
        if (*fmt != '%') { put_ch(*fmt++); continue; }
        fmt++;
        while (*fmt == '-' || *fmt == '+' || *fmt == ' ' || *fmt == '#' ||
               *fmt == '0' || *fmt == '.' || (*fmt >= '1' && *fmt <= '9'))
            fmt++;
        bool isLongLong = false;
        if (*fmt == 'l' && fmt[1] == 'l') { isLongLong = true; fmt += 2; }
        else if (*fmt == 'l') { fmt++; }
        else if (*fmt == 'I' && fmt[1] == '6' && fmt[2] == '4') { isLongLong = true; fmt += 3; }
        else if (*fmt == 'z' || *fmt == 't' || *fmt == 'j') { isLongLong = true; fmt++; }
        char c = *fmt++;
        if (c == 0) break;
        switch (c) {
            case '%': put_ch('%'); break;
            case 'd': case 'i': {
                int64_t v = isLongLong ? (int64_t)*args : (int64_t)(int32_t)(uintptr_t)*args;
                ++args; put_dec(v, true); break;
            }
            case 'u': {
                uint64_t v = isLongLong ? (uint64_t)*args : (uint64_t)(uint32_t)(uintptr_t)*args;
                ++args; put_dec((int64_t)v, false); break;
            }
            case 'x': case 'X': case 'p': {
                uint64_t v = (c == 'p' || isLongLong) ? (uint64_t)*args
                                                     : (uint64_t)(uint32_t)(uintptr_t)*args;
                ++args;
                if (c == 'p') { put_ch('0'); put_ch('x'); put_hex(v, true); }
                else          { put_hex(v, c == 'X'); }
                break;
            }
            case 's': { const char* s = (const char*)*args++; put_str(s); break; }
            case 'S': case 'w': { const wchar_t* s = (const wchar_t*)*args++; put_wstr_ascii(s); break; }
            case 'c': { put_ch((char)(uintptr_t)*args++); break; }
            default:
                ++args;
                put_ch('%'); put_ch(c);
                break;
        }
    }
    buffer[w] = 0;
    return (int)w;
}

extern "C" int __stdio_common_vsprintf(uint64_t /*options*/, char* buffer, size_t bufCount, const char* format, void* /*locale*/, void* args) {
    return vsnprintf_impl(buffer, bufCount, format, args);
}
CRT_REAL(__stdio_common_vsprintf);

extern "C" int __stdio_common_vsprintf_s(uint64_t /*options*/, char* buffer, size_t bufCount, const char* format, void* /*locale*/, void* args) {
    return vsnprintf_impl(buffer, bufCount, format, args);
}
CRT_REAL(__stdio_common_vsprintf_s);

extern "C" int __stdio_common_vsnprintf_s(uint64_t /*options*/, char* buffer, size_t bufCount, size_t /*maxCount*/, const char* format, void* /*locale*/, void* args) {
    return vsnprintf_impl(buffer, bufCount, format, args);
}
CRT_REAL(__stdio_common_vsnprintf_s);

extern "C" int __stdio_common_vfprintf(uint64_t /*options*/, void* /*stream*/, const char* format, void* /*locale*/, void* args) {
    // stream-printf: format to a stack buffer, surface to console.
    char tmp[1024];
    int n = vsnprintf_impl(tmp, sizeof(tmp), format, args);
    if (n > 0) SharpOSHost_DebugWrite(tmp, n);
    return n;
}
CRT_REAL(__stdio_common_vfprintf);

extern "C" int __stdio_common_vsscanf(uint64_t /*options*/, const char* /*input*/, size_t /*count*/, const char* /*format*/, void* /*locale*/, void* /*args*/) {
    TRACE_REAL(__stdio_common_vsscanf);
    return 0;  // 0 conversions matched
}
CRT_REAL(__stdio_common_vsscanf);

// --- Plain stdio path (Debug builds may bypass UCRT and call these directly) ---

extern "C" int puts(const char* s) {
    SharpOSHost_DebugPrint("[puts] ");
    if (s) SharpOSHost_DebugPrint(s); else SharpOSHost_DebugPrint("(null)");
    SharpOSHost_DebugPrint("\n");
    return 1;
}
CRT_REAL(puts);

extern "C" int fputs(const char* s, void* /*stream*/) {
    SharpOSHost_DebugPrint("[fputs] ");
    if (s) SharpOSHost_DebugPrint(s); else SharpOSHost_DebugPrint("(null)");
    SharpOSHost_DebugPrint("\n");
    return 0;
}
CRT_REAL(fputs);

extern "C" int fputws(const wchar_t* s, void* /*stream*/) {
    SharpOSHost_DebugPrint("[fputws] ");
    diag_print_ascii_w(s);
    SharpOSHost_DebugPrint("\n");
    return 0;
}
CRT_REAL(fputws);

extern "C" size_t fwrite(const void* p, size_t sz, size_t n, void* /*stream*/) {
    SharpOSHost_DebugPrint("[fwrite ");
    SharpOSHost_DebugPrintHex(sz * n);
    SharpOSHost_DebugPrint("b] ");
    if (p && sz == 1) {
        const char* s = (const char*)p;
        char buf[2] = { 0, 0 };
        for (size_t i = 0; i < n; i++) {
            char c = s[i];
            if (c == 0) break;
            buf[0] = ((c >= 0x20 && c < 0x7F) || c == '\n' || c == '\t') ? c : '?';
            SharpOSHost_DebugPrint(buf);
        }
    }
    SharpOSHost_DebugPrint("\n");
    return n;
}
CRT_REAL(fwrite);

extern "C" int fflush(void* /*stream*/) { return 0; }
CRT_REAL(fflush);

// __acrt_iob_func — UCRT helper that returns FILE* for stdin(0)/stdout(1)/
// stderr(2). Caller hands FILE* to fprintf/fputs. Our fprintf doesn't look
// at the stream pointer (just prints to console) so any unique non-NULL
// suffices. Returning &k_iob_slots[id] gives a stable distinct addr per id.
static uintptr_t k_iob_slots[3] = { 0xF11E1, 0xF11E2, 0xF11E3 };  // sentinel "FILE" bytes
extern "C" void* __acrt_iob_func(unsigned id) {
    if (id > 2) id = 2;
    return &k_iob_slots[id];
}
CRT_REAL(__acrt_iob_func);

// _fileno — return numeric file descriptor for FILE*. Recognize our three
// iob sentinels (stdin/stdout/stderr → 0/1/2); anything else → -1.
extern "C" int _fileno(void* stream) {
    if (stream == &k_iob_slots[0]) return 0;
    if (stream == &k_iob_slots[1]) return 1;
    if (stream == &k_iob_slots[2]) return 2;
    return -1;
}
CRT_REAL(_fileno);

// _write — POSIX write(fd, buf, count). This is a real output path, not a
// diagnostic one: PowerShell writes to stderr through it, escape sequences
// included. It used to replace every byte outside printable ASCII with '?'
// and add a "[_write fd=N] " tag plus a newline, which turned the colour reset
// "ESC[m" into "?m" — the opening "ESC[91m" went out through WriteConsoleW
// intact, so the console stayed red from the first stderr message onward.
// Forward the bytes verbatim to the same console sink WriteFile uses.
// Both are defined further down; declared here so this stays above them.
extern "C" uint64_t SharpOSHost_GetStdHandle(int nStdHandle);
extern "C" int      SharpOSHost_ConsoleWriteFile(uint64_t hHandle, const unsigned char* buffer,
                                                 uint32_t nBytes, uint32_t* numBytesWritten);

extern "C" int _write(int fd, const void* buf, unsigned int count) {
    if (fd != 1 && fd != 2) return -1;
    if (!buf || count == 0) return 0;
    uint64_t h = SharpOSHost_GetStdHandle(fd == 2 ? -12 : -11);
    uint32_t written = 0;
    SharpOSHost_ConsoleWriteFile(h, (const unsigned char*)buf, count, &written);
    return (int)count;
}
CRT_REAL(_write);

// --- Abort path neutralization ---
//
// CoreCLR assertions (e.g. EventPipe lock checks that fail under our
// single-thread + fake-handle model) cascade through _wassert → abort
// → _flushall → TerminateProcess. We want EE to keep going so we can see
// the NEXT empirical wall. Each of these becomes a print-and-continue
// no-op. Assertions still print их text via _CrtDbgReportW / vsprintf_s
// path so we know what fired.

extern "C" void _wassert(const wchar_t* msg, const wchar_t* file, unsigned line) {
    SharpOSHost_DebugPrint("[_wassert] ");
    diag_print_ascii_w(msg);
    SharpOSHost_DebugPrint(" @ ");
    diag_print_ascii_w(file);
    SharpOSHost_DebugPrint(":");
    SharpOSHost_DebugPrintHex(line);
    SharpOSHost_DebugPrint("\n");
    // Return — caller continues. CoreCLR assertion was logical, not fatal.
}
CRT_REAL(_wassert);

// _wcstoui64 / strtoull — real impls. GC config INT knobs (HeapHardLimit,
// RegionRange, RegionSize) parsed from our coreclr_initialize string props
// ("0x4000000" etc.) via _wcstoui64. base==0 → autodetect 0x/0/dec; base 16
// accepts optional 0x. endptr set to first unparsed char (may be NULL).
namespace {
template <typename CH>
unsigned long long sharpos_str2u64(const CH* p, CH** endptr, int base) {
    if (p == nullptr) { if (endptr) *endptr = (CH*)p; return 0; }
    const CH* s = p;
    while (*s == (CH)' ' || *s == (CH)'\t' || *s == (CH)'\n' || *s == (CH)'\r') s++;
    bool neg = false;
    if (*s == (CH)'+' ) s++;
    else if (*s == (CH)'-') { neg = true; s++; }
    if ((base == 0 || base == 16) &&
        s[0] == (CH)'0' && (s[1] == (CH)'x' || s[1] == (CH)'X')) { s += 2; base = 16; }
    else if (base == 0 && s[0] == (CH)'0') { base = 8; }
    else if (base == 0) { base = 10; }
    unsigned long long acc = 0; bool any = false;
    for (;; s++) {
        CH c = *s; int d;
        if (c >= (CH)'0' && c <= (CH)'9') d = (int)(c - (CH)'0');
        else if (c >= (CH)'a' && c <= (CH)'z') d = (int)(c - (CH)'a') + 10;
        else if (c >= (CH)'A' && c <= (CH)'Z') d = (int)(c - (CH)'A') + 10;
        else break;
        if (d >= base) break;
        acc = acc * (unsigned long long)base + (unsigned long long)d;
        any = true;
    }
    if (endptr) *endptr = (CH*)(any ? s : p);
    return neg ? (unsigned long long)(-(long long)acc) : acc;
}
} // namespace

extern "C" unsigned long long _wcstoui64(const wchar_t* s, wchar_t** endptr, int base) {
    return sharpos_str2u64<wchar_t>(s, endptr, base);
}
CRT_REAL(_wcstoui64);

extern "C" unsigned long long strtoull(const char* s, char** endptr, int base) {
    return sharpos_str2u64<char>(s, endptr, base);
}
CRT_REAL(strtoull);

extern "C" int _flushall(void) { return 0; }
CRT_REAL(_flushall);

extern "C" void _invalid_parameter_noinfo(void) {
    SharpOSHost_DebugPrint("[_invalid_parameter_noinfo]\n");
}
CRT_REAL(_invalid_parameter_noinfo);

extern "C" int TerminateProcess(void* /*hProcess*/, uint32_t exitCode) {
    uint64_t callerVA = (uint64_t)__builtin_return_address(0);
    // Route via DebugWrite (NOT Verbose-gated, unlike DebugPrint) so
    // the caller VA is always visible — TerminateProcess(0x80131506)
    // halts so we only get one shot at logging it.
    {
        SharpOSHost_DebugWrite((const void*)"[TerminateProcess code=0x", 25);
        char buf[20]; int n = 0;
        for (int sh = 28; sh >= 0; sh -= 4) {
            int nib = (int)((exitCode >> sh) & 0xF);
            buf[n++] = (char)(nib < 10 ? '0' + nib : 'A' + nib - 10);
        }
        SharpOSHost_DebugWrite((const void*)buf, n);
        SharpOSHost_DebugWrite((const void*)" caller=0x", 10);
        int n2 = 0;
        int started = 0;
        for (int sh = 60; sh >= 0; sh -= 4) {
            int nib = (int)((callerVA >> sh) & 0xF);
            if (!started && nib == 0 && sh != 0) continue;
            started = 1;
            buf[n2++] = (char)(nib < 10 ? '0' + nib : 'A' + nib - 10);
        }
        SharpOSHost_DebugWrite((const void*)buf, n2);
        SharpOSHost_DebugWrite((const void*)"]\n", 2);
    }
    // step 72 (sage): 0x80131506 == COR_E_EXECUTIONENGINE — a genuine
    // unrecoverable EE FailFast, not the EventPipe-assert→abort cascade we
    // intentionally swallow during bring-up. Continuing past it only
    // produces a post-fatal ignored-stackwalk storm that masks the real
    // result. Halt cleanly so the log ends at the FailFast.
    if (exitCode == 0x80131506u) {
        SharpOSHost_Panic("TerminateProcess(COR_E_EXECUTIONENGINE 0x80131506)");
    }
    return 1;  // pretend success; CoreCLR keeps running
}
CRT_REAL(TerminateProcess);

// RaiseFailFastException — Windows' fast-fail entrypoint, marked noreturn
// в headers. After call site the compiler emits an unconditional `int3`
// trusting it never returns. If we returned, kernel #BP-faults. Must hlt.
//
// Diagnostic value: we still print why we got here. The preceding
// assertion text is logged via _wassert/_CrtDbgReportW/printf chain — by
// the time we land here the operator already knows what fired.
extern "C" __attribute__((noreturn)) void RaiseFailFastException(void* /*pExceptionRecord*/, void* /*pContextRecord*/, uint32_t dwFlags) {
    SharpOSHost_DebugPrint("[RaiseFailFastException flags=0x");
    SharpOSHost_DebugPrintHex(dwFlags);
    SharpOSHost_DebugPrint("] HALT — CoreCLR fast-fail\n");
    SharpOSHost_Panic("RaiseFailFastException");
    for (;;) __asm__ volatile("hlt");
}
CRT_REAL(RaiseFailFastException);

// _strdup — POSIX-ish helper, allocates and copies a C string.
extern "C" char* _strdup(const char* s) {
    if (!s) return nullptr;
    size_t n = 0;
    while (s[n]) n++;
    char* d = (char*)SharpOSHost_HeapAlloc(n + 1);
    if (!d) return nullptr;
    for (size_t i = 0; i <= n; i++) d[i] = s[i];
    return d;
}
CRT_REAL(_strdup);

// MultiByteToWideChar — convert narrow → wide. We support only ASCII /
// single-byte identity mapping: each input byte zero-extended to UTF-16
// code unit. CodePage and dwFlags ignored (caller's intent is conversion
// of pure-ASCII config strings, paths, identifiers — multi-byte UTF-8
// sequences not yet seen empirically). cbMultiByte = -1 means input is
// null-terminated; we then compute length ourselves.
// Returns: char count written to lpWideCharStr, or required count if
// cchWideChar == 0 (caller's "ask for size" pattern).
extern "C" int MultiByteToWideChar(uint32_t /*CodePage*/, uint32_t /*dwFlags*/,
                                   const char* lpMultiByteStr, int cbMultiByte,
                                   wchar_t* lpWideCharStr, int cchWideChar) {
    if (lpMultiByteStr == nullptr) return 0;
    int srcLen;
    if (cbMultiByte < 0) {
        srcLen = 0;
        while (lpMultiByteStr[srcLen]) srcLen++;
        srcLen++;  // include null terminator
    } else {
        srcLen = cbMultiByte;
    }
    if (cchWideChar == 0) return srcLen;  // size query
    int writeCount = srcLen < cchWideChar ? srcLen : cchWideChar;
    for (int i = 0; i < writeCount; i++) {
        lpWideCharStr[i] = (wchar_t)(uint8_t)lpMultiByteStr[i];
    }
    return writeCount;
}
CRT_REAL(MultiByteToWideChar);

// WideCharToMultiByte — converse. Wide chars > 0xFF become '?' (lossy).
extern "C" int WideCharToMultiByte(uint32_t /*CodePage*/, uint32_t /*dwFlags*/,
                                   const wchar_t* lpWideCharStr, int cchWideChar,
                                   char* lpMultiByteStr, int cbMultiByte,
                                   const char* /*lpDefaultChar*/, int* lpUsedDefaultChar) {
    if (lpWideCharStr == nullptr) return 0;
    int srcLen;
    if (cchWideChar < 0) {
        srcLen = 0;
        while (lpWideCharStr[srcLen]) srcLen++;
        srcLen++;  // include null terminator
    } else {
        srcLen = cchWideChar;
    }
    if (cbMultiByte == 0) return srcLen;  // size query
    int writeCount = srcLen < cbMultiByte ? srcLen : cbMultiByte;
    int usedDefault = 0;
    for (int i = 0; i < writeCount; i++) {
        wchar_t wc = lpWideCharStr[i];
        if (wc > 0xFF) { lpMultiByteStr[i] = '?'; usedDefault = 1; }
        else           { lpMultiByteStr[i] = (char)wc; }
    }
    if (lpUsedDefaultChar) *lpUsedDefaultChar = usedDefault;
    return writeCount;
}
CRT_REAL(WideCharToMultiByte);

// _wcsdup — wide variant, often comes paired with _strdup.
extern "C" wchar_t* _wcsdup(const wchar_t* s) {
    if (!s) return nullptr;
    size_t n = 0;
    while (s[n]) n++;
    wchar_t* d = (wchar_t*)SharpOSHost_HeapAlloc((n + 1) * sizeof(wchar_t));
    if (!d) return nullptr;
    for (size_t i = 0; i <= n; i++) d[i] = s[i];
    return d;
}
CRT_REAL(_wcsdup);

// _errno — pointer to current-thread errno slot. Single-thread: one global.
static int g_errno = 0;
extern "C" int* _errno(void) { return &g_errno; }
CRT_REAL(_errno);

// CoCreateGuid — thin forwarder to SharpOSHost (managed side handles
// entropy + RFC 4122 v4 layout per CLAUDE.md invariant 1).
extern "C" int CoCreateGuid(void* pguid) {
    if (!pguid) return 0x80004003;  // E_POINTER
    SharpOSHost_CreateGuid(pguid);
    return 0;  // S_OK
}
CRT_REAL(CoCreateGuid);

// BCryptGenRandom — thin forwarder to SharpOSHost_FillRandom (host-side,
// CrtHeapStubs.cs). Generation logic stays in C# per CLAUDE.md invariant 1,
// same pattern as CoCreateGuid → SharpOSHost_CreateGuid. Used by
// System.HashCode / randomized string hashing / System.Text.Json for a
// hash-flood-resistant (non-cryptographic) seed. Returns STATUS_SUCCESS.
extern "C" int BCryptGenRandom(void* /*hAlgorithm*/, unsigned char* pbBuffer,
                               unsigned int cbBuffer, unsigned int /*dwFlags*/) {
    if (pbBuffer == nullptr) return (int)0xC000000DL; // STATUS_INVALID_PARAMETER
    SharpOSHost_FillRandom(pbBuffer, (int)cbBuffer);
    return 0; // STATUS_SUCCESS
}
CRT_REAL(BCryptGenRandom);

extern "C" void OutputDebugStringA(const char* s) {
    SharpOSHost_DebugPrint("[ODS-A] ");
    if (s) SharpOSHost_DebugPrint(s); else SharpOSHost_DebugPrint("(null)");
    SharpOSHost_DebugPrint("\n");
}
CRT_REAL(OutputDebugStringA);

extern "C" void OutputDebugStringW(const wchar_t* s) {
    SharpOSHost_DebugPrint("[ODS-W] ");
    diag_print_ascii_w(s);
    SharpOSHost_DebugPrint("\n");
}
CRT_REAL(OutputDebugStringW);

// --- Phase E9.b sync primitives: forwarded to kernel HandleTable ---
//
// Pre-E9.b: SharpOS treated all event/semaphore/mutex handles as opaque
// fake counters and let SetEvent/ResetEvent/ReleaseSemaphore no-op while
// WaitForSingleObject lied "signaled". That model collapses as soon as
// cross-thread signaling actually matters (Monitor.Wait/Pulse,
// ThreadPool worker wake-up, Task continuation chains).
//
// E9.b: each Create* returns a real HandleTable slot keyed to a
// kernel-side OS.Kernel.Threading.{Event,Semaphore,Win32Mutex} object;
// signal/release/wait route through Scheduler. ThreadStubs.cs already
// dispatches WaitForSingleObject by type tag via HandleTable.Lookup.
//
// Win32 SECURITY_ATTRIBUTES / lpName / DesiredAccess / Ex-flag bits
// outside the documented Create*Ex flags are ignored -- SharpOS has no
// named kernel objects, ACLs, or cross-process handles.

extern "C" uint64_t SharpOSHost_CreateEvent(int manualReset, int initialState);
extern "C" uint64_t SharpOSHost_CreateEventEx(uint32_t flags);
extern "C" int      SharpOSHost_SetEvent(uint64_t handle);
extern "C" int      SharpOSHost_ResetEvent(uint64_t handle);
extern "C" uint64_t SharpOSHost_CreateSemaphore(int32_t initial, int32_t max);
extern "C" int      SharpOSHost_ReleaseSemaphore(uint64_t handle, int32_t releaseCount, int32_t* outPrev);
extern "C" uint64_t SharpOSHost_CreateMutex(int initialOwner);
extern "C" int      SharpOSHost_ReleaseMutex(uint64_t handle);

extern "C" void* CreateEventW(void* /*lpEventAttrs*/, int bManualReset, int bInitState, const wchar_t* /*lpName*/) {
    TRACE_REAL(CreateEventW);
    uint64_t h = SharpOSHost_CreateEvent(bManualReset, bInitState);
    g_LastError = h == 0 ? 8 /*ERROR_NOT_ENOUGH_MEMORY*/ : 0;
    return (void*)(uintptr_t)h;
}
CRT_REAL(CreateEventW);

extern "C" void* CreateEventA(void* /*lpEventAttrs*/, int bManualReset, int bInitState, const char* /*lpName*/) {
    TRACE_REAL(CreateEventA);
    uint64_t h = SharpOSHost_CreateEvent(bManualReset, bInitState);
    g_LastError = h == 0 ? 8 : 0;
    return (void*)(uintptr_t)h;
}
CRT_REAL(CreateEventA);

extern "C" void* CreateEventExW(void* /*lpEventAttrs*/, const wchar_t* /*lpName*/, uint32_t dwFlags, uint32_t /*dwDesiredAccess*/) {
    TRACE_REAL(CreateEventExW);
    uint64_t h = SharpOSHost_CreateEventEx(dwFlags);
    g_LastError = h == 0 ? 8 : 0;
    return (void*)(uintptr_t)h;
}
CRT_REAL(CreateEventExW);

extern "C" void* CreateSemaphoreW(void* /*lpAttrs*/, int32_t lInitial, int32_t lMax, const wchar_t* /*lpName*/) {
    TRACE_REAL(CreateSemaphoreW);
    uint64_t h = SharpOSHost_CreateSemaphore(lInitial, lMax);
    g_LastError = h == 0 ? 8 : 0;
    return (void*)(uintptr_t)h;
}
CRT_REAL(CreateSemaphoreW);

extern "C" void* CreateSemaphoreExW(void* /*lpAttrs*/, int32_t lInitial, int32_t lMax, const wchar_t* /*lpName*/, uint32_t /*flags*/, uint32_t /*access*/) {
    TRACE_REAL(CreateSemaphoreExW);
    uint64_t h = SharpOSHost_CreateSemaphore(lInitial, lMax);
    g_LastError = h == 0 ? 8 : 0;
    return (void*)(uintptr_t)h;
}
CRT_REAL(CreateSemaphoreExW);

extern "C" void* CreateMutexW(void* /*lpAttrs*/, int bInitialOwner, const wchar_t* /*lpName*/) {
    TRACE_REAL(CreateMutexW);
    uint64_t h = SharpOSHost_CreateMutex(bInitialOwner);
    g_LastError = h == 0 ? 8 : 0;
    return (void*)(uintptr_t)h;
}
CRT_REAL(CreateMutexW);

extern "C" uint64_t SharpOSHost_OpenMutex(uint32_t* outLastError);

// OpenMutexW opens an EXISTING named mutex. PSReadLine probes with it to find
// out whether another instance already owns the terminal; kernel policy
// (MutexBridge.cs) answers "no such name", which is the truth here.
//
// This has to exist as an export even to say no: without it the P/Invoke fails
// to resolve, PSReadLine catches the resulting exception, and the catch-resume
// path used to come back with most nonvolatile registers zeroed (see the
// nonvolatile preservation in exceptionhandling.cpp).
extern "C" void* OpenMutexW(uint32_t /*dwDesiredAccess*/, int /*bInheritHandle*/,
                             const wchar_t* /*lpName*/) {
    TRACE_REAL(OpenMutexW);
    uint32_t err = 0;
    uint64_t h = SharpOSHost_OpenMutex(&err);
    g_LastError = err;
    return (void*)(uintptr_t)h;
}
CRT_REAL(OpenMutexW);

extern "C" void* OpenMutexA(uint32_t dwDesiredAccess, int bInheritHandle,
                             const char* /*lpName*/) {
    TRACE_REAL(OpenMutexA);
    return OpenMutexW(dwDesiredAccess, bInheritHandle, nullptr);
}
CRT_REAL(OpenMutexA);

extern "C" void* CreateMutexExW(void* /*lpAttrs*/, const wchar_t* /*lpName*/, uint32_t dwFlags, uint32_t /*dwDesiredAccess*/) {
    TRACE_REAL(CreateMutexExW);
    // CREATE_MUTEX_INITIAL_OWNER = 0x00000001
    int initialOwner = (dwFlags & 0x00000001) != 0 ? 1 : 0;
    uint64_t h = SharpOSHost_CreateMutex(initialOwner);
    g_LastError = h == 0 ? 8 : 0;
    return (void*)(uintptr_t)h;
}
CRT_REAL(CreateMutexExW);

extern "C" int SetEvent(void* h) {
    TRACE_REAL(SetEvent);
    int ok = SharpOSHost_SetEvent((uint64_t)(uintptr_t)h);
    g_LastError = ok ? 0 : 6 /*ERROR_INVALID_HANDLE*/;
    return ok;
}
CRT_REAL(SetEvent);

extern "C" int ResetEvent(void* h) {
    TRACE_REAL(ResetEvent);
    int ok = SharpOSHost_ResetEvent((uint64_t)(uintptr_t)h);
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(ResetEvent);

extern "C" int ReleaseSemaphore(void* h, int32_t lRelease, int32_t* lpPrev) {
    TRACE_REAL(ReleaseSemaphore);
    int ok = SharpOSHost_ReleaseSemaphore((uint64_t)(uintptr_t)h, lRelease, lpPrev);
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(ReleaseSemaphore);

extern "C" int ReleaseMutex(void* h) {
    TRACE_REAL(ReleaseMutex);
    int ok = SharpOSHost_ReleaseMutex((uint64_t)(uintptr_t)h);
    g_LastError = ok ? 0 : 288 /*ERROR_NOT_OWNER*/;
    return ok;
}
CRT_REAL(ReleaseMutex);

// --- Phase E9.c: WaitOnAddress / WakeByAddressSingle / WakeByAddressAll ---
//
// Modern .NET (4.6+) fast-path sync primitives -- ManualResetEventSlim,
// SemaphoreSlim, SpinWait, the low-level lock inside Monitor's syncblock
// fast path, ConcurrentDictionary slow path -- all spin briefly then
// fall back to WaitOnAddress instead of grabbing a kernel Event. Pre-
// E9.c the PAL had no stub (CRT trap on any call); now forwards to
// kernel-side OS.Kernel.Threading.AddressWait (bucketed wait queue
// keyed by user-memory address).
extern "C" int  SharpOSHost_WaitOnAddress(const void* addr, const void* cmpAddr, uint32_t addressSize, uint32_t timeoutMs);
extern "C" void SharpOSHost_WakeByAddressSingle(const void* addr);
extern "C" void SharpOSHost_WakeByAddressAll(const void* addr);

extern "C" int WaitOnAddress(volatile void* addr, void* cmpAddr, size_t addressSize, uint32_t timeoutMs) {
    TRACE_REAL(WaitOnAddress);
    int signaled = SharpOSHost_WaitOnAddress((const void*)addr, cmpAddr, (uint32_t)addressSize, timeoutMs);
    g_LastError = signaled ? 0 : 1460 /*ERROR_TIMEOUT*/;
    return signaled;
}
CRT_REAL(WaitOnAddress);

extern "C" void WakeByAddressSingle(void* addr) {
    TRACE_REAL(WakeByAddressSingle);
    SharpOSHost_WakeByAddressSingle(addr);
}
CRT_REAL(WakeByAddressSingle);

extern "C" void WakeByAddressAll(void* addr) {
    TRACE_REAL(WakeByAddressAll);
    SharpOSHost_WakeByAddressAll(addr);
}
CRT_REAL(WakeByAddressAll);

// Forward decl — full body around line 2306; CloseHandle below uses it to
// route DirHandle (CreateFileW BACKUP_SEMANTICS) frees through HeapFree
// rather than the kernel HandleTable.
static bool sharpos_is_dir_handle(void* h);

extern "C" int CloseHandle(void* h) {
    TRACE_REAL(CloseHandle);
    g_LastError = 0;
    if (sharpos_is_dir_handle(h)) {
        SharpOSHost_HeapFree(h);
        return 1;
    }
    return SharpOSHost_CloseHandle((uint64_t)(uintptr_t)h);
}
CRT_REAL(CloseHandle);

// Phase E9.a: routed to kernel SharpOSHost_WaitForSingleObject which
// blocks on Thread.JoinEvent / Event.Wait / Semaphore.Wait as appropriate.
// WAIT_OBJECT_0 = 0 (signaled), WAIT_FAILED = 0xFFFFFFFF.
extern "C" uint32_t WaitForSingleObject(void* h, uint32_t ms) {
    TRACE_REAL(WaitForSingleObject);
    return SharpOSHost_WaitForSingleObject((uint64_t)(uintptr_t)h, ms);
}
CRT_REAL(WaitForSingleObject);
extern "C" uint32_t WaitForSingleObjectEx(void* h, uint32_t ms, int /*alert*/) {
    TRACE_REAL(WaitForSingleObjectEx);
    return SharpOSHost_WaitForSingleObject((uint64_t)(uintptr_t)h, ms);
}
CRT_REAL(WaitForSingleObjectEx);
// step110-followup: forward single-handle WaitForMultiple* to the
// proper WaitForSingleObject path. Monitor.Wait → CLREvent.Wait →
// DoAppropriateAptStateWait → WaitForMultipleObjectsEx(1, &h, FALSE, ms, TRUE);
// pre-fix this was a stub returning 0 (=WAIT_OBJECT_0) which made the
// MRES.Wait / Task.Wait pair busy-spin forever. Multi-handle WaitAll/
// WaitAny still not implemented — falls through to WAIT_FAILED so a
// caller using it gets a clear failure instead of a silent bogus signal.
// Marshal HANDLE[] (void**, 8B each) to ulong[] for the kernel boundary,
// then delegate the actual wait-any policy to SharpOSHost_WaitForMultipleObjects.
// Stack buffer caps at MAXIMUM_WAIT_OBJECTS=64 (Win32 limit).
static uint32_t sharpos_wait_multi(uint32_t n, void* ph, int all, uint32_t ms) {
    if (n == 0 || n > 64 || ph == nullptr) return 0xFFFFFFFFu;
    if (n == 1) return SharpOSHost_WaitForSingleObject(
                          (uint64_t)(uintptr_t)(*(void**)ph), ms);
    uint64_t handles[64];
    void** src = (void**)ph;
    for (uint32_t i = 0; i < n; i++)
        handles[i] = (uint64_t)(uintptr_t)src[i];
    return SharpOSHost_WaitForMultipleObjects(n, handles, all, ms);
}

extern "C" uint32_t WaitForMultipleObjects(uint32_t n, void* ph, int all, uint32_t ms) {
    TRACE_REAL(WaitForMultipleObjects);
    return sharpos_wait_multi(n, ph, all, ms);
}
CRT_REAL(WaitForMultipleObjects);
extern "C" uint32_t WaitForMultipleObjectsEx(uint32_t n, void* ph, int all, uint32_t ms, int /*alert*/) {
    TRACE_REAL(WaitForMultipleObjectsEx);
    return sharpos_wait_multi(n, ph, all, ms);
}
CRT_REAL(WaitForMultipleObjectsEx);

// --- Threading: Phase E9.a real bridge to kernel scheduler ---
//
// Pre-E9.a these were fakes: CreateThread returned a unique handle but
// never started the thread function (CoreCLR's finalizer / EventPipe /
// GC helpers all faked). Post-E9.a CreateThread routes to
// SharpOSHost_CreateThread which spawns a real kernel.Thread via
// Scheduler.SpawnHosted; WaitForSingleObject blocks on Thread.JoinEvent;
// CloseHandle releases the kernel-side HandleTable slot.
//
// Sleep / SwitchToThread similarly bridge to Scheduler.Sleep /
// Scheduler.Yield. SleepEx delegates to Sleep (alertable wait
// extension is a no-op until APC queue lands).

extern "C" void* CreateThread(void* /*lpThreadAttrs*/, size_t /*dwStackSize*/,
                              void* lpStartAddr, void* lpParam,
                              uint32_t dwCreationFlags, uint32_t* lpThreadId) {
    TRACE_REAL(CreateThread);
    // CoreCLR (vm/threads.cpp:2145) always passes CREATE_SUSPENDED (0x4)
    // and follows with ResumeThread after post-init. dwCreationFlags is
    // forwarded so the kernel can honor it; dwStackSize stays ignored
    // (kernel uses a fixed 1 MiB host-thread stack today).
    uint64_t h = SharpOSHost_CreateThread(lpStartAddr, lpParam, dwCreationFlags, lpThreadId);
    g_LastError = 0;
    return (void*)(uintptr_t)h;
}
CRT_REAL(CreateThread);

extern "C" void Sleep(uint32_t ms) {
    TRACE_REAL(Sleep);
    SharpOSHost_Sleep(ms);
}
CRT_REAL(Sleep);

extern "C" uint32_t SleepEx(uint32_t ms, int /*alertable*/) {
    TRACE_REAL(SleepEx);
    SharpOSHost_Sleep(ms);
    return 0;   // WAIT_OBJECT_0 / non-alerted return
}
CRT_REAL(SleepEx);

extern "C" int SwitchToThread() {
    TRACE_REAL(SwitchToThread);
    return SharpOSHost_SwitchToThread();
}
CRT_REAL(SwitchToThread);

// SetThreadErrorMode — thread-local error mode (controls how Win32 errors
// propagate). No-op: we don't have a meaningful error mode mechanism on
// SharpOS. Return success with the "previous mode" set to 0.
extern "C" int SetThreadErrorMode(uint32_t /*dwNewMode*/, uint32_t* lpOldMode) {
    TRACE_REAL(SetThreadErrorMode);
    if (lpOldMode) *lpOldMode = 0;
    g_LastError = 0;
    return 1;
}
CRT_REAL(SetThreadErrorMode);

// SetThreadStackGuarantee -- Win32 API that resizes the guard-page region
// at the bottom of the calling thread's stack. CoreCLR's
// Thread::CLRSetThreadStackGuarantee invokes it from inside HasStarted
// (Debug builds always; Release on the StackOverflow setup path) to make
// room for SO EH dispatch. On SharpOS we have no guard pages today --
// stacks are flat physical pages allocated by Scheduler. Return success
// without touching anything; CoreCLR proceeds with its cached new size
// value but the next stack overflow simply pages onto a #PF without the
// extra cushion (acceptable until the Phase-E stack guard work lands).
// *pStackSizeInBytes is BOTH the requested new guard size AND the
// returned previous size; we leave it unchanged so the caller doesn't
// observe a confusing zero.
extern "C" int SetThreadStackGuarantee(uint32_t* /*pStackSizeInBytes*/) {
    TRACE_REAL(SetThreadStackGuarantee);
    g_LastError = 0;
    return 1;
}
CRT_REAL(SetThreadStackGuarantee);

// CreateFileMappingW — wrap our FileState handle as a mapping handle.
// CoreCLR uses CreateFileMapping(hFile, ...) + MapViewOfFile к load PE
// images. We already slurped the file into GcHeap buffer at FileOpen,
// so the "mapping" passes through the same FileState handle.
extern "C" void* CreateFileMappingW(void* hFile,
                                    void* /*lpFileMappingAttributes*/,
                                    uint32_t /*flProtect*/,
                                    uint32_t /*dwMaximumSizeHigh*/,
                                    uint32_t /*dwMaximumSizeLow*/,
                                    const wchar_t* /*lpName*/) {
    TRACE_REAL(CreateFileMappingW);
    if (hFile == (void*)(intptr_t)-1 || hFile == nullptr) {
        g_LastError = 6;
        return nullptr;
    }
    g_LastError = 0;
    return hFile;
}
CRT_REAL(CreateFileMappingW);

// MapViewOfFile — return FileState's buffer + offset. CoreCLR PE loader
// reads from this view as if it were a normal mapped image.
extern "C" void* MapViewOfFile(void* hMapping,
                                uint32_t /*dwDesiredAccess*/,
                                uint32_t dwFileOffsetHigh,
                                uint32_t dwFileOffsetLow,
                                size_t /*dwNumberOfBytesToMap*/) {
    TRACE_REAL(MapViewOfFile);
    if (hMapping == nullptr || hMapping == (void*)(intptr_t)-1) {
        g_LastError = 6;
        return nullptr;
    }
    uint64_t offset = ((uint64_t)dwFileOffsetHigh << 32) | dwFileOffsetLow;
    // FileState layout (CrtHeapStubs.cs): +0x00 Buffer, +0x08 Size, +0x0C Position
    void* buf = *(void**)((char*)hMapping + 0x00);
    uint32_t size = *(uint32_t*)((char*)hMapping + 0x08);
    if (offset >= size) { g_LastError = 87; return nullptr; }
    g_LastError = 0;
    return (char*)buf + offset;
}
CRT_REAL(MapViewOfFile);

// MapViewOfFileEx — same as MapViewOfFile с дополнительным lpBaseAddress
// hint. We ignore the hint и map anywhere (since "anywhere" = pointer
// inside in-memory buffer).
extern "C" void* MapViewOfFileEx(void* hMapping,
                                  uint32_t /*dwDesiredAccess*/,
                                  uint32_t dwFileOffsetHigh,
                                  uint32_t dwFileOffsetLow,
                                  size_t /*dwNumberOfBytesToMap*/,
                                  void* /*lpBaseAddress*/) {
    TRACE_REAL(MapViewOfFileEx);
    if (hMapping == nullptr || hMapping == (void*)(intptr_t)-1) {
        g_LastError = 6;
        return nullptr;
    }
    uint64_t offset = ((uint64_t)dwFileOffsetHigh << 32) | dwFileOffsetLow;
    void* buf = *(void**)((char*)hMapping + 0x00);
    uint32_t size = *(uint32_t*)((char*)hMapping + 0x08);
    if (offset >= size) { g_LastError = 87; return nullptr; }
    g_LastError = 0;
    return (char*)buf + offset;
}
CRT_REAL(MapViewOfFileEx);

extern "C" int UnmapViewOfFile(const void* /*lpBaseAddress*/) {
    TRACE_REAL(UnmapViewOfFile);
    // No-op: GC reclaims FileState and its buffer when the handle drops
    // out of liveness. Real Windows would release the VA mapping here.
    g_LastError = 0;
    return 1;
}
CRT_REAL(UnmapViewOfFile);

extern "C" int FlushViewOfFile(const void* /*lpBaseAddress*/, size_t /*dwNumberOfBytesToFlush*/) {
    TRACE_REAL(FlushViewOfFile);
    g_LastError = 0;
    return 1;
}
CRT_REAL(FlushViewOfFile);

// LoadLibrary family — CoreCLR uses LoadLibraryExW с LOAD_LIBRARY_AS_*
// flags to read managed PE images (metadata/CIL) as data, не как live
// modules. Route к our FileOpen, return buffer pointer as HMODULE so
// PE parser can walk headers directly.
//
// Real native DLL loading с DllMain / exports / relocations не поддержано —
// GetProcAddress всё ещё returns NULL. Embedded SharpOS не имеет
// external native libs.
//
// ВАЖНОЕ ИСКЛЮЧЕНИЕ — Advapi32 (ETW). System.Diagnostics.Tracing.EtwEventProvider
// делает P/Invoke в Advapi32.dll для EventRegister/EventWriteTransfer/etc.
// На bare metal Advapi32 отсутствует — обычное возвращение NULL ведёт к
// EEMessageException, которое не ловится нашим unwinder'ом на boundary с
// managed code (см. SehDispatch log). Возвращаем sentinel handle для
// Advapi32; GetProcAddress на этом handle резолвит ETW symbols в наши
// noop stubs (EventRegister=0 = ERROR_SUCCESS → ETW думает что
// зарегистрировалась, события пишутся в /dev/null).
//
// Тот же подход for другие optional Win32 dependencies which mogut поступать.

#define SHARPOS_ADVAPI32_HMODULE ((void*)(uintptr_t)0xAD7A1132U)
#define SHARPOS_SYSNATIVE_HMODULE ((void*)(uintptr_t)0x5751A71EU)
// kernel32/kernelbase/ntdll: the Windows-flavored framework P/Invokes
// these; their exports ARE statically linked into the SharpOS image
// (this very file). Sentinel handle → GetProcAddress maps names to the
// in-image stubs (sharpos_resolve_kernel32). Without this LoadLibrary
// file-loads kernel32.dll, fails, and the runtime throws DllNotFound.
#define SHARPOS_KERNEL32_HMODULE  ((void*)(uintptr_t)0x6E32116CU)
// ole32: Guid.NewGuid() P/Invokes [DllImport("ole32.dll")] CoCreateGuid.
// CoCreateGuid is statically in-image (this file). Sentinel handle →
// GetProcAddress maps CoCreateGuid to it, skipping the file LoadLibrary
// that fails on bare metal (no ole32.dll file → DllNotFound).
#define SHARPOS_OLE32_HMODULE     ((void*)(uintptr_t)0x01E32011U)
// BCrypt: System.HashCode / randomized string hashing / System.Text.Json
// P/Invoke [DllImport("BCrypt.dll")] BCryptGenRandom. In-image (this file).
#define SHARPOS_BCRYPT_HMODULE    ((void*)(uintptr_t)0x0BC39701U)
// step 99: Secur32 for Environment.UserName -> GetUserNameExW. In-image
// stub returns "local" -- SharpOS has no auth subsystem.
#define SHARPOS_SECUR32_HMODULE   ((void*)(uintptr_t)0x5EC03211U)
// step 99 pass 3: libSystem.Security.Cryptography.Native.OpenSsl --
// this fork's BCL uses the Unix-native OpenSSL surface for
// RandomNumberGenerator.Fill and SHA256.HashData even on Windows-host
// builds (System.Private.CoreLib is shared between Unix and SharpOS
// targets, and ships with libSystem.Security.Cryptography.Native.OpenSsl
// P/Invokes). We satisfy the minimal hash + RNG surface with the SHA-256
// already compiled in this file + SharpOSHost_FillRandom.
#define SHARPOS_SYSCRYPTO_HMODULE ((void*)(uintptr_t)0x5C39709AU)

// step126.2: shell32 sentinel. SHGetKnownFolderPath / SHGetFolderPathW return
// E_FAIL — managed Environment.GetFolderPathCore returns empty string on
// non-zero HRESULT, PowerShell's System.Management.Automation.Platform.cctor
// uses empty paths and continues init.
#define SHARPOS_SHELL32_HMODULE   ((void*)(uintptr_t)0x53E11320U)

// step126.4: wldp (Windows Lock Down Policy). PowerShell queries for
// AppLocker / WDAC / Constrained Language Mode policy. On bare metal
// SharpOS no policy is active — return "everything allowed".
#define SHARPOS_WLDP_HMODULE      ((void*)(uintptr_t)0x401D9011U)

// step126.9: amsi.dll (Antimalware Scan Interface). PowerShell scans
// script content before execution. Kernel returns CLEAN unconditionally.
#define SHARPOS_AMSI_HMODULE      ((void*)(uintptr_t)0xA751C0DEU)

// step126.11: user32.dll. PowerShell touches it for GetConsoleWindow,
// window styles, message handling. On unikernel there are no windows;
// stubs return null/zero/default to indicate "no window context".
#define SHARPOS_USER32_HMODULE    ((void*)(uintptr_t)0x05E32100U)
// wintrust.dll — Authenticode signature verification. PS' SystemPolicy
// calls WinVerifyTrust on pwsh.dll to decide FullLanguage vs CLM. When
// the library can't be loaded PS treats trust as "couldn't determine →
// fail-secure to ConstrainedLanguage". Sentinel + WinVerifyTrust → 0
// (ERROR_SUCCESS = verified trusted) makes PS go FullLanguage.
#define SHARPOS_WINTRUST_HMODULE  ((void*)(uintptr_t)0x05741457U)

// step126.19: mpr.dll (Multiple Provider Router) — network drive enumeration.
// iphlpapi.dll — IP Helper / network interface info. Both touched by PS at
// PSDrive automount for "network drives" / IPGlobalProperties. On unikernel
// no network providers exist; sentinel returns succeed so PS doesn't throw
// FileNotFoundException from LoadLibrary, but GetProcAddress returns null
// for any name → PS treats as "library has no exports" and skips network drives.
#define SHARPOS_MPR_HMODULE       ((void*)(uintptr_t)0x05049270U)
#define SHARPOS_IPHLPAPI_HMODULE  ((void*)(uintptr_t)0x07FE19A0U)
// ucrtbase → sentinel; the allocator entry points Interop.Ucrtbase declares
// (malloc/free/calloc/realloc/_aligned_*) are all in-image CRT functions.
// Without this Process.ProcessName throws DllNotFound out of GetProcessInfos.
#define SHARPOS_UCRTBASE_HMODULE  ((void*)(uintptr_t)0x0C271BA5U)

// Case-insensitive substring search: does `s` (UTF-16) contain ASCII `needle`?
// Used to detect API Set names like "api-ms-win-core-file-l1-1-0" anywhere
// in the path (loader may pass bare name or "\sharpos\..." prefix).
static int sharpos_wstr_icontains(const wchar_t* s, const char* needle) {
    if (s == nullptr || needle == nullptr || needle[0] == 0) return 0;
    size_t sLen = 0; while (s[sLen] != 0) sLen++;
    size_t nLen = 0; while (needle[nLen] != 0) nLen++;
    if (sLen < nLen) return 0;
    for (size_t i = 0; i + nLen <= sLen; i++) {
        int match = 1;
        for (size_t j = 0; j < nLen; j++) {
            wchar_t sc = s[i + j];
            char    tc = needle[j];
            if (sc >= L'A' && sc <= L'Z') sc = (wchar_t)(sc - L'A' + L'a');
            if (tc >= 'A' && tc <= 'Z')   tc = (char)(tc - 'A' + 'a');
            if (sc != (wchar_t)tc) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

// Case-insensitive equality of last `n` UTF-16 chars in `s` with ASCII `tail`.
static int sharpos_wstr_iends_with(const wchar_t* s, const char* tail) {
    size_t sLen = 0; while (s[sLen] != 0) sLen++;
    size_t tLen = 0; while (tail[tLen] != 0) tLen++;
    if (sLen < tLen) return 0;
    const wchar_t* sEnd = s + sLen - tLen;
    for (size_t i = 0; i < tLen; i++) {
        wchar_t sc = sEnd[i];
        char    tc = tail[i];
        if (sc >= L'A' && sc <= L'Z') sc = (wchar_t)(sc - L'A' + L'a');
        if (tc >= 'A' && tc <= 'Z')   tc = (char)(tc - 'A' + 'a');
        if (sc != (wchar_t)tc) return 0;
    }
    return 1;
}

static int sharpos_is_advapi32(const wchar_t* name) {
    if (name == nullptr) return 0;
    // Accepts: "advapi32", "advapi32.dll", "advapi32.dll.dll",
    //         "\sharpos\advapi32.dll" etc. — все варианты которые
    //         loader перебирает.
    // step126.3: also accepts Windows API Set forwarders that resolve to
    // advapi32 exports on real Windows. API set families redirected here:
    //   api-ms-win-eventing-*       → advapi32 ETW
    //   api-ms-win-security-base-*  → advapi32 token/SID
    //   api-ms-win-security-lsalookup-* → advapi32 LookupPrivilege*
    //   api-ms-win-service-*        → advapi32 service control
    // API set names are virtual — they never exist as physical DLLs.
    return sharpos_wstr_iends_with(name, "advapi32")
        || sharpos_wstr_iends_with(name, "advapi32.dll")
        || sharpos_wstr_iends_with(name, "advapi32.dll.dll")
        || sharpos_wstr_icontains(name, "api-ms-win-eventing-")
        || sharpos_wstr_icontains(name, "api-ms-win-security-base-")
        || sharpos_wstr_icontains(name, "api-ms-win-security-lsalookup-")
        || sharpos_wstr_icontains(name, "api-ms-win-security-sddl-")
        || sharpos_wstr_icontains(name, "api-ms-win-service-");
}

static int sharpos_is_kernel32(const wchar_t* name) {
    if (name == nullptr) return 0;
    // Direct: kernel32 / kernelbase / ntdll variants.
    // API sets: every "api-ms-win-core-*" forwarder resolves to kernel32
    // on real Windows. Examples: -file-, -processenvironment-, -string-,
    // -handle-, -memory-, -libraryloader-, -synch-, -threadpool-, -debug-,
    // -errorhandling-, -console-, -localization-, -processthreads-,
    // -sysinfo-, -systemtopology-, -rtlsupport-, -datetime-, -delayload-,
    // -fibers-, -heap-, -interlocked-, -io-, -kernel32-, -namedpipe-,
    // -profile-, -psapi-, -registry-, -timezone-, -url-, -util-, -version-,
    // -winrt-*, -wow64-*, ...
    // Rather than enumerate ~80 variants, match the api-ms-win-core- prefix.
    // Exclude api-ms-win-core-com-* / -winrt-* — they forward to ole32/combase
    // (caught by sharpos_is_ole32).
    if (sharpos_wstr_icontains(name, "api-ms-win-core-com-")) return 0;
    if (sharpos_wstr_icontains(name, "api-ms-win-core-winrt-")) return 0;
    return sharpos_wstr_iends_with(name, "kernel32")
        || sharpos_wstr_iends_with(name, "kernel32.dll")
        || sharpos_wstr_iends_with(name, "kernel32.dll.dll")
        || sharpos_wstr_iends_with(name, "kernelbase")
        || sharpos_wstr_iends_with(name, "kernelbase.dll")
        || sharpos_wstr_iends_with(name, "kernelbase.dll.dll")
        || sharpos_wstr_iends_with(name, "ntdll")
        || sharpos_wstr_iends_with(name, "ntdll.dll")
        || sharpos_wstr_iends_with(name, "ntdll.dll.dll")
        || sharpos_wstr_icontains(name, "api-ms-win-core-");
}

static int sharpos_is_ole32(const wchar_t* name) {
    if (name == nullptr) return 0;
    // ole32 + combase + COM-related API sets. The api-ms-win-core-com-*
    // family forwards to combase.dll on real Windows; we route them all
    // through our ole32 resolver branch.
    return sharpos_wstr_iends_with(name, "ole32")
        || sharpos_wstr_iends_with(name, "ole32.dll")
        || sharpos_wstr_iends_with(name, "ole32.dll.dll")
        || sharpos_wstr_iends_with(name, "combase")
        || sharpos_wstr_iends_with(name, "combase.dll")
        || sharpos_wstr_icontains(name, "api-ms-win-core-com-")
        || sharpos_wstr_icontains(name, "api-ms-win-core-winrt-");
}

static int sharpos_is_bcrypt(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "bcrypt")
        || sharpos_wstr_iends_with(name, "bcrypt.dll")
        || sharpos_wstr_iends_with(name, "bcrypt.dll.dll");
}

static int sharpos_is_secur32(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "secur32")
        || sharpos_wstr_iends_with(name, "secur32.dll")
        || sharpos_wstr_iends_with(name, "secur32.dll.dll");
}

static int sharpos_is_shell32(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "shell32")
        || sharpos_wstr_iends_with(name, "shell32.dll")
        || sharpos_wstr_iends_with(name, "shell32.dll.dll");
}

static int sharpos_is_wldp(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "wldp")
        || sharpos_wstr_iends_with(name, "wldp.dll")
        || sharpos_wstr_iends_with(name, "wldp.dll.dll");
}

static int sharpos_is_amsi(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "amsi")
        || sharpos_wstr_iends_with(name, "amsi.dll")
        || sharpos_wstr_iends_with(name, "amsi.dll.dll");
}

static int sharpos_is_user32(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "user32")
        || sharpos_wstr_iends_with(name, "user32.dll")
        || sharpos_wstr_iends_with(name, "user32.dll.dll");
}

static int sharpos_is_wintrust(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "wintrust")
        || sharpos_wstr_iends_with(name, "wintrust.dll")
        || sharpos_wstr_iends_with(name, "wintrust.dll.dll");
}

static int sharpos_is_mpr(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "mpr")
        || sharpos_wstr_iends_with(name, "mpr.dll")
        || sharpos_wstr_iends_with(name, "mpr.dll.dll");
}

static int sharpos_is_iphlpapi(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "iphlpapi")
        || sharpos_wstr_iends_with(name, "iphlpapi.dll")
        || sharpos_wstr_iends_with(name, "iphlpapi.dll.dll");
}

static int sharpos_is_ucrtbase(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "ucrtbase")
        || sharpos_wstr_iends_with(name, "ucrtbase.dll")
        || sharpos_wstr_iends_with(name, "ucrtbase.dll.dll");
}

static int sharpos_is_syscrypto(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "libsystem.security.cryptography.native.openssl")
        || sharpos_wstr_iends_with(name, "system.security.cryptography.native.openssl")
        || sharpos_wstr_iends_with(name, "libsystem.security.cryptography.native.openssl.dll")
        || sharpos_wstr_iends_with(name, "libsystem.security.cryptography.native.openssl.so")
        || sharpos_wstr_iends_with(name, "system.security.cryptography.native.openssl.dll");
}

// libSystem.Native — the .NET Unix native shim. Windows-built fork still
// emits Unix-flavored framework assemblies (System.Console P/Invokes
// libSystem.Native, not kernel32). The runtime's DllImport resolver tries
// many name variants ("libSystem.Native", "System.Native", "+.dll/.so").
// Sentinel handle (SHARPOS_SYSNATIVE_HMODULE, defined near ADVAPI32);
// GetProcAddress resolves SystemNative_* → our SharpOS_SN_* shims below.
static int sharpos_is_system_native(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "libsystem.native")
        || sharpos_wstr_iends_with(name, "system.native")
        || sharpos_wstr_iends_with(name, "libsystem.native.dll")
        || sharpos_wstr_iends_with(name, "system.native.dll")
        || sharpos_wstr_iends_with(name, "libsystem.native.so")
        || sharpos_wstr_iends_with(name, "libsystem.native.dll.dll");
}

extern "C" void* LoadLibraryExW(const wchar_t* lpLibFileName, void* /*hFile*/, uint32_t /*dwFlags*/) {
    TRACE_REAL(LoadLibraryExW);
    if (lpLibFileName == nullptr) {
        g_LastError = 87;
        return nullptr;
    }
    // Advapi32 → sentinel handle. GetProcAddress resolves к our ETW stubs.
    if (sharpos_is_advapi32(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary advapi32] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_ADVAPI32_HMODULE;
    }
    // libSystem.Native → sentinel. GetProcAddress resolves SystemNative_*
    // console shims (Write→serial, IsATty→0, init→no-op success).
    if (sharpos_is_system_native(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary libSystem.Native] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_SYSNATIVE_HMODULE;
    }
    // kernel32/kernelbase/ntdll → sentinel; exports are in-image.
    if (sharpos_is_kernel32(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary kernel32] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_KERNEL32_HMODULE;
    }
    // ole32 → sentinel; CoCreateGuid is in-image (Guid.NewGuid).
    if (sharpos_is_ole32(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary ole32] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_OLE32_HMODULE;
    }
    // BCrypt → sentinel; BCryptGenRandom is in-image (HashCode/JSON).
    if (sharpos_is_bcrypt(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary bcrypt] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_BCRYPT_HMODULE;
    }
    // step 99: Secur32 → sentinel; GetUserNameExW is in-image (Environment.UserName).
    if (sharpos_is_secur32(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary secur32] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_SECUR32_HMODULE;
    }
    // step126.2: shell32 → sentinel; SHGetKnownFolderPath et al return E_FAIL.
    if (sharpos_is_shell32(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary shell32] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_SHELL32_HMODULE;
    }
    // step126.4: wldp → sentinel; Wldp* return "no policy / everything allowed".
    if (sharpos_is_wldp(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary wldp] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_WLDP_HMODULE;
    }
    // step126.9: amsi → sentinel; AMSI scans return CLEAN.
    if (sharpos_is_amsi(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary amsi] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_AMSI_HMODULE;
    }
    // step126.11: user32 → sentinel; window-related stubs return null/default.
    if (sharpos_is_user32(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary user32] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_USER32_HMODULE;
    }
    // step126.19: mpr/iphlpapi → sentinel; PS PSDrive automount + network
    // enumeration. GetProcAddress returns null for all names → PS skips
    // network drive providers, FileSystem provider init survives.
    if (sharpos_is_mpr(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary mpr] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_MPR_HMODULE;
    }
    if (sharpos_is_wintrust(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary wintrust] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_WINTRUST_HMODULE;
    }
    if (sharpos_is_iphlpapi(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary iphlpapi] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_IPHLPAPI_HMODULE;
    }
    if (sharpos_is_ucrtbase(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary ucrtbase] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_UCRTBASE_HMODULE;
    }
    // step 99 pass 3: libSystem.Security.Cryptography.Native.OpenSsl → sentinel;
    // CryptoNative_* RNG/SHA256 are in-image.
    if (sharpos_is_syscrypto(lpLibFileName)) {
        SharpOSHost_DebugPrint("[LoadLibrary syscrypto] returning sentinel handle\n");
        g_LastError = 0;
        return SHARPOS_SYSCRYPTO_HMODULE;
    }
    void* handle = SharpOSHost_FileOpen(lpLibFileName);
    if (!handle) {
        g_LastError = 126 /*ERROR_MOD_NOT_FOUND*/;
        return nullptr;
    }
    g_LastError = 0;
    // Return the BUFFER pointer (PE image start), not the handle, so
    // CoreCLR's PE header walks work from this base directly.
    void* buf = *(void**)((char*)handle + 0x00);
    return buf;
}
CRT_REAL(LoadLibraryExW);

extern "C" void* LoadLibraryExA(const char* /*lpLibFileName*/, void* /*hFile*/, uint32_t /*dwFlags*/) {
    TRACE_REAL(LoadLibraryExA);
    g_LastError = 126;
    return nullptr;   // ANSI variant rare in CoreCLR; route via UTF-16 LoadLibraryExW
}
CRT_REAL(LoadLibraryExA);

extern "C" void* LoadLibraryW(const wchar_t* lpLibFileName) {
    TRACE_REAL(LoadLibraryW);
    return LoadLibraryExW(lpLibFileName, nullptr, 0);
}
CRT_REAL(LoadLibraryW);

extern "C" void* LoadLibraryA(const char* /*lpLibFileName*/) {
    TRACE_REAL(LoadLibraryA);
    g_LastError = 126;
    return nullptr;
}
CRT_REAL(LoadLibraryA);

extern "C" int FreeLibrary(void* /*hLibModule*/) {
    TRACE_REAL(FreeLibrary);
    g_LastError = 0;
    return 1;
}
CRT_REAL(FreeLibrary);

// PAL_LOAD* — moved to pal/sharpos/winapi_shim.cpp (in coreclrpal.lib) so
// that coreclr.dll smoke target can also link them. crt_imp_stubs.cpp lives
// in coreclrpal_kernel_crt (excluded from smoke link).

// GetFullPathNameW — thin forwarder к BCL System.IO.Path.GetFullPath
// (managed C# normalization). Signature:
//   DWORD GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength,
//                          LPWSTR lpBuffer, LPWSTR* lpFilePart);
// Return: char count written (excluding null) on success,
//         required size (including null) if buf too small,
//         0 on error.
// lpFilePart: out-pointer to last component start. We ignore it (callers
// rarely use it; we set to NULL if non-null).
extern "C" uint32_t GetFullPathNameW(const wchar_t* lpFileName,
                                     uint32_t nBufferLength,
                                     wchar_t* lpBuffer,
                                     wchar_t** lpFilePart) {
    TRACE_REAL(GetFullPathNameW);
    if (lpFilePart) *lpFilePart = nullptr;
    uint32_t r = SharpOSHost_GetFullPathName(lpFileName, nBufferLength, lpBuffer);
    g_LastError = (r == 0) ? 87 /*ERROR_INVALID_PARAMETER*/ : 0;
    return r;
}
CRT_REAL(GetFullPathNameW);

// --- File I/O ---
//
// Pipeline: CreateFileW → SharpOSHost_FileOpen (C#) → Platform.TryReadFile →
//           UEFI SimpleFileSystem. Whole file slurped into GcHeap buffer at
//           open time; subsequent ReadFile/SetFilePointer operate on the
//           in-memory copy. Write/create not supported.
#define HANDLE_INVALID  ((void*)(intptr_t)-1)

// Forward decls for console-pseudo-file handling in CreateFileW. Defined
// in C# kernel side (FileSystemPolicy.cs + ConsoleWin32.cs).
extern "C" int      SharpOSHost_ClassifyConsoleFileName(const uint8_t* utf8Name, int len);
extern "C" uint64_t SharpOSHost_GetStdHandle(int nStdHandle);

// Forward decls + DirHandle (CreateFileW backup-semantics → directory handle
// for NtQueryDirectoryFile). The full kernel-side helpers live further down
// in the file (sharpos_wpath_to_ascii @3773, SharpOSHost_GetFileAttributes
// extern @3767); these forwards just allow CreateFileW to use them inline.
extern "C" uint32_t SharpOSHost_GetFileAttributes(const uint8_t* utf8Path);
static int sharpos_wpath_to_ascii(const wchar_t* w, uint8_t* out, int outCap);

#define SHARPOS_DIR_HANDLE_MAGIC 0xD12C0DE5D1240E5DULL

struct DirHandle {
    uint64_t magic;          // 0x00 — SHARPOS_DIR_HANDLE_MAGIC
    uint8_t  dirAscii[260];  // 0x08 — directory path (NUL-terminated)
    uint32_t nextIndex;      // index for next entry
    uint32_t exhausted;      // 1 once kernel reported no-more
};

// Heap-pointer sanity guard before dereferencing the handle for a magic
// check. Some Win32 stubs return small integer "sentinel" handles (e.g.
// HKEY values 0x4D from our registry shim). Without this guard a stray
// CloseHandle(0x4D) would page-fault on *(uint64_t*)0x4D.
static bool sharpos_is_dir_handle(void* h) {
    uintptr_t v = (uintptr_t)h;
    if (v < 0x100000ULL) return false;                  // small int sentinel
    if (v >= 0x800000000000ULL) return false;           // non-canonical
    if (h == (void*)(intptr_t)-1) return false;         // INVALID_HANDLE_VALUE
    return *(uint64_t*)h == SHARPOS_DIR_HANDLE_MAGIC;
}

extern "C" void* CreateFileW(const wchar_t* lpFileName,
                              uint32_t dwDesiredAccess,
                              uint32_t /*dwShareMode*/,
                              void* /*lpSecurityAttrs*/,
                              uint32_t /*dwCreationDisposition*/,
                              uint32_t dwFlagsAndAttributes,
                              void* /*hTemplateFile*/) {
    TRACE_REAL(CreateFileW);
    // step126.6: console pseudo-files. Classification ("is this a CONOUT$,
    // CONIN$, CONERR$ name") lives in kernel C# (FileSystemPolicy). Shim
    // converts wide name → UTF-8 bytes, asks kernel, then maps result to
    // the std-handle sentinel (which itself comes from
    // SharpOSHost_GetStdHandle defined in ConsoleWin32.cs).
    if (lpFileName != nullptr) {
        uint8_t nameBuf[16];
        int nameLen = 0;
        for (int i = 0; i < 15 && lpFileName[i] != 0; i++) {
            nameBuf[i] = (uint8_t)(lpFileName[i] & 0xFF);
            nameLen++;
        }
        nameBuf[nameLen] = 0;
        int kind = SharpOSHost_ClassifyConsoleFileName(nameBuf, nameLen);
        if (kind == 1) {  // CONOUT$ / CONERR$
            uint64_t h = SharpOSHost_GetStdHandle(-11);  // STD_OUTPUT_HANDLE
            g_LastError = 0;
            return (void*)(uintptr_t)h;
        }
        if (kind == 2) {  // CONIN$
            uint64_t h = SharpOSHost_GetStdHandle(-10);  // STD_INPUT_HANDLE
            g_LastError = 0;
            return (void*)(uintptr_t)h;
        }
    }
    // Reject write/append/delete — read-only host FS access.
    if (dwDesiredAccess & 0x40000000u /*GENERIC_WRITE*/) {
        g_LastError = 5 /*ERROR_ACCESS_DENIED*/;
        return HANDLE_INVALID;
    }
    // Local hex formatter — print a uint64 via DebugPrintForced one char at
    // a time. We intentionally don't use SharpOSHost_DebugPrintHex here:
    // bypassing its Verbose gate would open the floodgates for every other
    // hex-print call site in the fork.
    auto probe_hex = [](uint64_t v) {
        char buf[19] = "0x0000000000000000";
        for (int i = 17; i >= 2; i--) {
            int nib = (int)(v & 0xF);
            buf[i] = (char)(nib < 10 ? ('0' + nib) : ('A' + nib - 10));
            v >>= 4;
        }
        SharpOSHost_DebugPrintForced(buf);
    };

    // Diagnostic probe — detect the "\sharpos\C:\sharpos\..." doubled path
    // and dump the return-address chain. Lets us symbolize who in BCL/PS
    // constructs the bad string.
    if (lpFileName != nullptr) {
        const wchar_t* p = lpFileName;
        // Pattern start: "\sharpos\C:" or "C:\sharpos\C:\sharpos\..."
        // Quick check — scan for "C:\sharpos\C:" or "\sharpos\C:".
        int matched = 0;
        for (int i = 0; p[i] != 0 && i < 256; i++) {
            if (p[i] == L's' && p[i+1] == L'h' && p[i+2] == L'a' && p[i+3] == L'r'
             && p[i+4] == L'p' && p[i+5] == L'o' && p[i+6] == L's' && p[i+7] == L'\\'
             && p[i+8] == L'C' && p[i+9] == L':' && p[i+10] == L'\\') {
                matched = 1;
                break;
            }
        }
        static int s_probeFired = 0;
        if (matched && s_probeFired < 1) {
            s_probeFired++;
            SharpOSHost_DebugPrintForced("[probe-dup-path] path=\"");
            for (int i = 0; p[i] != 0 && i < 256; i++) {
                uint8_t c = (uint8_t)(p[i] & 0xFF);
                char buf[2] = { (char)c, 0 };
                SharpOSHost_DebugPrintForced(buf);
            }
            SharpOSHost_DebugPrintForced("\"\n");
            // Walk rbp chain: each frame stores caller's saved rbp at [rbp]
            // and caller's return address at [rbp+8]. Prints up to 8 frames
            // upward — symbolize via llvm-symbolizer against the right module.
            SharpOSHost_DebugPrintForced("[probe-dup-path] ra0=0x");
            probe_hex((uint64_t)__builtin_return_address(0));
            SharpOSHost_DebugPrintForced("\n");
            // Walk via __builtin_frame_address. *fp = saved caller rbp,
            // *(fp+1) = caller return address.
            uint64_t* rbp = (uint64_t*)__builtin_frame_address(0);
            // Step up one to caller's frame.
            if (rbp != nullptr) rbp = (uint64_t*)rbp[0];
            for (int level = 1; level <= 4 && rbp != nullptr; level++) {
                // Sanity: rbp must look like a stack pointer (canonical).
                uint64_t v = (uint64_t)rbp;
                if (v < 0x10000 || v > 0x7fffffffffffull) break;
                uint64_t ra = rbp[1];
                char head[28] = "[probe-dup-path] raN=0x";
                head[19] = (char)('0' + level);
                SharpOSHost_DebugPrintForced(head);
                probe_hex(ra);
                SharpOSHost_DebugPrintForced("\n");
                rbp = (uint64_t*)rbp[0];
            }
            // Fallback: stack dump (FPO functions don't preserve rbp). Print
            // top 24 qwords from our current rsp — caller RIPs land somewhere
            // in that range. Filter by image base ranges during symbolize.
            uint64_t* sp = (uint64_t*)__builtin_frame_address(0);
            SharpOSHost_DebugPrintForced("[probe-dup-path] stack-dump from rsp:\n");
            for (int i = 0; i < 12; i++) {
                uint64_t v = sp[i];
                SharpOSHost_DebugPrintForced("  [+"); probe_hex((uint64_t)(i*8));
                SharpOSHost_DebugPrintForced("] "); probe_hex(v);
                SharpOSHost_DebugPrintForced("\n");
            }
        }
    }
    // BCL FileSystemEnumerator.Windows opens a directory handle via
    //   CreateFileW(dir, GENERIC_READ, ..., FILE_FLAG_BACKUP_SEMANTICS)
    // and then walks it with NtQueryDirectoryFile. Only the explicit flag
    // triggers DirHandle alloc — avoiding the attribute-probe fallback that
    // false-positived on regular .dll file opens last time.
    if (dwFlagsAndAttributes & 0x02000000u /*FILE_FLAG_BACKUP_SEMANTICS*/) {
        DirHandle* d = (DirHandle*)SharpOSHost_HeapAlloc(sizeof(DirHandle));
        if (d == nullptr) { g_LastError = 8; return HANDLE_INVALID; }
        for (int i = 0; i < (int)sizeof(DirHandle); i++) ((uint8_t*)d)[i] = 0;
        d->magic = SHARPOS_DIR_HANDLE_MAGIC;
        int pn = sharpos_wpath_to_ascii(lpFileName, d->dirAscii, sizeof(d->dirAscii));
        if (pn < 0) {
            SharpOSHost_HeapFree(d);
            g_LastError = 87;
            return HANDLE_INVALID;
        }
        g_LastError = 0;
        return (void*)d;
    }
    void* h = SharpOSHost_FileOpen(lpFileName);
    if (!h) {
        g_LastError = 2 /*ERROR_FILE_NOT_FOUND*/;
        return HANDLE_INVALID;
    }
    g_LastError = 0;
    return h;
}
CRT_REAL(CreateFileW);

// CreateNamedPipeA — DiagnosticServer init calls this to set up the
// `\\.\pipe\dotnet-diagnostic-N` IPC channel for dotnet-trace / dotnet-dump
// connections. На unikernel'е других процессов нет, подключаться неоткуда →
// возвращаем INVALID_HANDLE_VALUE с GetLastError() = ERROR_ACCESS_DENIED.
// DiagnosticServer handles failure path: skip IPC, runtime продолжает без
// диагностического сервера. EventPipe-генерация продолжает работать внутрь —
// её выходы можно перехватить отдельно (форвард в console — TODO).
extern "C" void* CreateNamedPipeA(const char* /*lpName*/,
                                  uint32_t /*dwOpenMode*/,
                                  uint32_t /*dwPipeMode*/,
                                  uint32_t /*nMaxInstances*/,
                                  uint32_t /*nOutBufferSize*/,
                                  uint32_t /*nInBufferSize*/,
                                  uint32_t /*nDefaultTimeOut*/,
                                  void*    /*lpSecurityAttributes*/) {
    SharpOSHost_DebugPrint("[CreateNamedPipeA] disabled \xe2\x86\x92 INVALID_HANDLE_VALUE\n");
    g_LastError = 5 /*ERROR_ACCESS_DENIED*/;
    return HANDLE_INVALID;
}
CRT_REAL(CreateNamedPipeA);

extern "C" int ReadFile(void* hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead,
                        uint32_t* lpNumberOfBytesRead, void* /*lpOverlapped*/) {
    TRACE_REAL(ReadFile);
    if (hFile == HANDLE_INVALID || hFile == nullptr) {
        g_LastError = 6 /*ERROR_INVALID_HANDLE*/;
        if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
        return 0;
    }
    int rc = SharpOSHost_FileRead(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead);
    g_LastError = (rc == 0) ? 1117 /*ERROR_IO_DEVICE*/ : 0;
    return rc;
}
CRT_REAL(ReadFile);

extern "C" uint32_t SetFilePointer(void* hFile, int32_t lDistanceToMove,
                                   int32_t* lpDistanceToMoveHigh, uint32_t dwMoveMethod) {
    TRACE_REAL(SetFilePointer);
    int64_t distance = (int64_t)lDistanceToMove;
    if (lpDistanceToMoveHigh) {
        distance |= ((int64_t)(*lpDistanceToMoveHigh)) << 32;
    }
    int64_t result = SharpOSHost_FileSetPosition(hFile, distance, dwMoveMethod);
    if (result < 0) {
        g_LastError = 23 /*ERROR_INVALID_FUNCTION*/;
        return 0xFFFFFFFFu;   // INVALID_SET_FILE_POINTER
    }
    if (lpDistanceToMoveHigh) *lpDistanceToMoveHigh = (int32_t)(result >> 32);
    g_LastError = 0;
    return (uint32_t)(result & 0xFFFFFFFFu);
}
CRT_REAL(SetFilePointer);

// SetFilePointerEx — 64-bit variant; BCL FileStream.Seek and modern paths
// use this instead of the 32-bit SetFilePointer.
extern "C" int SetFilePointerEx(void* hFile, int64_t liDistanceToMove,
                                 int64_t* lpNewFilePointer, uint32_t dwMoveMethod) {
    TRACE_REAL(SetFilePointerEx);
    int64_t result = SharpOSHost_FileSetPosition(hFile, liDistanceToMove, dwMoveMethod);
    if (result < 0) {
        g_LastError = 23 /*ERROR_INVALID_FUNCTION*/;
        return 0;
    }
    if (lpNewFilePointer) *lpNewFilePointer = result;
    g_LastError = 0;
    return 1;
}
CRT_REAL(SetFilePointerEx);

// GetFileInformationByHandleEx — BCL FileInfo.Length / Get-Content / Get-ChildItem
// detail rendering all funnel through this. Three info classes cover the
// 99% surface PS hits: FileBasicInfo (times/attrs), FileStandardInfo (size,
// directory bit), FileAttributeTagInfo (attrs + reparse tag).
extern "C" int GetFileInformationByHandleEx(void* hFile,
                                             int32_t FileInformationClass,
                                             void* lpFileInformation,
                                             uint32_t dwBufferSize) {
    TRACE_REAL(GetFileInformationByHandleEx);
    if (lpFileInformation == nullptr) { g_LastError = 87; return 0; }

    bool isDir = sharpos_is_dir_handle(hFile);
    uint32_t fileSize = 0;
    if (!isDir && hFile != nullptr && hFile != (void*)(intptr_t)-1) {
        fileSize = SharpOSHost_FileGetSize(hFile);
        // SharpOSHost_FileGetSize returns 0 on unknown handle — that's fine
        // for our purposes (PS sees size 0 rather than throwing).
    }
    uint8_t* p = (uint8_t*)lpFileInformation;

    if (FileInformationClass == 0 /*FileBasicInfo*/) {
        // 4× FILETIME (i64) + DWORD FileAttributes + 4 pad = 0x28
        if (dwBufferSize < 0x28) { g_LastError = 122 /*ERROR_INSUFFICIENT_BUFFER*/; return 0; }
        for (int i = 0; i < 0x28; i++) p[i] = 0;
        *(uint32_t*)(p + 0x20) = isDir ? 0x10u /*DIRECTORY*/ : 0x80u /*NORMAL*/;
        g_LastError = 0;
        return 1;
    }
    if (FileInformationClass == 1 /*FileStandardInfo*/) {
        // i64 AllocationSize, i64 EndOfFile, DWORD NumberOfLinks,
        // BOOLEAN DeletePending, BOOLEAN Directory + pad = 0x18
        if (dwBufferSize < 0x18) { g_LastError = 122; return 0; }
        for (int i = 0; i < 0x18; i++) p[i] = 0;
        *(uint64_t*)(p + 0x00) = fileSize;
        *(uint64_t*)(p + 0x08) = fileSize;
        *(uint32_t*)(p + 0x10) = 1;          // NumberOfLinks
        p[0x14] = 0;                          // DeletePending
        p[0x15] = isDir ? 1 : 0;              // Directory
        g_LastError = 0;
        return 1;
    }
    if (FileInformationClass == 9 /*FileAttributeTagInfo*/) {
        if (dwBufferSize < 8) { g_LastError = 122; return 0; }
        *(uint32_t*)(p + 0x00) = isDir ? 0x10u : 0x80u;
        *(uint32_t*)(p + 0x04) = 0;           // ReparseTag
        g_LastError = 0;
        return 1;
    }
    g_LastError = 50 /*ERROR_NOT_SUPPORTED*/;
    return 0;
}
CRT_REAL(GetFileInformationByHandleEx);

// FillConsoleOutputCharacterW / FillConsoleOutputCharacterA / FillConsoleOutputAttribute:
// Clear-Host (and other PS UX paths) draw spaces over the buffer to clear it.
// Our UART doesn't have a buffer to overwrite; succeed silently so the host
// doesn't throw. The cursor still moves via SetConsoleCursorPosition + the
// terminal's own scroll, which is enough for usable shell output.
// Forward decl — full body around line 5054.
extern "C" int SharpOSHost_ConsoleWriteW(uint64_t hConsole, const wchar_t* buffer,
                                         uint32_t nChars, uint32_t* charsWritten);

// PS Clear-Host pattern: fill(' ', whole_buffer, 0,0) + fill(attrs,whole,0,0) +
// SetCursorPosition(0,0). When we see a long run of spaces at coord 0, emit
// ANSI \e[2J\e[H so both UART terminal AND our FbTty parser do a real clear.
static void sharpos_maybe_clear_screen(wchar_t cChar, uint32_t nLength, uint32_t dwCoord) {
    if (cChar != L' ' || nLength < 100 || dwCoord != 0) return;
    static const wchar_t k_clear[] = { 0x1B, L'[', L'2', L'J', 0x1B, L'[', L'H', 0 };
    uint32_t written = 0;
    SharpOSHost_ConsoleWriteW((uint64_t)(uintptr_t)SharpOSHost_GetStdHandle(-11),
                              k_clear, 7, &written);
}

extern "C" int FillConsoleOutputCharacterW(void* /*hConsole*/, wchar_t cChar,
                                            uint32_t nLength, uint32_t dwCoord,
                                            uint32_t* lpNumberWritten) {
    TRACE_REAL(FillConsoleOutputCharacterW);
    sharpos_maybe_clear_screen(cChar, nLength, dwCoord);
    if (lpNumberWritten) *lpNumberWritten = nLength;
    g_LastError = 0;
    return 1;
}
CRT_REAL(FillConsoleOutputCharacterW);

extern "C" int FillConsoleOutputCharacterA(void* /*hConsole*/, char cChar,
                                            uint32_t nLength, uint32_t dwCoord,
                                            uint32_t* lpNumberWritten) {
    TRACE_REAL(FillConsoleOutputCharacterA);
    sharpos_maybe_clear_screen((wchar_t)cChar, nLength, dwCoord);
    if (lpNumberWritten) *lpNumberWritten = nLength;
    g_LastError = 0;
    return 1;
}
CRT_REAL(FillConsoleOutputCharacterA);

extern "C" int FillConsoleOutputAttribute(void* /*hConsole*/, uint16_t /*wAttr*/,
                                           uint32_t nLength, uint32_t /*dwCoord*/,
                                           uint32_t* lpNumberWritten) {
    TRACE_REAL(FillConsoleOutputAttribute);
    if (lpNumberWritten) *lpNumberWritten = nLength;
    g_LastError = 0;
    return 1;
}
CRT_REAL(FillConsoleOutputAttribute);

extern "C" uint32_t GetFileSize(void* hFile, uint32_t* lpFileSizeHigh) {
    TRACE_REAL(GetFileSize);
    if (hFile == HANDLE_INVALID || hFile == nullptr) {
        g_LastError = 6;
        if (lpFileSizeHigh) *lpFileSizeHigh = 0xFFFFFFFFu;
        return 0xFFFFFFFFu;
    }
    uint32_t sz = SharpOSHost_FileGetSize(hFile);
    if (lpFileSizeHigh) *lpFileSizeHigh = 0;   // our files are < 4 GiB
    g_LastError = 0;
    return sz;
}
CRT_REAL(GetFileSize);

extern "C" int DuplicateHandle(void* /*srcProc*/, void* srcHandle, void* /*tgtProc*/,
                               void** tgtHandle, uint32_t /*access*/, int /*inherit*/, uint32_t /*opts*/) {
    TRACE_REAL(DuplicateHandle);
    if (tgtHandle) *tgtHandle = srcHandle;  // same handle — refcount irrelevant for fakes
    g_LastError = 0;
    return 1;
}
CRT_REAL(DuplicateHandle);

extern "C" void ExitThread(uint32_t exitCode) {
    TRACE_REAL(ExitThread);
    // Phase E9.a: route to kernel SharpOSHost_ExitThread which marks the
    // current kernel.Thread HasExited + signals JoinEvent + Scheduler.Exit.
    // Never returns.
    SharpOSHost_ExitThread(exitCode);
    for (;;) __asm__ volatile("hlt");   // unreachable; defensive
}
CRT_REAL(ExitThread);

extern "C" int GetThreadPriority(void* /*hThread*/) {
    TRACE_REAL(GetThreadPriority);
    return 0;  // THREAD_PRIORITY_NORMAL
}
CRT_REAL(GetThreadPriority);

extern "C" int SetThreadPriority(void* /*hThread*/, int /*priority*/) {
    TRACE_REAL(SetThreadPriority);
    return 1;
}
CRT_REAL(SetThreadPriority);

extern "C" uint32_t ResumeThread(void* hThread) {
    TRACE_REAL(ResumeThread);
    // Phase E9 -- threads created with CREATE_SUSPENDED sit in `New`
    // state until ResumeThread transitions them to Runnable. Returns
    // the previous suspend count per Win32 convention (1 = was paused,
    // 0 = wasn't, -1 = error).
    return SharpOSHost_ResumeThread((uint64_t)(uintptr_t)hThread);
}
CRT_REAL(ResumeThread);

// FlushInstructionCache — Windows API to invalidate I-cache for a range
// of just-written code. On x86/x64 I-cache snoops the D-cache so writes
// are visible to subsequent instruction fetches automatically (with the
// usual `jmp` or `call` self-modifying-code serialization at execution
// point). Returns BOOL success.
extern "C" int FlushInstructionCache(void* /*hProcess*/, const void* /*lpBaseAddress*/, size_t /*dwSize*/) {
    return 1;
}
CRT_REAL(FlushInstructionCache);

// FlushProcessWriteBuffers — Win32/kernel32 full-memory-barrier across all
// threads of the process. SharpOS bring-up is single-core with no
// background managed threads, so a plain return is correct (no other
// thread can observe stale writes). SMP later: send an IPI / membarrier.
// Was a CRT trap-stub; reflection-mode System.Text.Json reached it via
// the EH/GC path and panicked.
extern "C" void FlushProcessWriteBuffers(void) { }
CRT_REAL(FlushProcessWriteBuffers);

// NtQuerySystemInformation — ntdll P/Invoke. The only call on our path is
// .NET's DateTime leap-second probe:
//   Interop.NtDll.NtQuerySystemInformation(SystemLeapSecondInformation,
//       &SYSTEM_LEAP_SECOND_INFORMATION{ BOOLEAN Enabled; ULONG Flags; },
//       len, &ret)  (SystemLeapSecondInformation = 206)
// Report "leap seconds unsupported" (Enabled=0) with STATUS_SUCCESS so
// the BCL caches that result instead of throwing. Any other class →
// STATUS_NOT_IMPLEMENTED (callers treat non-zero as "unsupported").
// Defined further down; the process-information class below fills the image
// name from it so the path is spelled in exactly one place.
extern "C" uint32_t GetModuleFileNameW(void* mod, wchar_t* buf, uint32_t size);

extern "C" int NtQuerySystemInformation(int SystemInformationClass,
                                        void* SystemInformation,
                                        unsigned int SystemInformationLength,
                                        unsigned int* ReturnLength) {
    const int  STATUS_SUCCESS              = 0;
    const int  STATUS_NOT_IMPLEMENTED      = (int)0xC0000002u;
    const int  STATUS_INFO_LENGTH_MISMATCH = (int)0xC0000004u;
    const int  SystemLeapSecondInformation = 206;
    const int  SystemProcessInformation    = 5;
    if (ReturnLength) *ReturnLength = 0;
    if (SystemInformationClass == SystemLeapSecondInformation) {
        // { unsigned char Enabled; unsigned int Flags; } — 8 bytes packed.
        if (ReturnLength) *ReturnLength = 8;
        if (!SystemInformation || SystemInformationLength < 8)
            return STATUS_INFO_LENGTH_MISMATCH;
        ((unsigned char*)SystemInformation)[0] = 0;          // Enabled = FALSE
        *(unsigned int*)((unsigned char*)SystemInformation + 4) = 0; // Flags
        return STATUS_SUCCESS;
    }
    if (SystemInformationClass == SystemProcessInformation) {
        // Process.ProcessName walks this. Offsets mirror the managed
        // SYSTEM_PROCESS_INFORMATION (Interop.SYSTEM_PROCESS_INFORMATION.cs);
        // the struct is 0x100 bytes on x64 and, as on Windows, the image name
        // characters are stored in the same buffer right behind the entry.
        const uint32_t OFF_NEXT_ENTRY = 0x00, OFF_THREAD_COUNT = 0x04;
        const uint32_t OFF_IMAGE_NAME = 0x38, OFF_BASE_PRIORITY = 0x48;
        const uint32_t OFF_UNIQUE_PID = 0x50, OFF_SESSION_ID   = 0x64;
        const uint32_t ENTRY_SIZE     = 0x100;

        // One entry: this process. The name comes from GetModuleFileNameW so
        // there is a single spelling of it; trimming path and extension is
        // GetProcessShortName's job on the managed side.
        uint32_t nameLen  = GetModuleFileNameW(nullptr, nullptr, 0);
        uint32_t required = ENTRY_SIZE + (nameLen + 1) * 2;
        if (ReturnLength) *ReturnLength = required;
        if (!SystemInformation || SystemInformationLength < required)
            return STATUS_INFO_LENGTH_MISMATCH;

        unsigned char* base = (unsigned char*)SystemInformation;
        for (uint32_t i = 0; i < ENTRY_SIZE; i++) base[i] = 0;

        wchar_t* nameBuf = (wchar_t*)(base + ENTRY_SIZE);
        GetModuleFileNameW(nullptr, nameBuf, nameLen + 1);

        *(uint32_t*)(base + OFF_NEXT_ENTRY)    = 0;   // single entry, no chain
        *(uint32_t*)(base + OFF_THREAD_COUNT)  = 0;   // no SYSTEM_THREAD_INFORMATION follows
        *(uint16_t*)(base + OFF_IMAGE_NAME)    = (uint16_t)(nameLen * 2);        // Length
        *(uint16_t*)(base + OFF_IMAGE_NAME + 2)= (uint16_t)((nameLen + 1) * 2);  // MaximumLength
        *(void**)   (base + OFF_IMAGE_NAME + 8)= nameBuf;                        // Buffer
        *(int32_t*) (base + OFF_BASE_PRIORITY) = 8;
        *(uintptr_t*)(base + OFF_UNIQUE_PID)   = (uintptr_t)GetCurrentProcessId();
        *(uint32_t*)(base + OFF_SESSION_ID)    = 0;
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_IMPLEMENTED;
}
CRT_REAL(NtQuerySystemInformation);

// NtQueryDirectoryFile — Windows BCL FileSystemEnumerator's directory walker.
// Wraps our SharpOSHost_FindDirEntry into the FILE_FULL_DIR_INFORMATION
// stream format. PowerShell's module discovery and most BCL Directory.* APIs
// land here on Windows-shape.
//
// Layout of FILE_FULL_DIR_INFORMATION (0x44 byte header + name):
//   +0x00 NextEntryOffset  uint32  (0 on last entry; aligned to 8)
//   +0x04 FileIndex        uint32
//   +0x08 CreationTime     int64
//   +0x10 LastAccessTime   int64
//   +0x18 LastWriteTime    int64
//   +0x20 ChangeTime       int64
//   +0x28 EndOfFile        int64
//   +0x30 AllocationSize   int64
//   +0x38 FileAttributes   uint32
//   +0x3C FileNameLength   uint32  (in BYTES, not chars)
//   +0x40 EaSize           uint32
//   +0x44 FileName[]       WCHAR[FileNameLength/2]
//
// FileInformationClass values we handle:
//   FileFullDirectoryInformation     = 2  (primary, BCL uses this)
//   FileBothDirectoryInformation     = 3  (alternate, same layout for our use)
//   FileFullDirectoryInformationEx   = 60 (newer variant, same shape)
//   FileDirectoryInformation         = 1  (no EaSize, but BCL doesn't ask for it)
// Anything else → STATUS_NOT_IMPLEMENTED (0xC0000002).
extern "C" int32_t NtQueryDirectoryFile(
    void* FileHandle,
    void* /*Event*/,
    void* /*ApcRoutine*/,
    void* /*ApcContext*/,
    void* IoStatusBlock,
    void* FileInformation,
    uint32_t Length,
    int32_t FileInformationClass,
    uint8_t ReturnSingleEntry,
    void* /*FileName*/,        // FileName mask (e.g. "*.dll") — ignore, return all
    uint8_t RestartScan)
{
    const int32_t STATUS_SUCCESS         = 0;
    const int32_t STATUS_INVALID_HANDLE  = (int32_t)0xC0000008;
    const int32_t STATUS_BUFFER_TOO_SMALL= (int32_t)0xC0000023;
    const int32_t STATUS_NOT_IMPLEMENTED = (int32_t)0xC0000002;
    const int32_t STATUS_NO_MORE_FILES   = (int32_t)0x80000006;

    if (!sharpos_is_dir_handle(FileHandle)) return STATUS_INVALID_HANDLE;
    DirHandle* d = (DirHandle*)FileHandle;

    if (FileInformationClass != 1 && FileInformationClass != 2
     && FileInformationClass != 3 && FileInformationClass != 60)
        return STATUS_NOT_IMPLEMENTED;

    if (RestartScan) { d->nextIndex = 0; d->exhausted = 0; }

    if (FileInformation == nullptr || Length < 0x48) return STATUS_BUFFER_TOO_SMALL;

    uint8_t* buf = (uint8_t*)FileInformation;
    uint8_t* lastEntry = nullptr;
    uint32_t written = 0;
    uint32_t entries = 0;

    while (!d->exhausted) {
        wchar_t nameBuf[260];
        uint32_t attrs = 0;
        uint32_t fileSize = 0;
        uint32_t nameLen = SharpOSHost_FindDirEntry(d->dirAscii, d->nextIndex,
                                                     nameBuf, 260, &attrs, &fileSize);
        if (nameLen == 0) { d->exhausted = 1; break; }

        uint32_t nameBytes = nameLen * 2;
        uint32_t entrySize = 0x44 + nameBytes;
        entrySize = (entrySize + 7) & ~7u;

        if (written + entrySize > Length) {
            if (entries == 0) return STATUS_BUFFER_TOO_SMALL;
            break;   // doesn't fit — leave nextIndex pointing at this entry
        }

        // Commit the entry.
        uint8_t* p = buf + written;
        for (int i = 0; i < (int)entrySize; i++) p[i] = 0;
        *(uint32_t*)(p + 0x00) = entrySize;            // NextEntryOffset (fixed up later if last)
        *(uint32_t*)(p + 0x04) = d->nextIndex;         // FileIndex
        *(uint64_t*)(p + 0x28) = fileSize;             // EndOfFile (logical size)
        *(uint64_t*)(p + 0x30) = fileSize;             // AllocationSize
        *(uint32_t*)(p + 0x38) = attrs;                // FileAttributes
        *(uint32_t*)(p + 0x3C) = nameBytes;            // FileNameLength (bytes)
        wchar_t* nameDst = (wchar_t*)(p + 0x44);
        for (uint32_t i = 0; i < nameLen; i++) nameDst[i] = nameBuf[i];

        lastEntry = p;
        written += entrySize;
        entries++;
        d->nextIndex++;
        if (ReturnSingleEntry) break;
    }

    if (entries == 0) {
        if (IoStatusBlock != nullptr) {
            ((uint64_t*)IoStatusBlock)[0] = (uint64_t)(uint32_t)STATUS_NO_MORE_FILES;
            ((uint64_t*)IoStatusBlock)[1] = 0;
        }
        return STATUS_NO_MORE_FILES;
    }

    if (lastEntry != nullptr) *(uint32_t*)(lastEntry + 0x00) = 0;

    if (IoStatusBlock != nullptr) {
        ((uint64_t*)IoStatusBlock)[0] = STATUS_SUCCESS;
        ((uint64_t*)IoStatusBlock)[1] = written;
    }
    return STATUS_SUCCESS;
}
CRT_REAL(NtQueryDirectoryFile);

// NtClose — ntdll handle release. Mirrors CloseHandle's DirHandle dispatch.
extern "C" int32_t NtClose(void* h) {
    TRACE_REAL(NtClose);
    if (sharpos_is_dir_handle(h)) {
        SharpOSHost_HeapFree(h);
        return 0;
    }
    SharpOSHost_CloseHandle((uint64_t)(uintptr_t)h);
    return 0;
}
CRT_REAL(NtClose);

// RtlCaptureContext — capture caller-state CPU registers into a CONTEXT
// struct. Win64 ABI: arg in RCX = PCONTEXT.
//
// CONTEXT layout offsets (winnt.h, AMD64):
//   0x30 ContextFlags  DWORD
//   0x44 EFlags        DWORD
//   0x78 Rax           QWORD
//   0x80 Rcx, 0x88 Rdx, 0x90 Rbx, 0x98 Rsp, 0xA0 Rbp, 0xA8 Rsi, 0xB0 Rdi
//   0xB8..0xF0 R8..R15
//   0xF8 Rip
//
// CONTEXT_FULL = CONTEXT_AMD64(0x100000) | CONTROL(1) | INTEGER(2) | FP(8) = 0x10000B.
// We set INTEGER + CONTROL only (FP state not captured — naked asm here
// would need fxsave / vector regs; not needed for CoreCLR's early-init
// unwind code path).
__attribute__((naked))
extern "C" void RtlCaptureContext(void* /*ctx*/) {
    __asm__ volatile(
        "movl $0x100003, 0x30(%rcx)\n\t"   // ContextFlags = AMD64|CONTROL|INTEGER
        "movq %rax, 0x78(%rcx)\n\t"
        "movq %rcx, 0x80(%rcx)\n\t"        // (caller's rcx was clobbered by arg pass)
        "movq %rdx, 0x88(%rcx)\n\t"
        "movq %rbx, 0x90(%rcx)\n\t"
        "movq %rbp, 0xA0(%rcx)\n\t"
        "movq %rsi, 0xA8(%rcx)\n\t"
        "movq %rdi, 0xB0(%rcx)\n\t"
        "movq %r8,  0xB8(%rcx)\n\t"
        "movq %r9,  0xC0(%rcx)\n\t"
        "movq %r10, 0xC8(%rcx)\n\t"
        "movq %r11, 0xD0(%rcx)\n\t"
        "movq %r12, 0xD8(%rcx)\n\t"
        "movq %r13, 0xE0(%rcx)\n\t"
        "movq %r14, 0xE8(%rcx)\n\t"
        "movq %r15, 0xF0(%rcx)\n\t"
        // Rip = return address sitting at [rsp]
        "movq (%rsp), %rax\n\t"
        "movq %rax, 0xF8(%rcx)\n\t"
        // Rsp at the call site = current rsp + 8 (pop the return addr)
        "leaq 8(%rsp), %rax\n\t"
        "movq %rax, 0x98(%rcx)\n\t"
        // EFlags via pushfq/pop
        "pushfq\n\t"
        "popq %rax\n\t"
        "movl %eax, 0x44(%rcx)\n\t"
        "ret\n\t"
    );
}
CRT_REAL(RtlCaptureContext);

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
    // Phase 6.1.b: clean minimal impl. Removed TRACE_REAL + stack scan —
    // those added enough output noise that race conditions / register
    // pressure may have shifted timing. Goal: see if removing diagnostic
    // changes crash pattern. CRITICAL_SECTION struct (40 bytes) zeroed
    // + LockCount=-1 sentinel.
    if (cs) {
        uint8_t* p = (uint8_t*)cs;
        for (int i = 0; i < 40; i++) p[i] = 0;
        *(int32_t*)(p + 0x08) = -1;
    }
}
CRT_REAL(InitializeCriticalSection);
// Heartbeat counter: every Nth EnterCriticalSection/LeaveCriticalSection
// emits a brief "[cs ping] N" so we can tell if runtime is alive but silent
// (lots of CRT-internal CS ops without our diagnostic firing) vs truly stuck
// in a tight CPU loop.
static volatile uint64_t g_csPingCount = 0;
extern "C" void EnterCriticalSection(void* cs) {
    uint64_t n = ++g_csPingCount;
    if ((n & 0x3FF) == 0) {  // every 1024th call
        SharpOSHost_DebugPrint("[cs ping] n=0x");
        SharpOSHost_DebugPrintHex(n);
        SharpOSHost_DebugPrint(" cs=0x");
        SharpOSHost_DebugPrintHex((uint64_t)cs);
        SharpOSHost_DebugPrint(" caller=0x");
        SharpOSHost_DebugPrintHex((uint64_t)__builtin_return_address(0));
        SharpOSHost_DebugPrint("\n");
    }
}
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

// GlobalMemoryStatusEx — CoreCLR queries this to size GC heap, decide
// whether to enable concurrent / server GC heuristics, etc. Real numbers
// would come from BootInfo.MemoryMap. For now: 2 GiB physical, 1 GiB
// free, no pagefile, 128 TiB virtual address space (typical x64).
extern "C" int GlobalMemoryStatusEx(void* lpBuffer) {
    TRACE_REAL(GlobalMemoryStatusEx);
    if (!lpBuffer) return 0;
    uint8_t* b = (uint8_t*)lpBuffer;
    // dwLength (DWORD): caller has set this to sizeof(MEMORYSTATUSEX)=64.
    // We don't validate; just fill rest.
    *(uint32_t*)(b + 4)  = 50;                      // dwMemoryLoad = 50%
    *(uint64_t*)(b + 8)  = 2ULL * 1024 * 1024 * 1024; // ullTotalPhys = 2 GiB
    *(uint64_t*)(b + 16) = 1ULL * 1024 * 1024 * 1024; // ullAvailPhys = 1 GiB
    *(uint64_t*)(b + 24) = 0;                       // ullTotalPageFile
    *(uint64_t*)(b + 32) = 0;                       // ullAvailPageFile
    *(uint64_t*)(b + 40) = (uint64_t)128 * 1024 * 1024 * 1024 * 1024; // ullTotalVirtual = 128 TiB
    *(uint64_t*)(b + 48) = (uint64_t)128 * 1024 * 1024 * 1024 * 1024; // ullAvailVirtual
    *(uint64_t*)(b + 56) = 0;                       // ullAvailExtendedVirtual
    return 1;
}
CRT_REAL(GlobalMemoryStatusEx);

extern "C" void GetSystemInfo(void* out) {
    TRACE_REAL(GetSystemInfo);
    if (!out) return;
    uint32_t* p = (uint32_t*)out;
    for (int i = 0; i < 12; i++) p[i] = 0;
    p[0]  = 9;       // wProcessorArchitecture = AMD64
    p[1]  = 0x1000;  // dwPageSize = 4 KiB
    p[8]  = 1;       // dwNumberOfProcessors
    p[10] = 0x10000; // dwAllocationGranularity = 64 KiB
                     // CoreCLR ExecutableAllocator::Granularity() returns
                     // this value and divides reservation sizes by it —
                     // zero here ⇒ #DE in code heap setup.
}
CRT_REAL(GetSystemInfo);

extern "C" void* GetProcessHeap(void) { TRACE_REAL(GetProcessHeap); return (void*)(intptr_t)1; }
CRT_REAL(GetProcessHeap);

// HeapAlloc(handle, flags, size) → SharpOSHost-routed alloc.
extern "C" void* HeapAlloc(void* /*h*/, uint32_t /*flags*/, size_t size) {
    void* p = SharpOSHost_HeapAlloc(size);
    SharpOSHost_DebugPrint("[crt] HeapAlloc(0x");
    SharpOSHost_DebugPrintHex(size);
    SharpOSHost_DebugPrint(")=0x");
    SharpOSHost_DebugPrintHex((uint64_t)p);
    SharpOSHost_DebugPrint(" caller=0x");
    SharpOSHost_DebugPrintHex((uint64_t)__builtin_return_address(0));
    SharpOSHost_DebugPrint("\n");
    return p;
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

// LocalAlloc / LocalFree — Win32 legacy heap. ThreadPool init's CoreLib
// uses them for short-lived buffers. LMEM_FIXED=0x0000 / LMEM_ZEROINIT=0x0040;
// we ignore flags except for zero-init (HEAP_ZERO_MEMORY=0x8) and route
// through HeapAlloc which forwards to SharpOSHost_HeapAlloc.
extern "C" void* LocalAlloc(uint32_t uFlags, size_t uBytes) {
    void* p = SharpOSHost_HeapAlloc(uBytes);
    if (p != nullptr && (uFlags & 0x0040)) {
        uint8_t* b = (uint8_t*)p;
        for (size_t i = 0; i < uBytes; i++) b[i] = 0;
    }
    return p;
}
CRT_REAL(LocalAlloc);

extern "C" void* LocalFree(void* hMem) {
    if (hMem != nullptr) SharpOSHost_HeapFree(hMem);
    return nullptr;   // Win32: returns NULL on success, hMem on failure
}
CRT_REAL(LocalFree);

// FormatMessageW — minimal implementation covering the CoreCLR usage in
// SString::FormatMessage (utilcode/sstring.cpp). Supports:
//   FORMAT_MESSAGE_FROM_STRING       (0x00000400) — lpSource is the template
//   FORMAT_MESSAGE_ALLOCATE_BUFFER   (0x00000100) — allocate output via LocalAlloc
//   FORMAT_MESSAGE_ARGUMENT_ARRAY    (0x00002000) — Arguments is WCHAR*[] not va_list
// Inserts: %1!s! .. %9!s! → Arguments[N-1] (a WCHAR*). The "!s!" type
// suffix is optional (we accept bare %N too). Win32 also supports %0
// (terminate without newline), %% (literal), %n (newline) — handled.
// No FROM_HMODULE / FROM_SYSTEM (we read templates from compiled-in
// mscorrc table; both are unused here). Step103d.
extern "C" uint32_t FormatMessageW(uint32_t dwFlags,
                                   const void* lpSource,
                                   uint32_t /*dwMessageId*/,
                                   uint32_t /*dwLanguageId*/,
                                   wchar_t* lpBuffer,
                                   uint32_t nSize,
                                   void* Arguments)
{
    if (!(dwFlags & 0x00000400)) return 0;          // require FROM_STRING
    if (lpSource == nullptr || lpBuffer == nullptr) return 0;
    const wchar_t* src = (const wchar_t*)lpSource;
    const wchar_t** args = (const wchar_t**)Arguments;
    bool allocate = (dwFlags & 0x00000100) != 0;

    auto wstrlen = [](const wchar_t* s) -> size_t {
        size_t n = 0; if (!s) return 0; while (s[n] != 0) ++n; return n;
    };

    // Pass 1: compute output length.
    size_t outLen = 0;
    for (const wchar_t* p = src; *p != 0; ) {
        if (*p == L'%') {
            wchar_t c = *(p + 1);
            if (c >= L'1' && c <= L'9' && args != nullptr) {
                outLen += wstrlen(args[c - L'1']);
                p += 2;
                // optional "!fmt!" suffix — skip until second '!' inclusive
                if (*p == L'!') {
                    ++p;
                    while (*p != 0 && *p != L'!') ++p;
                    if (*p == L'!') ++p;
                }
                continue;
            }
            if (c == L'%')  { outLen += 1; p += 2; continue; }   // %%
            if (c == L'n')  { outLen += 1; p += 2; continue; }   // newline
            if (c == L'0')  { p += 2; break; }                   // %0 terminate
            // Unknown %X — copy literal
            outLen += 1; ++p; continue;
        }
        outLen += 1; ++p;
    }

    // Allocate or validate output buffer.
    wchar_t* dst;
    size_t dstCap;
    if (allocate) {
        wchar_t* allocated = (wchar_t*)LocalAlloc(0, (outLen + 1) * sizeof(wchar_t));
        if (allocated == nullptr) return 0;
        *(wchar_t**)lpBuffer = allocated;
        dst = allocated;
        dstCap = outLen + 1;
    } else {
        if (nSize == 0) return 0;
        dst = lpBuffer;
        dstCap = nSize;
    }

    // Pass 2: emit.
    size_t w = 0;
    auto put_ch = [&](wchar_t ch) {
        if (w + 1 < dstCap) dst[w++] = ch;
    };
    auto put_str = [&](const wchar_t* s) {
        if (!s) return;
        for (; *s != 0; ++s) put_ch(*s);
    };
    for (const wchar_t* p = src; *p != 0; ) {
        if (*p == L'%') {
            wchar_t c = *(p + 1);
            if (c >= L'1' && c <= L'9' && args != nullptr) {
                put_str(args[c - L'1']);
                p += 2;
                if (*p == L'!') {
                    ++p;
                    while (*p != 0 && *p != L'!') ++p;
                    if (*p == L'!') ++p;
                }
                continue;
            }
            if (c == L'%')  { put_ch(L'%');  p += 2; continue; }
            if (c == L'n')  { put_ch(L'\n'); p += 2; continue; }
            if (c == L'0')  { p += 2; break; }
            put_ch(*p); ++p; continue;
        }
        put_ch(*p); ++p;
    }
    dst[w] = 0;
    return (uint32_t)w;
}
CRT_REAL(FormatMessageW);

// Win32 condition variable shim — used by PortableThreadPool worker
// dispatch. SleepConditionVariableSRW and WakeAllConditionVariable are
// already defined upstream as no-op stubs (return 1 / void). We only
// need to add the missing InitializeConditionVariable + SleepConditionVariableCS
// + WakeConditionVariable so the kernel32 resolver can wire all five.
// Cooperative single-CPU means Sleep can just return immediately —
// workers won't truly block but progress through the work queue.
extern "C" void InitializeConditionVariable(void* /*cv*/) {
    /* opaque pointer; first Sleep/Wake handles state */
}
CRT_REAL(InitializeConditionVariable);

extern "C" int SleepConditionVariableCS(void* /*cv*/, void* /*cs*/, uint32_t /*dwMs*/) {
    // Cooperative single-CPU: just succeed. Worker re-checks predicate
    // and may loop. Matching shape of existing SleepConditionVariableSRW.
    g_LastError = 0;
    return 1;
}
CRT_REAL(SleepConditionVariableCS);

extern "C" void WakeConditionVariable(void* /*cv*/) {
    /* paired no-op with SleepConditionVariableCS */
}
CRT_REAL(WakeConditionVariable);

// GetSystemTimes — ThreadPool hill-climber polls this for CPU utilization.
// Win32 reports idle/kernel/user time as FILETIME (100-ns ticks since
// some epoch). For single-CPU cooperative kernel we report all zeros;
// hill-climber sees 100% busy and may try to spawn more workers (capped
// by max thread count), which is fine for our test case.
extern "C" int GetSystemTimes(void* lpIdle, void* lpKernel, void* lpUser) {
    if (lpIdle)   { ((uint64_t*)lpIdle)[0]   = 0; }
    if (lpKernel) { ((uint64_t*)lpKernel)[0] = 0; }
    if (lpUser)   { ((uint64_t*)lpUser)[0]   = 0; }
    g_LastError = 0;
    return 1;
}
CRT_REAL(GetSystemTimes);

// --- Virtual memory ---
//
// SharpOS unikernel: no W^X enforcement, no demand-paging, single AS. All
// kernel memory is RWX from page-table standpoint (NX disabled in EFI paging
// inherited at boot). MEM_RESERVE / MEM_COMMIT distinction collapses — we
// allocate from the kernel heap (SharpOSHost_HeapAlloc routes to GcHeap)
// regardless. Sizes are typically loader-heap-sized (64KB-256KB) post W^X
// disable, not the 2TB RangeSectionMap reservations the double-mapping path
// would request.
//
// Note: ExecutableAllocator::Reserve passes size that's Granularity-aligned
// (64KB on Windows). VirtualAlloc semantics return base of reservation;
// further commit calls on subranges expect same base or interior — we
// return what GcHeap gave us and trust subsequent commits are interior
// (no-op since memory already physical-backed).

// Forward decls for SharpOS-host page allocator (impl в OS/src/PAL/SharpOSHost/Memory.cs)
extern "C" __attribute__((weak)) void* SharpOSHost_AllocExecutable(uint64_t /*size*/) { return nullptr; }
extern "C" __attribute__((weak)) int   SharpOSHost_ProtectExecutable(void* /*addr*/, uint64_t /*size*/, uint32_t /*flProtect*/) { return 0; }

// S3 — true reserve≠commit via the SharpOS VM manager (OS/src/Kernel/Memory/
// VirtualMemory.cs, exported by VirtualMemoryHost.cs). gcenv.windows.cpp's
// GCToOSInterface::Virtual{Reserve,Commit,Decommit,Release} all funnel through
// Win32 VirtualAlloc/VirtualFree → these. Replaces the old GcHeap commit-on-
// alloc path (which made gc_heap degenerate → IsHeapPointer=false → Monitor
// spin). Weak fallbacks so the non-kernel coreclr.dll smoke link still resolves.
extern "C" __attribute__((weak)) void* SharpOSHost_VMReserve(uint64_t /*size*/, uint64_t /*align*/) { return nullptr; }
extern "C" __attribute__((weak)) int   SharpOSHost_VMCommit(void* /*addr*/, uint64_t /*size*/, int /*exec*/) { return 0; }
extern "C" __attribute__((weak)) int   SharpOSHost_VMDecommit(void* /*addr*/, uint64_t /*size*/) { return 1; }
extern "C" __attribute__((weak)) int   SharpOSHost_VMRelease(void* /*addr*/, uint64_t /*size*/) { return 1; }

// Win32 semantics we honour:
//   lpAddress == NULL → allocate any address. exec=EfiLoaderCode pool with
//     RWX patch; non-exec=GcHeap (RW, NX=1).
//   lpAddress != NULL → caller wants a SPECIFIC address (typically subrange
//     inside an earlier MEM_RESERVE block). Don't allocate; just flip the
//     page protection on the requested range. Returning a different address
//     breaks CoreCLR's reserve+commit pattern для code heap (it computes
//     code addresses inside the reservation it received).
extern "C" void* VirtualAlloc(void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect) {
    if (dwSize == 0) { g_LastError = 87 /*ERROR_INVALID_PARAMETER*/; return nullptr; }
    const size_t GRAN = 0x10000;
    const uint32_t MEM_COMMIT_F  = 0x1000;
    const uint32_t MEM_RESERVE_F = 0x2000;

    bool wantExec  = (flProtect & 0xF0u) != 0;
    bool doReserve = (flAllocationType & MEM_RESERVE_F) != 0;
    bool doCommit  = (flAllocationType & MEM_COMMIT_F) != 0;
    void* result = nullptr;

    if (lpAddress != nullptr) {
        // Commit (and/or protect) a sub-range of an earlier VMReserve. The
        // VA is reserved-but-unbacked → VMCommit allocates frames + maps
        // them (idempotent on already-committed pages). Covers GC region
        // commit (RW) and any JIT commit-into-reserve (exec).
        int rc = SharpOSHost_VMCommit(lpAddress, (uint64_t)dwSize, wantExec ? 1 : 0);
        result = rc ? lpAddress : nullptr;
        SharpOSHost_DebugPrint("[VA commit] lp=0x");
        SharpOSHost_DebugPrintHex((uint64_t)lpAddress);
        SharpOSHost_DebugPrint(" size=0x"); SharpOSHost_DebugPrintHex((uint64_t)dwSize);
        SharpOSHost_DebugPrint(" pr=0x");   SharpOSHost_DebugPrintHex((uint64_t)flProtect);
        SharpOSHost_DebugPrint(rc ? " ok\n" : " FAIL\n");
    } else if (wantExec) {
        // Fresh-anywhere exec allocation. EfiLoaderCode pool + RWX patch
        // (JIT code heap — unchanged, works; VM-migration is S6).
        void* execRaw = SharpOSHost_AllocExecutable((uint64_t)(dwSize + GRAN));
        if (execRaw) {
            uintptr_t alignedExec = ((uintptr_t)execRaw + (GRAN - 1)) & ~(uintptr_t)(GRAN - 1);
            result = (void*)alignedExec;
        }
        SharpOSHost_DebugPrint("[VA exec] size=0x"); SharpOSHost_DebugPrintHex((uint64_t)dwSize);
        SharpOSHost_DebugPrint(" result=0x"); SharpOSHost_DebugPrintHex((uint64_t)result);
        SharpOSHost_DebugPrint("\n");
    } else {
        // Fresh-anywhere non-exec: reserve VA from the VM window (no backing).
        // If MEM_COMMIT also set (or no flags = legacy reserve+commit), back
        // it immediately. GC's big MEM_RESERVE(RegionRange) lands here cheap;
        // it then commits sub-regions via the lpAddress!=NULL path.
        void* va = SharpOSHost_VMReserve((uint64_t)dwSize, GRAN);
        if (va != nullptr && (doCommit || !doReserve)) {
            if (!SharpOSHost_VMCommit(va, (uint64_t)dwSize, 0)) va = nullptr;
        }
        result = va;
        SharpOSHost_DebugPrint("[VA resv] size=0x"); SharpOSHost_DebugPrintHex((uint64_t)dwSize);
        SharpOSHost_DebugPrint(" at=0x");  SharpOSHost_DebugPrintHex((uint64_t)flAllocationType);
        SharpOSHost_DebugPrint(" result=0x"); SharpOSHost_DebugPrintHex((uint64_t)result);
        SharpOSHost_DebugPrint("\n");
    }

    if (!result) { g_LastError = 8 /*ERROR_NOT_ENOUGH_MEMORY*/; return nullptr; }
    g_LastError = 0;
    return result;
}
CRT_REAL(VirtualAlloc);

extern "C" int VirtualFree(void* lpAddress, size_t dwSize, uint32_t dwFreeType) {
    TRACE_REAL(VirtualFree);
    const uint32_t MEM_DECOMMIT_F = 0x4000;
    const uint32_t MEM_RELEASE_F  = 0x8000;
    int rc = 1;
    if (dwFreeType & MEM_DECOMMIT_F) rc &= SharpOSHost_VMDecommit(lpAddress, (uint64_t)dwSize);
    if (dwFreeType & MEM_RELEASE_F)  rc &= SharpOSHost_VMRelease(lpAddress, (uint64_t)dwSize);
    g_LastError = 0;
    return rc;
}
CRT_REAL(VirtualFree);

extern "C" int VirtualProtect(void* lpAddress, size_t dwSize, uint32_t flNewProtect, uint32_t* lpflOldProtect) {
    int rc = SharpOSHost_ProtectExecutable(lpAddress, (uint64_t)dwSize, flNewProtect);
    SharpOSHost_DebugPrint("[VirtualProtect] addr=0x");
    SharpOSHost_DebugPrintHex((uint64_t)lpAddress);
    SharpOSHost_DebugPrint(" size=0x");
    SharpOSHost_DebugPrintHex((uint64_t)dwSize);
    SharpOSHost_DebugPrint(" newProtect=0x");
    SharpOSHost_DebugPrintHex((uint64_t)flNewProtect);
    SharpOSHost_DebugPrint(rc ? " ok\n" : " FAIL\n");
    if (lpflOldProtect) *lpflOldProtect = 0x40 /*PAGE_EXECUTE_READWRITE — best-effort guess*/;
    g_LastError = rc ? 0u : 87u;
    return rc;
}
CRT_REAL(VirtualProtect);

extern "C" size_t VirtualQuery(const void* lpAddress, void* lpBuffer, size_t dwLength) {
    TRACE_REAL(VirtualQuery);
    if (!lpBuffer || dwLength < 48) { g_LastError = 87; return 0; }
    uint8_t* b = (uint8_t*)lpBuffer;
    for (size_t i = 0; i < 48; i++) b[i] = 0;
    *(const void**)(b + 0)  = lpAddress;
    *(const void**)(b + 8)  = lpAddress;
    *(uint32_t*)   (b + 16) = 0x40;
    *(size_t*)     (b + 24) = 0x10000;
    *(uint32_t*)   (b + 32) = 0x1000;
    *(uint32_t*)   (b + 36) = 0x40;
    *(uint32_t*)   (b + 40) = 0x20000;
    g_LastError = 0;
    return 48;
}
CRT_REAL(VirtualQuery);

// --- Win32 env / module / console (all empty / not-found) ---
//
// CoreCLR queries DOTNET_*/COMPlus_* env vars for config tuning. Returning
// 0 (var not found) makes CoreCLR fall back to baked-in defaults.
// GetCommandLineW returns empty wstr. Module handles return null (no
// modules loaded — kernel image is the only one).

static const wchar_t k_empty_w[] = { 0 };
static uint32_t k_ERROR_ENVVAR_NOT_FOUND = 203;

// Kernel-side env-var policy (OS/src/PAL/SharpOSHost/EnvironmentPolicy.cs).
// Fork side is pure ABI: marshal wide/ASCII name → ASCII bytes, call kernel,
// marshal value back into caller's wide/ASCII buffer with the Win32 length
// protocol (chars-excl-NUL on success / required-incl-NUL on overflow).
extern "C" uint32_t SharpOSHost_GetEnvVar(const uint8_t* name, int32_t nameLen,
                                          uint8_t* outBuf, uint32_t outBufSize,
                                          uint32_t* outErr);

// Convert a wide name to ASCII (env names are always 7-bit). Returns
// length or -1 if it contains non-ASCII (which can't be an env-var name).
// Stops at NUL.
static int sharpos_env_widen_name_to_ascii(const wchar_t* name, uint8_t* out, int outCap) {
    if (name == nullptr || out == nullptr) return -1;
    int i = 0;
    for (; i + 1 < outCap; i++) {
        wchar_t c = name[i];
        if (c == 0) break;
        if (c > 0x7F) return -1;
        out[i] = (uint8_t)c;
    }
    out[i] = 0;
    return i;
}

extern "C" uint32_t GetEnvironmentVariableW(const wchar_t* name, wchar_t* buf, uint32_t size) {
    uint8_t asciiName[128];
    int nl = sharpos_env_widen_name_to_ascii(name, asciiName, sizeof(asciiName));
    if (nl <= 0) { g_LastError = k_ERROR_ENVVAR_NOT_FOUND; return 0; }

    // Kernel writes UTF-8 bytes; we widen one byte at a time below. To keep
    // a single kernel ABI we slurp into a stack ASCII buffer first then
    // widen — env values here are always small (<= 64 bytes).
    uint8_t valueBuf[128];
    uint32_t err = 0;
    uint32_t bytes = SharpOSHost_GetEnvVar(asciiName, nl, valueBuf,
                                            (uint32_t)sizeof(valueBuf), &err);
    if (err != 0 && err != 122) { g_LastError = err; return 0; }
    // bytes is value length (excl NUL). Required wide-buffer = bytes + 1.
    if (buf == nullptr || size < bytes + 1) {
        g_LastError = 0;
        return bytes + 1;                            // required size incl NUL
    }
    for (uint32_t i = 0; i < bytes; i++) buf[i] = (wchar_t)valueBuf[i];
    buf[bytes] = 0;
    g_LastError = 0;
    return bytes;
}
CRT_REAL(GetEnvironmentVariableW);

extern "C" uint32_t GetEnvironmentVariableA(const char* name, char* buf, uint32_t size) {
    if (name == nullptr) { g_LastError = k_ERROR_ENVVAR_NOT_FOUND; return 0; }
    int nl = 0;
    while (name[nl] != 0 && nl < 127) nl++;

    uint8_t valueBuf[128];
    uint32_t err = 0;
    uint32_t bytes = SharpOSHost_GetEnvVar((const uint8_t*)name, nl, valueBuf,
                                            (uint32_t)sizeof(valueBuf), &err);
    if (err != 0 && err != 122) { g_LastError = err; return 0; }
    if (buf == nullptr || size < bytes + 1) {
        g_LastError = 0;
        return bytes + 1;
    }
    for (uint32_t i = 0; i < bytes; i++) buf[i] = (char)valueBuf[i];
    buf[bytes] = 0;
    g_LastError = 0;
    return bytes;
}
CRT_REAL(GetEnvironmentVariableA);

// step 73 quick-win — was `return nullptr`: CoreCLR's
// Environment.GetEnvironmentVariables() walked a null block computing
// length to a huge value → OutOfMemoryException. A valid EMPTY
// environment block is a double-NUL (the parser sees a zero-length
// first entry and stops) → empty dictionary, no OOM. Static storage;
// FreeEnvironmentStringsW is a no-op (must not free a static).
extern "C" wchar_t* GetEnvironmentStringsW(void) {
    TRACE_REAL(GetEnvironmentStringsW);
    static const wchar_t k_empty_env[] = { 0, 0 };
    return (wchar_t*)k_empty_env;
}
CRT_REAL(GetEnvironmentStringsW);
extern "C" int FreeEnvironmentStringsW(wchar_t* /*p*/) { TRACE_REAL(FreeEnvironmentStringsW); return 1; }
CRT_REAL(FreeEnvironmentStringsW);

// step 99 -- system/env string getters. PAL is a thin forwarder; the
// actual strings (machine name "SHARPOS", paths starting with \sharpos,
// hostname "sharpos", user "local") live kernel-side in
// OS/src/PAL/SharpOSHost/SystemIdentity.cs (SharpOSHost_GetSystemString).
// Win32 length protocol is enforced HERE (return chars copied excl NUL
// on success, required size incl NUL on too-small) because the kernel
// returns the same uniform shape and the per-API quirks (ASCII -> UTF-16
// widening, nSize in/out vs nBufferLength, NameType ignored, ...) are
// ABI shape transformations, not policy.

extern "C" int SharpOSHost_GetSystemString(int kind, uint8_t* outBuf, int outBufSize);

// Kind constants mirror SystemIdentity.Kind*.
static const int k_SI_CurrentDir   = 0;
static const int k_SI_TempPath     = 1;
static const int k_SI_SystemDir    = 2;
static const int k_SI_WindowsDir   = 3;
static const int k_SI_MachineName  = 4;
static const int k_SI_UserName     = 5;
// k_SI_HostName, k_SI_OsName, k_SI_TimeZoneName not used by Win32 paths.

// Helper: copy a kernel-side ASCII string into a wide Win32 buffer.
// Returns chars copied (excl NUL) on success, or required size (incl
// NUL) when the caller's buffer is too small. Returns 0 with
// g_LastError set on internal failure (bad kind).
static uint32_t sharpos_wfetch(int kind, wchar_t* dst, uint32_t dst_chars) {
    // Ask the kernel for the required length first.
    int needed_incl_nul = SharpOSHost_GetSystemString(kind, nullptr, 0);
    if (needed_incl_nul <= 0) { g_LastError = 87; return 0; }
    uint32_t needed = (uint32_t)needed_incl_nul;        // incl NUL
    if (dst == nullptr || dst_chars < needed) return needed;

    // Fetch into a transient stack buffer of bounded size (kernel
    // strings are ASCII paths/identifiers, well under 64 chars).
    uint8_t tmp[128];
    int n = needed > sizeof(tmp) ? (int)sizeof(tmp) : (int)needed;
    int got = SharpOSHost_GetSystemString(kind, tmp, n);
    if (got < 0) { g_LastError = 87; return 0; }
    uint32_t srcLen = (uint32_t)got;
    for (uint32_t i = 0; i < srcLen; i++) dst[i] = (wchar_t)tmp[i];
    dst[srcLen] = 0;
    return srcLen;                                       // chars excl NUL
}

extern "C" uint32_t GetCurrentDirectoryW(uint32_t nBufferLength, wchar_t* lpBuffer) {
    TRACE_REAL(GetCurrentDirectoryW);
    g_LastError = 0;
    return sharpos_wfetch(k_SI_CurrentDir, lpBuffer, nBufferLength);
}
CRT_REAL(GetCurrentDirectoryW);

extern "C" uint32_t GetTempPathW(uint32_t nBufferLength, wchar_t* lpBuffer) {
    TRACE_REAL(GetTempPathW);
    g_LastError = 0;
    return sharpos_wfetch(k_SI_TempPath, lpBuffer, nBufferLength);
}
CRT_REAL(GetTempPathW);

extern "C" uint32_t GetTempPath2W(uint32_t nBufferLength, wchar_t* lpBuffer) {
    TRACE_REAL(GetTempPath2W);
    g_LastError = 0;
    return sharpos_wfetch(k_SI_TempPath, lpBuffer, nBufferLength);
}
CRT_REAL(GetTempPath2W);

extern "C" uint32_t GetSystemDirectoryW(wchar_t* lpBuffer, uint32_t uSize) {
    TRACE_REAL(GetSystemDirectoryW);
    g_LastError = 0;
    return sharpos_wfetch(k_SI_SystemDir, lpBuffer, uSize);
}
CRT_REAL(GetSystemDirectoryW);

extern "C" uint32_t GetWindowsDirectoryW(wchar_t* lpBuffer, uint32_t uSize) {
    TRACE_REAL(GetWindowsDirectoryW);
    g_LastError = 0;
    return sharpos_wfetch(k_SI_WindowsDir, lpBuffer, uSize);
}
CRT_REAL(GetWindowsDirectoryW);

// nSize is in/out: caller passes max chars, gets back length excl NUL
// on success (return TRUE) or required size incl NUL on too-small
// (return FALSE, ERROR_MORE_DATA).
static const uint32_t k_ERROR_MORE_DATA = 234;

static int sharpos_winsize_fetch(int kind, wchar_t* lpBuffer, uint32_t* nSize) {
    if (nSize == nullptr) { g_LastError = 87; return 0; }
    int needed_incl_nul = SharpOSHost_GetSystemString(kind, nullptr, 0);
    if (needed_incl_nul <= 0) { g_LastError = 87; return 0; }
    uint32_t needed = (uint32_t)needed_incl_nul;
    if (lpBuffer == nullptr || *nSize < needed) {
        *nSize = needed;
        g_LastError = k_ERROR_MORE_DATA;
        return 0;
    }
    uint32_t copied = sharpos_wfetch(kind, lpBuffer, *nSize);
    *nSize = copied;
    g_LastError = 0;
    return 1;
}

extern "C" int GetComputerNameExW(int /*NameType*/, wchar_t* lpBuffer, uint32_t* nSize) {
    TRACE_REAL(GetComputerNameExW);
    return sharpos_winsize_fetch(k_SI_MachineName, lpBuffer, nSize);
}
CRT_REAL(GetComputerNameExW);

extern "C" int GetUserNameExW(int /*NameFormat*/, wchar_t* lpNameBuffer, uint32_t* nSize) {
    TRACE_REAL(GetUserNameExW);
    return sharpos_winsize_fetch(k_SI_UserName, lpNameBuffer, nSize);
}
CRT_REAL(GetUserNameExW);

// RTL_OSVERSIONINFOEXW: dwMajor at [+1], dwMinor at [+2], dwBuild at
// [+3], dwPlatformId at [+4]. PAL only marshals; the version values
// come from SharpOSHost_GetOSVersion (kernel-side).
extern "C" void SharpOSHost_GetOSVersion(uint32_t* outMajor, uint32_t* outMinor, uint32_t* outBuild);

extern "C" int32_t RtlGetVersion(void* lpVersionInformation) {
    TRACE_REAL(RtlGetVersion);
    if (lpVersionInformation == nullptr) return (int32_t)0xC000000D;
    uint32_t* fields = (uint32_t*)lpVersionInformation;
    SharpOSHost_GetOSVersion(&fields[1], &fields[2], &fields[3]);
    fields[4] = 2;       // dwPlatformId = VER_PLATFORM_WIN32_NT
    g_LastError = 0;
    return 0;
}
CRT_REAL(RtlGetVersion);

// CHAR NTAPI RtlQueryProcessPlaceholderCompatibilityMode(VOID)
// Used by .NET FileSystem provider startup to detect cloud-file /
// placeholder mode. We have neither concept, so return PHCM_APPLICATION_DEFAULT
// (0). Without this stub, PowerShell's FileSystem provider fails to start →
// Get-ChildItem / Set-Location / FileSystem PSDrive cmdlets unavailable.
extern "C" char RtlQueryProcessPlaceholderCompatibilityMode(void) {
    TRACE_REAL(RtlQueryProcessPlaceholderCompatibilityMode);
    return 0;  // PHCM_APPLICATION_DEFAULT
}
CRT_REAL(RtlQueryProcessPlaceholderCompatibilityMode);

extern "C" int GetVersionExW(void* lpVersionInformation) {
    TRACE_REAL(GetVersionExW);
    return RtlGetVersion(lpVersionInformation) == 0 ? 1 : 0;
}
CRT_REAL(GetVersionExW);

// GetFileAttributesExW -- BCL File.Exists/Directory.Exists probe this.
// Returning FALSE with ERROR_FILE_NOT_FOUND makes File.Exists("foo")
// return `false` without throwing. The actual FS would be reached via
// SharpOSHost_FileOpen-style routing in future iterations; for now we
// honestly report "not found" for everything except the well-known
// SharpOS root.
//
// WIN32_FILE_ATTRIBUTE_DATA layout (out struct, fInfoLevelId=
// GetFileExInfoStandard=0):
//   +0  DWORD dwFileAttributes
//   +4  FILETIME ftCreationTime         (DWORD low+high)
//   +12 FILETIME ftLastAccessTime
//   +20 FILETIME ftLastWriteTime
//   +28 DWORD nFileSizeHigh
//   +32 DWORD nFileSizeLow              (= 36 bytes total)
static const uint32_t k_ERROR_FILE_NOT_FOUND = 2;
static const uint32_t k_FILE_ATTRIBUTE_DIRECTORY = 0x00000010;

// GetComputerNameW (kernel32) -- BCL Environment.MachineName uses the
// non-Ex variant. Marshals through SystemIdentity (KindMachineName).
extern "C" int GetComputerNameW(wchar_t* lpBuffer, uint32_t* nSize) {
    TRACE_REAL(GetComputerNameW);
    return sharpos_winsize_fetch(k_SI_MachineName, lpBuffer, nSize);
}
CRT_REAL(GetComputerNameW);

// GetTimeZoneInformation / GetDynamicTimeZoneInformation -- BCL
// TimeZoneInfo.Local calls these. PAL marshals the Win32 struct shape;
// the actual policy (bias, zone name, no DST) lives kernel-side in
// SystemIdentity (SharpOSHost_GetTimeZoneBiasMinutes / KindTimeZoneName).
//
// TIME_ZONE_INFORMATION layout (172 bytes):
//   +0   LONG Bias                              (4)
//   +4   WCHAR StandardName[32]                  (64)
//   +68  SYSTEMTIME StandardDate                 (16)
//   +84  LONG StandardBias                       (4)
//   +88  WCHAR DaylightName[32]                  (64)
//   +152 SYSTEMTIME DaylightDate                 (16)
//   +168 LONG DaylightBias                       (4)  -> 172 total
//
// DYNAMIC_TIME_ZONE_INFORMATION extends with:
//   +172 WCHAR TimeZoneKeyName[128]              (256)
//   +428 BOOLEAN DynamicDaylightTimeDisabled     (1, padded to 4) -> 432
static const uint32_t k_TIME_ZONE_ID_UNKNOWN = 0;
static const uint32_t k_TIME_ZONE_ID_INVALID = 0xFFFFFFFFu;

extern "C" int SharpOSHost_GetTimeZoneBiasMinutes(void);

// Fill TIME_ZONE_INFORMATION fixed-prefix from kernel-reported state.
// Returns TIME_ZONE_ID_UNKNOWN (no DST) on success.
static uint32_t sharpos_fill_tz(uint8_t* p, uint32_t totalBytes) {
    for (uint32_t i = 0; i < totalBytes; i++) p[i] = 0;
    int biasMinutes = SharpOSHost_GetTimeZoneBiasMinutes();
    *(int32_t*)(p + 0) = biasMinutes;           // Bias (positive = west of UTC)
    // StandardName (offset +4, 32 wchars). Fill from KindTimeZoneName.
    uint8_t tzNameUtf8[16] = {0};
    int got = SharpOSHost_GetSystemString(/*KindTimeZoneName*/8, tzNameUtf8, sizeof(tzNameUtf8));
    if (got > 0) {
        wchar_t* stdName = (wchar_t*)(p + 4);
        int copy = got;
        if (copy > 31) copy = 31;
        for (int i = 0; i < copy; i++) stdName[i] = (wchar_t)tzNameUtf8[i];
        // Mirror as DaylightName at +88 so consumers reading either get
        // a sensible label, even though DST is disabled (zero dates).
        wchar_t* dstName = (wchar_t*)(p + 88);
        for (int i = 0; i < copy; i++) dstName[i] = (wchar_t)tzNameUtf8[i];
    }
    return k_TIME_ZONE_ID_UNKNOWN;
}

extern "C" uint32_t GetTimeZoneInformation(void* lpTimeZoneInformation) {
    TRACE_REAL(GetTimeZoneInformation);
    if (lpTimeZoneInformation == nullptr) {
        g_LastError = 87;
        return k_TIME_ZONE_ID_INVALID;
    }
    g_LastError = 0;
    return sharpos_fill_tz((uint8_t*)lpTimeZoneInformation, 172);
}
CRT_REAL(GetTimeZoneInformation);

extern "C" uint32_t GetDynamicTimeZoneInformation(void* lpDynamicTimeZoneInformation) {
    TRACE_REAL(GetDynamicTimeZoneInformation);
    if (lpDynamicTimeZoneInformation == nullptr) {
        g_LastError = 87;
        return k_TIME_ZONE_ID_INVALID;
    }
    g_LastError = 0;
    return sharpos_fill_tz((uint8_t*)lpDynamicTimeZoneInformation, 432);
}
CRT_REAL(GetDynamicTimeZoneInformation);

// DeleteFileW -- File.Delete. We have no writable FS yet; report
// ERROR_FILE_NOT_FOUND so BCL throws FileNotFoundException... which
// the probe catches as FAIL. The cleaner win comes when writable FS
// lands. For now, returning FALSE without trapping at least lets
// other File.* probes proceed (no chained SEH cascade).
extern "C" int DeleteFileW(const wchar_t* /*lpFileName*/) {
    TRACE_REAL(DeleteFileW);
    g_LastError = k_ERROR_FILE_NOT_FOUND;
    return 0;
}
CRT_REAL(DeleteFileW);

// BCrypt advanced surface -- RandomNumberGenerator.Fill +
// SHA256.HashData go via BCryptOpenAlgorithmProvider("RNG"/"SHA256")
// before calling BCryptGenRandom/CreateHash. The minimal stub set:
//
//   OpenAlgorithmProvider  -> hand back a sentinel handle keyed by algo
//   CloseAlgorithmProvider -> no-op
//   CreateHash             -> allocate a minimal hash context struct
//   HashData               -> SHA-256 incremental update
//   FinishHash             -> emit 32-byte digest
//   DestroyHash            -> free
//
// For now keep the openrng path real (RNG goes via SharpOSHost_FillRandom
// when BCryptGenRandom fires) but SHA256 still requires algo state. We
// route SHA256 through a tiny in-image SHA-256 (FIPS 180-4) compiled
// here; algorithm/HashContext layouts are SharpOS-private (BCL only
// sees opaque handles).

#define SHARPOS_BCRYPT_ALG_RNG     ((void*)(uintptr_t)0xBC011001U)
#define SHARPOS_BCRYPT_ALG_SHA256  ((void*)(uintptr_t)0xBC012001U)

// SHA-256 algorithm proper lives kernel-side in OS.Kernel.Crypto.Sha256
// (C#, see OS/src/Kernel/Crypto/Sha256.cs). PAL is a thin forwarder per
// the SharpOS invariant. These extern declarations bind to the managed
// [RuntimeExport]s in OS/src/PAL/SharpOSHost/Sha256Bridge.cs.
extern "C" void* SharpOSHost_Sha256_Create(void);
extern "C" void  SharpOSHost_Sha256_Update(void* state, const uint8_t* data, uint32_t len);
extern "C" void  SharpOSHost_Sha256_Final(void* state, uint8_t* out32);
extern "C" void  SharpOSHost_Sha256_Snapshot(void* state, uint8_t* out32);
extern "C" void  SharpOSHost_Sha256_Reset(void* state);
extern "C" void  SharpOSHost_Sha256_Destroy(void* state);
extern "C" void  SharpOSHost_Sha256_OneShot(const uint8_t* data, uint32_t len, uint8_t* out32);

// Compare wide-string algorithm IDs against BCL's BCRYPT_RNG_ALGORITHM /
// BCRYPT_SHA256_ALGORITHM constants ("RNG" / "SHA256"). Inline compare
// without pulling a wcscmp -- callers always pass the exact BCL constant
// string. ASCII-only tail (BCL constants are ASCII identifiers).
static int sharpos_wcs_eq_short(const wchar_t* s, const char* t) {
    while (*t) { if ((wchar_t)*t != *s) return 0; t++; s++; }
    return *s == 0;
}

extern "C" int32_t BCryptOpenAlgorithmProvider(void** phAlgorithm, const wchar_t* pszAlgId,
                                               const wchar_t* /*pszImpl*/, uint32_t /*dwFlags*/) {
    TRACE_REAL(BCryptOpenAlgorithmProvider);
    if (phAlgorithm == nullptr || pszAlgId == nullptr) return (int32_t)0xC000000D;
    if (sharpos_wcs_eq_short(pszAlgId, "RNG"))    { *phAlgorithm = SHARPOS_BCRYPT_ALG_RNG;    return 0; }
    if (sharpos_wcs_eq_short(pszAlgId, "SHA256")) { *phAlgorithm = SHARPOS_BCRYPT_ALG_SHA256; return 0; }
    // Unknown algo -- return STATUS_NOT_FOUND so caller fails cleanly via
    // CryptographicException (catchable Exception, not SEH).
    SharpOSHost_DebugPrint("[BCryptOpenAlgo] unknown algo\n");
    *phAlgorithm = nullptr;
    return (int32_t)0xC0000225;
}
CRT_REAL(BCryptOpenAlgorithmProvider);

extern "C" int32_t BCryptCloseAlgorithmProvider(void* /*hAlgorithm*/, uint32_t /*dwFlags*/) {
    TRACE_REAL(BCryptCloseAlgorithmProvider);
    return 0;
}
CRT_REAL(BCryptCloseAlgorithmProvider);

// BCrypt hash handles are opaque pointers handed back by
// SharpOSHost_Sha256_Create (allocation + state init both happen
// kernel-side). PAL never inspects the box.
extern "C" int32_t BCryptCreateHash(void* hAlgorithm, void** phHash, uint8_t* /*pbHashObject*/,
                                    uint32_t /*cbHashObject*/, uint8_t* /*pbSecret*/,
                                    uint32_t /*cbSecret*/, uint32_t /*dwFlags*/) {
    TRACE_REAL(BCryptCreateHash);
    if (phHash == nullptr) return (int32_t)0xC000000D;
    if (hAlgorithm != SHARPOS_BCRYPT_ALG_SHA256) {
        SharpOSHost_DebugPrint("[BCryptCreateHash] non-SHA256 not supported\n");
        return (int32_t)0xC0000225;
    }
    void* state = SharpOSHost_Sha256_Create();
    if (state == nullptr) return (int32_t)0xC0000017;
    *phHash = state;
    return 0;
}
CRT_REAL(BCryptCreateHash);

extern "C" int32_t BCryptHashData(void* hHash, uint8_t* pbInput, uint32_t cbInput, uint32_t /*dwFlags*/) {
    TRACE_REAL(BCryptHashData);
    if (hHash == nullptr) return (int32_t)0xC000000D;
    if (cbInput > 0 && pbInput != nullptr)
        SharpOSHost_Sha256_Update(hHash, pbInput, cbInput);
    return 0;
}
CRT_REAL(BCryptHashData);

extern "C" int32_t BCryptFinishHash(void* hHash, uint8_t* pbOutput, uint32_t cbOutput, uint32_t /*dwFlags*/) {
    TRACE_REAL(BCryptFinishHash);
    if (hHash == nullptr || pbOutput == nullptr) return (int32_t)0xC000000D;
    if (cbOutput < 32) return (int32_t)0xC0000023;
    SharpOSHost_Sha256_Final(hHash, pbOutput);
    return 0;
}
CRT_REAL(BCryptFinishHash);

extern "C" int32_t BCryptDestroyHash(void* hHash) {
    TRACE_REAL(BCryptDestroyHash);
    if (hHash != nullptr) SharpOSHost_Sha256_Destroy(hHash);
    return 0;
}
CRT_REAL(BCryptDestroyHash);

// BCryptGetProperty -- BCL calls this with BCRYPT_HASH_LENGTH ("HashDigestLength")
// to discover digest size. Return 32 (SHA-256 = 32 bytes).
// libSystem.Security.Cryptography.Native.OpenSsl surface used by the
// BCL when System.Private.CoreLib was built with the Unix native shim
// (which is the case in our fork because we share CoreLib with the Unix
// target). RNG + SHA-256 only -- enough to pass the census probes.
//
// CryptoNative_GetRandomBytes(uint8_t* buf, int32_t numBytes)
//   returns 1 on success, 0 on error. We forward to SharpOSHost_FillRandom.
extern "C" int32_t CryptoNative_GetRandomBytes(uint8_t* buf, int32_t numBytes) {
    TRACE_REAL(CryptoNative_GetRandomBytes);
    if (buf == nullptr || numBytes < 0) return 0;
    SharpOSHost_FillRandom(buf, numBytes);
    return 1;
}
CRT_REAL(CryptoNative_GetRandomBytes);

// EVP_MD opaque tag -- BCL holds it as an algorithm identifier passed
// into EvpMdCtxCreate. We only support SHA-256.
#define SHARPOS_EVP_MD_SHA256  ((void*)(uintptr_t)0x5E3702A6U)

extern "C" void* CryptoNative_EvpSha256(void) {
    TRACE_REAL(CryptoNative_EvpSha256);
    return SHARPOS_EVP_MD_SHA256;
}
CRT_REAL(CryptoNative_EvpSha256);

// EVP context is an opaque handle from SharpOSHost_Sha256_Create.
extern "C" void* CryptoNative_EvpMdCtxCreate(void* md) {
    TRACE_REAL(CryptoNative_EvpMdCtxCreate);
    if (md != SHARPOS_EVP_MD_SHA256) {
        SharpOSHost_DebugPrint("[EvpMdCtxCreate] non-SHA256 not supported\n");
        return nullptr;
    }
    return SharpOSHost_Sha256_Create();
}
CRT_REAL(CryptoNative_EvpMdCtxCreate);

extern "C" int32_t CryptoNative_EvpDigestUpdate(void* ctx, const uint8_t* data, int32_t len) {
    TRACE_REAL(CryptoNative_EvpDigestUpdate);
    if (ctx == nullptr) return 0;
    if (len > 0 && data != nullptr)
        SharpOSHost_Sha256_Update(ctx, data, (uint32_t)len);
    return 1;
}
CRT_REAL(CryptoNative_EvpDigestUpdate);

extern "C" int32_t CryptoNative_EvpDigestReset(void* ctx, void* md) {
    TRACE_REAL(CryptoNative_EvpDigestReset);
    if (ctx == nullptr || md != SHARPOS_EVP_MD_SHA256) return 0;
    SharpOSHost_Sha256_Reset(ctx);
    return 1;
}
CRT_REAL(CryptoNative_EvpDigestReset);

extern "C" int32_t CryptoNative_EvpDigestFinalEx(void* ctx, uint8_t* out, uint32_t* outlen) {
    TRACE_REAL(CryptoNative_EvpDigestFinalEx);
    if (ctx == nullptr || out == nullptr) return 0;
    SharpOSHost_Sha256_Final(ctx, out);
    if (outlen) *outlen = 32;
    return 1;
}
CRT_REAL(CryptoNative_EvpDigestFinalEx);

extern "C" int32_t CryptoNative_EvpDigestCurrent(void* ctx, uint8_t* out, uint32_t* outlen) {
    TRACE_REAL(CryptoNative_EvpDigestCurrent);
    if (ctx == nullptr || out == nullptr) return 0;
    SharpOSHost_Sha256_Snapshot(ctx, out);
    if (outlen) *outlen = 32;
    return 1;
}
CRT_REAL(CryptoNative_EvpDigestCurrent);

extern "C" int32_t CryptoNative_EvpDigestOneShot(void* md, const uint8_t* data, int32_t len,
                                                 uint8_t* out, uint32_t* outlen) {
    TRACE_REAL(CryptoNative_EvpDigestOneShot);
    if (md != SHARPOS_EVP_MD_SHA256 || out == nullptr) return 0;
    SharpOSHost_Sha256_OneShot(data, len > 0 ? (uint32_t)len : 0, out);
    if (outlen) *outlen = 32;
    return 1;
}
CRT_REAL(CryptoNative_EvpDigestOneShot);

extern "C" void CryptoNative_EvpMdCtxDestroy(void* ctx) {
    TRACE_REAL(CryptoNative_EvpMdCtxDestroy);
    if (ctx != nullptr) SharpOSHost_Sha256_Destroy(ctx);
}
CRT_REAL(CryptoNative_EvpMdCtxDestroy);

// EvpMdSize(md) -> 32 for SHA-256.
extern "C" int32_t CryptoNative_EvpMdSize(void* md) {
    TRACE_REAL(CryptoNative_EvpMdSize);
    if (md == SHARPOS_EVP_MD_SHA256) return 32;
    return 0;
}
CRT_REAL(CryptoNative_EvpMdSize);

// EnsureOpenSslInitialized -> 0 (success). No real OpenSSL to init.
extern "C" int32_t CryptoNative_EnsureOpenSslInitialized(void) {
    TRACE_REAL(CryptoNative_EnsureOpenSslInitialized);
    return 0;
}
CRT_REAL(CryptoNative_EnsureOpenSslInitialized);

// CryptoNative_GetMaxMdSize -- BCL queries this when sizing hash output
// buffers (max digest across OpenSSL's hash algos). 64 covers SHA-512.
extern "C" int32_t CryptoNative_GetMaxMdSize(void) {
    TRACE_REAL(CryptoNative_GetMaxMdSize);
    return 64;
}
CRT_REAL(CryptoNative_GetMaxMdSize);

extern "C" int32_t BCryptGetProperty(void* /*hObject*/, const wchar_t* pszProperty,
                                     uint8_t* pbOutput, uint32_t cbOutput,
                                     uint32_t* pcbResult, uint32_t /*dwFlags*/) {
    TRACE_REAL(BCryptGetProperty);
    if (pszProperty == nullptr) return (int32_t)0xC000000D;
    if (sharpos_wcs_eq_short(pszProperty, "HashDigestLength")) {
        if (pcbResult) *pcbResult = 4;
        if (cbOutput < 4 || pbOutput == nullptr) return (int32_t)0xC0000023;
        *(uint32_t*)pbOutput = 32;
        return 0;
    }
    if (sharpos_wcs_eq_short(pszProperty, "ObjectLength")) {
        // BCL queries this to size the optional working buffer for
        // BCryptCreateHash. We allocate kernel-side via
        // SharpOSHost_Sha256_Create and ignore pbHashObject, so a
        // generous constant suffices -- 512 bytes covers any plausible
        // future hash state without leaking the kernel struct layout
        // into the PAL.
        if (pcbResult) *pcbResult = 4;
        if (cbOutput < 4 || pbOutput == nullptr) return (int32_t)0xC0000023;
        *(uint32_t*)pbOutput = 512;
        return 0;
    }
    SharpOSHost_DebugPrint("[BCryptGetProperty] unknown property\n");
    return (int32_t)0xC0000225;
}
CRT_REAL(BCryptGetProperty);

// SharpOSHost_GetFileAttributes (kernel-side) is the policy point:
// "which paths exist on SharpOS, and what are their Win32 attrs". PAL
// just marshals the wide path to UTF-8 (ASCII zero-narrow) and forwards.
extern "C" uint32_t SharpOSHost_GetFileAttributes(const uint8_t* utf8Path);

// Convert a Win32 wide path to a UTF-8/ASCII stack buffer. Returns the
// byte length (excl NUL), or -1 if the wide chars include non-ASCII
// (kernel paths are ASCII so this is a clean reject). Buffer must hold
// at least 260 bytes (Win32 MAX_PATH).
static int sharpos_wpath_to_ascii(const wchar_t* w, uint8_t* out, int outCap) {
    if (w == nullptr || out == nullptr || outCap < 2) return -1;
    int i = 0;
    for (;;) {
        wchar_t c = w[i];
        if (c == 0) { out[i] = 0; return i; }
        if (c > 0x7F || i + 1 >= outCap) return -1;
        out[i] = (uint8_t)c;
        i++;
    }
}

// Probe helpers — print wide path char-by-char + hex value via DebugPrintForced.
static void probe_print_wpath(const wchar_t* w) {
    if (w == nullptr) { SharpOSHost_DebugPrintForced("<null>"); return; }
    for (int i = 0; i < 256 && w[i] != 0; i++) {
        char b[2] = { (char)(w[i] & 0xFF), 0 };
        SharpOSHost_DebugPrintForced(b);
    }
}
static void probe_print_hex(uint64_t v) {
    char buf[19] = "0x0000000000000000";
    for (int i = 17; i >= 2; i--) {
        int nib = (int)(v & 0xF);
        buf[i] = (char)(nib < 10 ? ('0' + nib) : ('A' + nib - 10));
        v >>= 4;
    }
    SharpOSHost_DebugPrintForced(buf);
}

// GetFileAttributesW (no Ex) -- BCL Directory.Exists / older paths use
// this. Returns the DWORD attributes bitmask or 0xFFFFFFFF on error.
extern "C" uint32_t GetFileAttributesW(const wchar_t* lpFileName) {
    TRACE_REAL(GetFileAttributesW);
    if (lpFileName == nullptr) {
        g_LastError = 87;
        return 0xFFFFFFFFu;
    }
    uint8_t path[260];
    int n = sharpos_wpath_to_ascii(lpFileName, path, sizeof(path));
    if (n < 0) {
        SharpOSHost_DebugPrintForced("[probe-fs] GetFileAttributesW path=\"");
        probe_print_wpath(lpFileName);
        SharpOSHost_DebugPrintForced("\" → non-ASCII path → INVALID\n");
        g_LastError = k_ERROR_FILE_NOT_FOUND;
        return 0xFFFFFFFFu;
    }
    uint32_t attr = SharpOSHost_GetFileAttributes(path);
    SharpOSHost_DebugPrintForced("[probe-fs] GetFileAttributesW path=\"");
    probe_print_wpath(lpFileName);
    SharpOSHost_DebugPrintForced("\" → attr=");
    probe_print_hex(attr);
    SharpOSHost_DebugPrintForced("\n");
    if (attr == 0xFFFFFFFFu) {
        g_LastError = k_ERROR_FILE_NOT_FOUND;
        return 0xFFFFFFFFu;
    }
    g_LastError = 0;
    return attr;
}
CRT_REAL(GetFileAttributesW);

// FindFirstFileW / FindFirstFileExW / FindNextFileW / FindClose --
// minimal stubs returning "directory empty". For Directory.EnumerateFiles
// to pass: GetFileAttributesW must confirm dir, then FindFirstFileW
// returns INVALID_HANDLE_VALUE with ERROR_FILE_NOT_FOUND, the BCL
// interprets that as "no matches" and yields empty enumeration -- the
// probe passes since it only iterates, not inspects results.
static void* k_INVALID_HANDLE_VALUE = (void*)(intptr_t)-1;

// DirHandle struct + magic + is_dir_handle helper live above CreateFileW
// (see ~line 2295) so all directory-handle dispatch sites share one defn.

// Win32 WIN32_FIND_DATAW layout (592 bytes):
//   0x000 DWORD    dwFileAttributes
//   0x004 FILETIME ftCreationTime    (8)
//   0x00C FILETIME ftLastAccessTime  (8)
//   0x014 FILETIME ftLastWriteTime   (8)
//   0x01C DWORD    nFileSizeHigh
//   0x020 DWORD    nFileSizeLow
//   0x024 DWORD    dwReserved0
//   0x028 DWORD    dwReserved1
//   0x02C WCHAR    cFileName[260]
//   0x234 WCHAR    cAlternateFileName[14]
//   0x250 end
struct DirIterState {
    uint8_t  dirAscii[260];  // directory path (UTF-8 / ASCII, NUL-terminated)
    uint32_t nextIndex;      // index for the NEXT FindNext call
    uint32_t exhausted;      // 1 once the kernel said "no more"
};

// Take a search pattern like "C:\foo\bar\*" and split into directory path
// "C:\foo\bar" (stored ASCII into dst). Returns dir length or -1 on failure.
static int sharpos_split_pattern_dir(const wchar_t* pattern, uint8_t* dst, int dstCap) {
    if (pattern == nullptr || dst == nullptr) return -1;
    // Find last separator.
    int lastSep = -1;
    int len = 0;
    for (; pattern[len] != 0 && len < 1024; len++) {
        if (pattern[len] == L'\\' || pattern[len] == L'/') lastSep = len;
    }
    int dirLen;
    if (lastSep < 0) {
        // No separator — treat whole thing as dir name (rare).
        dirLen = len;
    } else if (lastSep == 0) {
        // Pattern was "\X" — dir is just "\".
        dst[0] = '\\'; dst[1] = 0; return 1;
    } else {
        dirLen = lastSep;
    }
    if (dirLen >= dstCap) return -1;
    for (int i = 0; i < dirLen; i++) {
        wchar_t c = pattern[i];
        if (c > 0x7F) return -1;  // non-ASCII path — bail
        dst[i] = (uint8_t)c;
    }
    dst[dirLen] = 0;
    return dirLen;
}

// Populate WIN32_FIND_DATAW from a single entry name + attributes.
static void sharpos_fill_find_data(void* lpFindFileData, uint32_t attrs,
                                    const wchar_t* name, int nameLen) {
    if (lpFindFileData == nullptr) return;
    uint8_t* p = (uint8_t*)lpFindFileData;
    for (int i = 0; i < 0x250; i++) p[i] = 0;
    *(uint32_t*)(p + 0x000) = attrs;
    wchar_t* cName = (wchar_t*)(p + 0x02C);
    int copy = nameLen;
    if (copy > 259) copy = 259;
    for (int i = 0; i < copy; i++) cName[i] = name[i];
    cName[copy] = 0;
}

// Step the iterator: call kernel, write FIND_DATA. Returns true on success.
static bool sharpos_iter_step(DirIterState* st, void* lpFindFileData) {
    if (st == nullptr || st->exhausted) return false;
    wchar_t nameBuf[260];
    uint32_t attrs = 0;
    uint32_t fileSize = 0;
    uint32_t nameLen = SharpOSHost_FindDirEntry(st->dirAscii, st->nextIndex,
                                                 nameBuf, 260, &attrs, &fileSize);
    st->nextIndex++;
    if (nameLen == 0) { st->exhausted = 1; return false; }
    sharpos_fill_find_data(lpFindFileData, attrs, nameBuf, (int)nameLen);
    return true;
}

extern "C" void* FindFirstFileW(const wchar_t* lpFileName, void* lpFindFileData) {
    TRACE_REAL(FindFirstFileW);
    DirIterState* st = (DirIterState*)SharpOSHost_HeapAlloc(sizeof(DirIterState));
    if (st == nullptr) {
        g_LastError = 8;  // ERROR_NOT_ENOUGH_MEMORY
        return k_INVALID_HANDLE_VALUE;
    }
    for (int i = 0; i < (int)sizeof(DirIterState); i++) ((uint8_t*)st)[i] = 0;
    if (sharpos_split_pattern_dir(lpFileName, st->dirAscii, sizeof(st->dirAscii)) < 0) {
        SharpOSHost_HeapFree(st);
        g_LastError = k_ERROR_FILE_NOT_FOUND;
        return k_INVALID_HANDLE_VALUE;
    }
    st->nextIndex = 0;
    if (!sharpos_iter_step(st, lpFindFileData)) {
        SharpOSHost_HeapFree(st);
        g_LastError = k_ERROR_FILE_NOT_FOUND;
        return k_INVALID_HANDLE_VALUE;
    }
    g_LastError = 0;
    return (void*)st;
}
CRT_REAL(FindFirstFileW);

extern "C" void* FindFirstFileExW(const wchar_t* lpFileName, int /*fInfoLevelId*/,
                                  void* lpFindFileData, int /*fSearchOp*/,
                                  void* /*lpSearchFilter*/, uint32_t /*dwAdditionalFlags*/) {
    TRACE_REAL(FindFirstFileExW);
    return FindFirstFileW(lpFileName, lpFindFileData);
}
CRT_REAL(FindFirstFileExW);

extern "C" int FindNextFileW(void* hFindFile, void* lpFindFileData) {
    TRACE_REAL(FindNextFileW);
    static const uint32_t k_ERROR_NO_MORE_FILES = 18;
    if (hFindFile == nullptr || hFindFile == k_INVALID_HANDLE_VALUE) {
        g_LastError = 6;  // ERROR_INVALID_HANDLE
        return 0;
    }
    DirIterState* st = (DirIterState*)hFindFile;
    if (!sharpos_iter_step(st, lpFindFileData)) {
        g_LastError = k_ERROR_NO_MORE_FILES;
        return 0;
    }
    g_LastError = 0;
    return 1;
}
CRT_REAL(FindNextFileW);

extern "C" int FindClose(void* hFindFile) {
    TRACE_REAL(FindClose);
    if (hFindFile != nullptr && hFindFile != k_INVALID_HANDLE_VALUE)
        SharpOSHost_HeapFree(hFindFile);
    g_LastError = 0;
    return 1;
}
CRT_REAL(FindClose);

// GetFileAttributesExW -- Ex variant with full WIN32_FILE_ATTRIBUTE_DATA
// (36 bytes: dwFileAttributes + 3 FILETIMEs + size hi/lo). PAL marshals
// the path, kernel returns attrs, PAL zero-fills the rest. Times stay
// zero (SharpOS RTC integration is per-RTC-tick; sub-second timestamps
// in directory metadata are out of scope until FS write lands).
extern "C" int GetFileAttributesExW(const wchar_t* lpFileName, int /*fInfoLevelId*/, void* lpFileInformation) {
    TRACE_REAL(GetFileAttributesExW);
    if (lpFileName == nullptr || lpFileInformation == nullptr) {
        g_LastError = 87;
        return 0;
    }
    uint8_t path[260];
    int n = sharpos_wpath_to_ascii(lpFileName, path, sizeof(path));
    if (n < 0) {
        SharpOSHost_DebugPrintForced("[probe-fs] GetFileAttributesExW path=\"");
        probe_print_wpath(lpFileName);
        SharpOSHost_DebugPrintForced("\" → non-ASCII → 0\n");
        g_LastError = k_ERROR_FILE_NOT_FOUND;
        return 0;
    }
    uint32_t attr = SharpOSHost_GetFileAttributes(path);
    SharpOSHost_DebugPrintForced("[probe-fs] GetFileAttributesExW path=\"");
    probe_print_wpath(lpFileName);
    SharpOSHost_DebugPrintForced("\" → attr=");
    probe_print_hex(attr);
    SharpOSHost_DebugPrintForced("\n");
    if (attr == 0xFFFFFFFFu) { g_LastError = k_ERROR_FILE_NOT_FOUND; return 0; }
    uint8_t* p = (uint8_t*)lpFileInformation;
    for (int i = 0; i < 36; i++) p[i] = 0;
    *(uint32_t*)p = attr;
    g_LastError = 0;
    return 1;
}
CRT_REAL(GetFileAttributesExW);

extern "C" const wchar_t* GetCommandLineW(void) { TRACE_REAL(GetCommandLineW); return k_empty_w; }
CRT_REAL(GetCommandLineW);

extern "C" uint32_t GetConsoleOutputCP(void) { TRACE_REAL(GetConsoleOutputCP); return 437; }
CRT_REAL(GetConsoleOutputCP);

// SetConsoleOutputCP / SetConsoleCP — the terminal engine decodes UTF-8 and the
// serial log is bytes either way, so the requested code page changes nothing.
// Report success: a failure here makes PowerShell think the console is broken.
extern "C" int SetConsoleOutputCP(uint32_t /*wCodePageID*/) {
    TRACE_REAL(SetConsoleOutputCP);
    g_LastError = 0;
    return 1;
}
CRT_REAL(SetConsoleOutputCP);

extern "C" int SetConsoleCP(uint32_t /*wCodePageID*/) {
    TRACE_REAL(SetConsoleCP);
    g_LastError = 0;
    return 1;
}
CRT_REAL(SetConsoleCP);

// Codepage queries used by BCL Encoding.OEM / Encoding.ASCII fallback paths.
// PS Get-Content goes through Encoding detection on file read → these must
// resolve or PS throws EntryPointNotFoundException at the read site.
//   437  = OEM US (DOS English)
//   1252 = Windows-1252 (Western European, ANSI default)
//   65001 = UTF-8
extern "C" uint32_t GetOEMCP(void) { TRACE_REAL(GetOEMCP); return 437; }
CRT_REAL(GetOEMCP);

extern "C" uint32_t GetACP(void) { TRACE_REAL(GetACP); return 1252; }
CRT_REAL(GetACP);

extern "C" uint32_t GetConsoleCP(void) { TRACE_REAL(GetConsoleCP); return 437; }
CRT_REAL(GetConsoleCP);

// ─── step125: advapi32 Registry — thin marshal to kernel C# ────────────
// All policy and state live in OS/src/PAL/SharpOSHost/Registry.cs
// (SharpOSHost_Reg* exports). The fork side just:
//   - widens HKEY parameter to uint64_t
//   - converts wide subKey/valueName to bounded UTF-8 byte buffer
//     (registry paths are ASCII in practice)
//   - forwards the call
//   - propagates LSTATUS into both return value and g_LastError
// Per SharpOS invariant: no decisions here ("does this key exist", "what
// error", "which roots are valid"). All of that is in the C# side.

// Kernel-side exports take 64-bit HKEY values (we cast void*→uint64_t at
// the shim boundary) and integer params as uint32_t for predictability.
// The C# side handles the bit-width differences.
extern "C" int SharpOSHost_RegOpenKey(uint64_t hKey, const uint8_t* subKey,
                                       int subKeyLen, uint64_t* phkResult);
extern "C" int SharpOSHost_RegCloseKey(uint64_t hKey);
extern "C" int SharpOSHost_RegQueryValue(uint64_t hKey, const uint8_t* valueName,
                                          int valueNameLen, uint32_t* outType,
                                          uint8_t* outData, uint32_t* outDataLen);
extern "C" int SharpOSHost_RegEnumKey(uint64_t hKey, uint32_t dwIndex,
                                       uint8_t* outName, uint32_t* outNameLen,
                                       uint8_t* outClass, uint32_t* outClassLen,
                                       int64_t* outLastWriteTime);
extern "C" int SharpOSHost_RegEnumValue(uint64_t hKey, uint32_t dwIndex,
                                         uint8_t* outName, uint32_t* outNameLen,
                                         uint32_t* outType,
                                         uint8_t* outData, uint32_t* outDataLen);
extern "C" int SharpOSHost_RegQueryInfoKey(uint64_t hKey,
                                            uint8_t* outClass, uint32_t* outClassLen,
                                            uint32_t* outNumSubKeys, uint32_t* outMaxSubKeyLen,
                                            uint32_t* outMaxClassLen,
                                            uint32_t* outNumValues, uint32_t* outMaxValueNameLen,
                                            uint32_t* outMaxValueDataLen,
                                            uint32_t* outSecurityDescriptor,
                                            int64_t* outLastWriteTime);
extern "C" int SharpOSHost_RegCreateKey(uint64_t hKey, const uint8_t* subKey,
                                         int subKeyLen, uint32_t reserved,
                                         const uint8_t* keyClass, uint32_t options,
                                         uint32_t samDesired, void* securityAttrs,
                                         uint64_t* phkResult, uint32_t* outDisposition);
extern "C" int SharpOSHost_RegFlushKey(uint64_t hKey);

// Helper: zero-extend wide to UTF-8 byte buffer. Registry strings are
// ASCII in practice; bounded copy avoids unbounded user input.
static int sharpos_wide_to_bytes(const wchar_t* src, uint8_t* dst, int dstCap) {
    if (src == nullptr || dst == nullptr || dstCap <= 0) return 0;
    int i = 0;
    while (i < dstCap - 1 && src[i] != 0) {
        dst[i] = (uint8_t)(src[i] & 0xFF);
        i++;
    }
    dst[i] = 0;
    return i;
}

// Win32 SDK signatures: LSTATUS=long, HKEY=void*, DWORD=unsigned long,
// REGSAM=DWORD, PHKEY=HKEY*. Must match advapi32 SDK declarations exactly
// (winreg.h is transitively included) — otherwise C++ flags conflicting
// types at link.

extern "C" long RegOpenKeyExW(void* hKey, const wchar_t* lpSubKey,
                               unsigned long /*ulOptions*/, unsigned long /*samDesired*/,
                               void** phkResult) {
    TRACE_REAL(RegOpenKeyExW);
    uint8_t buf[260];
    int len = sharpos_wide_to_bytes(lpSubKey, buf, (int)sizeof(buf));
    uint64_t outHKey = 0;
    int status = SharpOSHost_RegOpenKey((uint64_t)(uintptr_t)hKey, buf, len, &outHKey);
    if (phkResult != nullptr) *phkResult = (void*)(uintptr_t)outHKey;
    g_LastError = (uint32_t)status;
    return (long)status;
}
CRT_REAL(RegOpenKeyExW);

extern "C" long RegCloseKey(void* hKey) {
    TRACE_REAL(RegCloseKey);
    int status = SharpOSHost_RegCloseKey((uint64_t)(uintptr_t)hKey);
    g_LastError = (uint32_t)status;
    return (long)status;
}
CRT_REAL(RegCloseKey);

extern "C" long RegQueryValueExW(void* hKey, const wchar_t* lpValueName,
                                  unsigned long* /*lpReserved*/, unsigned long* lpType,
                                  unsigned char* lpData, unsigned long* lpcbData) {
    TRACE_REAL(RegQueryValueExW);
    uint8_t buf[260];
    int len = sharpos_wide_to_bytes(lpValueName, buf, (int)sizeof(buf));
    uint32_t outType = 0;
    uint32_t outDataLen = 0;
    int status = SharpOSHost_RegQueryValue((uint64_t)(uintptr_t)hKey, buf, len,
                                            &outType, lpData, &outDataLen);
    if (lpType   != nullptr) *lpType   = (unsigned long)outType;
    if (lpcbData != nullptr) *lpcbData = (unsigned long)outDataLen;
    g_LastError = (uint32_t)status;
    return (long)status;
}
CRT_REAL(RegQueryValueExW);

extern "C" long RegEnumKeyExW(void* hKey, unsigned long dwIndex,
                               wchar_t* /*lpName*/, unsigned long* lpcchName,
                               unsigned long* /*lpReserved*/,
                               wchar_t* /*lpClass*/, unsigned long* lpcchClass,
                               long long* lpftLastWriteTime) {
    TRACE_REAL(RegEnumKeyExW);
    uint32_t nameLen = 0, classLen = 0;
    int64_t lwt = 0;
    int status = SharpOSHost_RegEnumKey((uint64_t)(uintptr_t)hKey, (uint32_t)dwIndex,
                                         nullptr, &nameLen,
                                         nullptr, &classLen,
                                         &lwt);
    if (lpcchName  != nullptr) *lpcchName  = (unsigned long)nameLen;
    if (lpcchClass != nullptr) *lpcchClass = (unsigned long)classLen;
    if (lpftLastWriteTime != nullptr) *lpftLastWriteTime = lwt;
    g_LastError = (uint32_t)status;
    return (long)status;
}
CRT_REAL(RegEnumKeyExW);

extern "C" long RegEnumValueW(void* hKey, unsigned long dwIndex,
                               wchar_t* /*lpValueName*/, unsigned long* lpcchValueName,
                               unsigned long* /*lpReserved*/, unsigned long* lpType,
                               unsigned char* lpData, unsigned long* lpcbData) {
    TRACE_REAL(RegEnumValueW);
    uint32_t nameLen = 0, outType = 0, outDataLen = 0;
    int status = SharpOSHost_RegEnumValue((uint64_t)(uintptr_t)hKey, (uint32_t)dwIndex,
                                           nullptr, &nameLen,
                                           &outType, lpData, &outDataLen);
    if (lpcchValueName != nullptr) *lpcchValueName = (unsigned long)nameLen;
    if (lpType         != nullptr) *lpType         = (unsigned long)outType;
    if (lpcbData       != nullptr) *lpcbData       = (unsigned long)outDataLen;
    g_LastError = (uint32_t)status;
    return (long)status;
}
CRT_REAL(RegEnumValueW);

extern "C" long RegQueryInfoKeyW(void* hKey,
                                  wchar_t* /*lpClass*/, unsigned long* lpcchClass,
                                  unsigned long* /*lpReserved*/,
                                  unsigned long* lpcSubKeys, unsigned long* lpcbMaxSubKeyLen,
                                  unsigned long* lpcbMaxClassLen,
                                  unsigned long* lpcValues, unsigned long* lpcbMaxValueNameLen,
                                  unsigned long* lpcbMaxValueLen,
                                  unsigned long* lpcbSecurityDescriptor,
                                  long long* lpftLastWriteTime) {
    TRACE_REAL(RegQueryInfoKeyW);
    uint32_t classLen = 0, numSubKeys = 0, maxSubKeyLen = 0, maxClassLen = 0;
    uint32_t numValues = 0, maxValueNameLen = 0, maxValueLen = 0, securityDescriptor = 0;
    int64_t lwt = 0;
    int status = SharpOSHost_RegQueryInfoKey((uint64_t)(uintptr_t)hKey,
                                              nullptr, &classLen,
                                              &numSubKeys, &maxSubKeyLen, &maxClassLen,
                                              &numValues, &maxValueNameLen, &maxValueLen,
                                              &securityDescriptor,
                                              &lwt);
    if (lpcchClass             != nullptr) *lpcchClass             = (unsigned long)classLen;
    if (lpcSubKeys             != nullptr) *lpcSubKeys             = (unsigned long)numSubKeys;
    if (lpcbMaxSubKeyLen       != nullptr) *lpcbMaxSubKeyLen       = (unsigned long)maxSubKeyLen;
    if (lpcbMaxClassLen        != nullptr) *lpcbMaxClassLen        = (unsigned long)maxClassLen;
    if (lpcValues              != nullptr) *lpcValues              = (unsigned long)numValues;
    if (lpcbMaxValueNameLen    != nullptr) *lpcbMaxValueNameLen    = (unsigned long)maxValueNameLen;
    if (lpcbMaxValueLen        != nullptr) *lpcbMaxValueLen        = (unsigned long)maxValueLen;
    if (lpcbSecurityDescriptor != nullptr) *lpcbSecurityDescriptor = (unsigned long)securityDescriptor;
    if (lpftLastWriteTime      != nullptr) *lpftLastWriteTime      = lwt;
    g_LastError = (uint32_t)status;
    return (long)status;
}
CRT_REAL(RegQueryInfoKeyW);

extern "C" long RegCreateKeyExW(void* hKey, const wchar_t* lpSubKey,
                                 unsigned long reserved, const wchar_t* lpClass,
                                 unsigned long dwOptions, unsigned long samDesired,
                                 void* lpSecurityAttributes, void** phkResult,
                                 unsigned long* lpdwDisposition) {
    TRACE_REAL(RegCreateKeyExW);
    uint8_t subKeyBuf[260];
    uint8_t classBuf[64];
    int subKeyLen = sharpos_wide_to_bytes(lpSubKey, subKeyBuf, (int)sizeof(subKeyBuf));
    sharpos_wide_to_bytes(lpClass, classBuf, (int)sizeof(classBuf));
    uint64_t outHKey = 0;
    uint32_t outDisposition = 0;
    int status = SharpOSHost_RegCreateKey((uint64_t)(uintptr_t)hKey, subKeyBuf, subKeyLen,
                                           (uint32_t)reserved,
                                           classBuf, (uint32_t)dwOptions, (uint32_t)samDesired,
                                           lpSecurityAttributes, &outHKey, &outDisposition);
    if (phkResult       != nullptr) *phkResult       = (void*)(uintptr_t)outHKey;
    if (lpdwDisposition != nullptr) *lpdwDisposition = (unsigned long)outDisposition;
    g_LastError = (uint32_t)status;
    return (long)status;
}
CRT_REAL(RegCreateKeyExW);

extern "C" long RegFlushKey(void* hKey) {
    TRACE_REAL(RegFlushKey);
    int status = SharpOSHost_RegFlushKey((uint64_t)(uintptr_t)hKey);
    g_LastError = (uint32_t)status;
    return (long)status;
}
CRT_REAL(RegFlushKey);

// ─── step126: advapi32 Token/Privilege stubs (no logic, return failure) ──
// ProcessManager::.cctor (Windows-impl System.Diagnostics.Process.dll)
// tries to acquire SE_DEBUG_NAME privilege via OpenProcessToken +
// LookupPrivilegeValueW + AdjustTokenPrivileges. On unikernel there are
// no privileges/tokens — return controlled failure so cctor logs and
// continues (BCL handles "can't adjust privilege" gracefully).
//
// Win32 error codes (WinError.h):
//   ERROR_NO_SUCH_PRIVILEGE = 1313
//   ERROR_NOT_ENOUGH_MEMORY = 8
//   ERROR_INVALID_HANDLE = 6

// Kernel-side policy lives in OS/src/PAL/SharpOSHost/TokenSecurity.cs.
// Fork shims convert ABI shape and propagate kernel's error code → g_LastError
// → BOOL return.
extern "C" int  SharpOSHost_LookupPrivilegeValue(uint64_t* outLuid);
extern "C" int  SharpOSHost_LookupPrivilegeName(unsigned long* outNameLen);
extern "C" int  SharpOSHost_OpenProcessToken(void** outToken);
extern "C" int  SharpOSHost_OpenThreadToken(void** outToken);
extern "C" int  SharpOSHost_AdjustTokenPrivileges(void);
extern "C" int  SharpOSHost_GetTokenInformation(unsigned long* outReturnLen);
extern "C" int  SharpOSHost_ImpersonateLoggedOnUser(void);
extern "C" int  SharpOSHost_RevertToSelf(void);
extern "C" int  SharpOSHost_CheckTokenMembership(int* outIsMember);
extern "C" int  SharpOSHost_DuplicateTokenEx(void** outNewToken);

extern "C" int LookupPrivilegeValueW(const wchar_t* /*lpSystemName*/,
                                      const wchar_t* /*lpName*/,
                                      void* lpLuid) {
    TRACE_REAL(LookupPrivilegeValueW);
    int err = SharpOSHost_LookupPrivilegeValue((uint64_t*)lpLuid);
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(LookupPrivilegeValueW);

extern "C" int LookupPrivilegeNameW(const wchar_t* /*lpSystemName*/,
                                     void* /*lpLuid*/,
                                     wchar_t* /*lpName*/, unsigned long* lpcchName) {
    TRACE_REAL(LookupPrivilegeNameW);
    int err = SharpOSHost_LookupPrivilegeName(lpcchName);
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(LookupPrivilegeNameW);

extern "C" int OpenProcessToken(void* /*ProcessHandle*/,
                                 unsigned long /*DesiredAccess*/,
                                 void** TokenHandle) {
    TRACE_REAL(OpenProcessToken);
    int err = SharpOSHost_OpenProcessToken(TokenHandle);
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(OpenProcessToken);

extern "C" int OpenThreadToken(void* /*ThreadHandle*/,
                                unsigned long /*DesiredAccess*/,
                                int /*OpenAsSelf*/,
                                void** TokenHandle) {
    TRACE_REAL(OpenThreadToken);
    int err = SharpOSHost_OpenThreadToken(TokenHandle);
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(OpenThreadToken);

extern "C" int AdjustTokenPrivileges(void* /*TokenHandle*/, int /*DisableAllPrivileges*/,
                                      void* /*NewState*/, unsigned long /*BufferLength*/,
                                      void* /*PreviousState*/, unsigned long* /*ReturnLength*/) {
    TRACE_REAL(AdjustTokenPrivileges);
    int err = SharpOSHost_AdjustTokenPrivileges();
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(AdjustTokenPrivileges);

extern "C" int GetTokenInformation(void* /*TokenHandle*/, int /*TokenInformationClass*/,
                                    void* /*TokenInformation*/, unsigned long /*TokenInformationLength*/,
                                    unsigned long* ReturnLength) {
    TRACE_REAL(GetTokenInformation);
    int err = SharpOSHost_GetTokenInformation(ReturnLength);
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(GetTokenInformation);

extern "C" int ImpersonateLoggedOnUser(void* /*hToken*/) {
    TRACE_REAL(ImpersonateLoggedOnUser);
    int err = SharpOSHost_ImpersonateLoggedOnUser();
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(ImpersonateLoggedOnUser);

extern "C" int RevertToSelf(void) {
    TRACE_REAL(RevertToSelf);
    int err = SharpOSHost_RevertToSelf();
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(RevertToSelf);

// SaferIdentifyLevel — Win32 Software Restriction Policy classifier. PS uses
// it via System.Management.Automation.Security.SystemPolicy.GetAppLockerPolicy
// to decide between FullLanguage and ConstrainedLanguage. On unikernel
// there's no SRP; return success with SAFER_LEVELID_FULLYTRUSTED so the
// shim's lpLevelHandle out-pointer carries that sentinel and PS treats
// every script as fully trusted → FullLanguage → cmdlets register normally.
#define SHARPOS_SAFER_LEVEL_FULLYTRUSTED  ((void*)(uintptr_t)0x40000U)
extern "C" int SaferIdentifyLevel(uint32_t /*dwNumProperties*/,
                                   void* /*pCodeProperties*/,
                                   void** lpLevelHandle,
                                   const wchar_t* /*lpszReserved*/) {
    TRACE_REAL(SaferIdentifyLevel);
    if (lpLevelHandle) *lpLevelHandle = SHARPOS_SAFER_LEVEL_FULLYTRUSTED;
    g_LastError = 0;
    return 1;  // TRUE
}
CRT_REAL(SaferIdentifyLevel);

extern "C" int SaferIdentifyLevelA(uint32_t /*dwNumProperties*/,
                                    void* /*pCodeProperties*/,
                                    void** lpLevelHandle,
                                    const char* /*lpszReserved*/) {
    TRACE_REAL(SaferIdentifyLevelA);
    if (lpLevelHandle) *lpLevelHandle = SHARPOS_SAFER_LEVEL_FULLYTRUSTED;
    g_LastError = 0;
    return 1;
}
CRT_REAL(SaferIdentifyLevelA);

// SaferGetLevelInformation — PS queries identifier from the level handle to
// confirm trust. Class 1 = SaferObjectLevelId. Return value: SAFER_LEVELID_FULLYTRUSTED = 0x40000.
extern "C" int SaferGetLevelInformation(void* /*hLevelHandle*/,
                                         uint32_t dwInfoType,
                                         void* lpQueryBuffer,
                                         uint32_t /*dwInBufferSize*/,
                                         uint32_t* lpdwOutBufferSize) {
    TRACE_REAL(SaferGetLevelInformation);
    if (dwInfoType == 1 /*SaferObjectLevelId*/ && lpQueryBuffer) {
        *(uint32_t*)lpQueryBuffer = 0x40000;  // SAFER_LEVELID_FULLYTRUSTED
        if (lpdwOutBufferSize) *lpdwOutBufferSize = 4;
        g_LastError = 0;
        return 1;
    }
    g_LastError = 87;
    return 0;
}
CRT_REAL(SaferGetLevelInformation);

extern "C" int SaferCloseLevel(void* /*hLevelHandle*/) {
    TRACE_REAL(SaferCloseLevel);
    g_LastError = 0;
    return 1;
}
CRT_REAL(SaferCloseLevel);

// SaferComputeTokenFromLevel — given a SAFER level handle, build the restricted
// access token the code must run under. The verdict travels in the OUT token,
// not the return value: NULL means "no restriction applies". Handing back a
// non-null sentinel told PowerShell the opposite — that a restricted token was
// required — and it refused to load PSReadLine's format file with "blocked by
// software restriction policies". Kernel policy lives in
// OS/src/PAL/SharpOSHost/SaferPolicy.cs.
extern "C" int SharpOSHost_SaferComputeTokenFromLevel(void** outAccessToken);
extern "C" int SaferComputeTokenFromLevel(void* /*LevelHandle*/,
                                           void* /*InAccessToken*/,
                                           void** OutAccessToken,
                                           uint32_t /*dwFlags*/,
                                           void* /*lpReserved*/) {
    TRACE_REAL(SaferComputeTokenFromLevel);
    int ok = SharpOSHost_SaferComputeTokenFromLevel(OutAccessToken);
    g_LastError = 0;
    return ok;
}
CRT_REAL(SaferComputeTokenFromLevel);

extern "C" int CheckTokenMembership(void* /*TokenHandle*/, void* /*SidToCheck*/, int* IsMember) {
    TRACE_REAL(CheckTokenMembership);
    int err = SharpOSHost_CheckTokenMembership(IsMember);
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(CheckTokenMembership);

extern "C" int DuplicateTokenEx(void* /*hExistingToken*/, unsigned long /*dwDesiredAccess*/,
                                 void* /*lpTokenAttributes*/, int /*ImpersonationLevel*/,
                                 int /*TokenType*/, void** phNewToken) {
    TRACE_REAL(DuplicateTokenEx);
    int err = SharpOSHost_DuplicateTokenEx(phNewToken);
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(DuplicateTokenEx);

// ─── step126.2: shell32 known-folder stubs (no logic, controlled failure) ──
// PowerShell's System.Management.Automation.Platform::.cctor calls
// Environment.GetFolderPath(SpecialFolder.ApplicationData / UserProfile /
// ProgramData / ...) which on Windows-impl SPC routes through:
//   Environment.GetFolderPathCore
//     → Interop.Shell32.SHGetKnownFolderPath  (preferred, new API)
//     → Interop.Shell32.SHGetFolderPathW       (legacy fallback)
// On non-zero HRESULT, BCL returns string.Empty → caller treats as
// "no profile path" and uses defaults (PowerShell stops looking for
// PSReadLine history / module roots / user profile, continues init).
//
// On unikernel there's no per-user roaming/profile/known-folder concept;
// returning E_FAIL is the semantically correct answer.
//
// Win32 HRESULT codes (WinError.h):
//   E_FAIL = 0x80004005
//   E_INVALIDARG = 0x80070057

// Kernel-side policy in OS/src/PAL/SharpOSHost/ShellFolders.cs.
extern "C" int SharpOSHost_ShellGetKnownFolderPath(void** outPathPtr);
extern "C" int SharpOSHost_ShellGetFolderPath(wchar_t* pszPath);

extern "C" long SHGetKnownFolderPath(const void* /*rfid*/, unsigned long /*dwFlags*/,
                                      void* /*hToken*/, wchar_t** ppszPath) {
    TRACE_REAL(SHGetKnownFolderPath);
    return (long)SharpOSHost_ShellGetKnownFolderPath((void**)ppszPath);
}
CRT_REAL(SHGetKnownFolderPath);

extern "C" long SHGetFolderPathW(void* /*hwnd*/, int /*csidl*/, void* /*hToken*/,
                                  unsigned long /*dwFlags*/, wchar_t* pszPath) {
    TRACE_REAL(SHGetFolderPathW);
    return (long)SharpOSHost_ShellGetFolderPath(pszPath);
}
CRT_REAL(SHGetFolderPathW);

// ─── step126.4: wldp (Lock Down Policy) — return "no policy / allow" ─────
// PowerShell uses these for:
//   - Constrained Language Mode detection (WldpGetLockdownPolicy)
//   - Dynamic code trust (WldpQueryDynamicCodeTrust) — affects Add-Type
//   - COM approved-list check (WldpIsClassInApprovedList) — affects scripting
// On unikernel no policy is active; return success + "allowed" values.
//
// WLDP_LOCKDOWN_STATE values (wldp.h):
//   WLDP_LOCKDOWN_OFF      = 0x00000000
//   WLDP_LOCKDOWN_DEFINED  = 0x80000000  (policy is set, see other bits)
//   WLDP_LOCKDOWN_CONFIG_CI_AUDIT  = 0x4
//   WLDP_LOCKDOWN_CONFIG_CI = 0x8
//   WLDP_LOCKDOWN_UMCIENFORCE = 0x40000000

// Kernel-side policy in OS/src/PAL/SharpOSHost/LockdownPolicy.cs.
extern "C" int SharpOSHost_WldpGetLockdownPolicy(unsigned long* outState);
extern "C" int SharpOSHost_WldpQueryDynamicCodeTrust(void);
extern "C" int SharpOSHost_WldpSetDynamicCodeTrust(void);
extern "C" int SharpOSHost_WldpIsClassInApprovedList(int* outApproved);
extern "C" int SharpOSHost_WldpQueryWindowsLockdownMode(unsigned long* outMode);
extern "C" int SharpOSHost_WldpIsDynamicCodePolicyEnabled(int* outEnabled);
extern "C" int SharpOSHost_WldpCanExecuteFile(int* outResult);

extern "C" long WldpGetLockdownPolicy(void* /*pHostInformation*/,
                                       unsigned long* lockdownState,
                                       unsigned long /*lockdownFlags*/) {
    TRACE_REAL(WldpGetLockdownPolicy);
    return (long)SharpOSHost_WldpGetLockdownPolicy(lockdownState);
}
CRT_REAL(WldpGetLockdownPolicy);

extern "C" long WldpQueryDynamicCodeTrust(void* /*fileHandle*/,
                                           const void* /*baseImage*/,
                                           unsigned long /*imageSize*/) {
    TRACE_REAL(WldpQueryDynamicCodeTrust);
    return (long)SharpOSHost_WldpQueryDynamicCodeTrust();
}
CRT_REAL(WldpQueryDynamicCodeTrust);

extern "C" long WldpSetDynamicCodeTrust(void* /*fileHandle*/) {
    TRACE_REAL(WldpSetDynamicCodeTrust);
    return (long)SharpOSHost_WldpSetDynamicCodeTrust();
}
CRT_REAL(WldpSetDynamicCodeTrust);

extern "C" long WldpIsClassInApprovedList(const void* /*classID*/,
                                           const void* /*hostInformation*/,
                                           int* isApproved,
                                           unsigned long /*optionalFlags*/) {
    TRACE_REAL(WldpIsClassInApprovedList);
    return (long)SharpOSHost_WldpIsClassInApprovedList(isApproved);
}
CRT_REAL(WldpIsClassInApprovedList);

extern "C" long WldpQueryWindowsLockdownMode(unsigned long* lockdownMode) {
    TRACE_REAL(WldpQueryWindowsLockdownMode);
    return (long)SharpOSHost_WldpQueryWindowsLockdownMode(lockdownMode);
}
CRT_REAL(WldpQueryWindowsLockdownMode);

extern "C" long WldpIsDynamicCodePolicyEnabled(int* isEnabled) {
    TRACE_REAL(WldpIsDynamicCodePolicyEnabled);
    return (long)SharpOSHost_WldpIsDynamicCodePolicyEnabled(isEnabled);
}
CRT_REAL(WldpIsDynamicCodePolicyEnabled);

extern "C" long WldpCanExecuteFile(const void* /*host*/,
                                    unsigned long /*options*/,
                                    void* /*fileHandle*/,
                                    const wchar_t* /*auditInfo*/,
                                    int* result) {
    TRACE_REAL(WldpCanExecuteFile);
    return (long)SharpOSHost_WldpCanExecuteFile(result);
}
CRT_REAL(WldpCanExecuteFile);

// step126.9: amsi.dll shims. Kernel policy in AmsiPolicy.cs returns CLEAN.
extern "C" int  SharpOSHost_AmsiInitialize(uint64_t* outContext);
extern "C" void SharpOSHost_AmsiUninitialize(void);
extern "C" int  SharpOSHost_AmsiOpenSession(uint64_t* outSession);
extern "C" void SharpOSHost_AmsiCloseSession(void);
extern "C" int  SharpOSHost_AmsiScan(unsigned int* outResult);

extern "C" long AmsiInitialize(const wchar_t* /*appName*/, void** amsiContext) {
    TRACE_REAL(AmsiInitialize);
    uint64_t ctx = 0;
    int hr = SharpOSHost_AmsiInitialize(&ctx);
    if (amsiContext != nullptr) *amsiContext = (void*)(uintptr_t)ctx;
    return (long)hr;
}
CRT_REAL(AmsiInitialize);

extern "C" void AmsiUninitialize(void* /*amsiContext*/) {
    TRACE_REAL(AmsiUninitialize);
    SharpOSHost_AmsiUninitialize();
}
CRT_REAL(AmsiUninitialize);

extern "C" long AmsiOpenSession(void* /*amsiContext*/, void** session) {
    TRACE_REAL(AmsiOpenSession);
    uint64_t s = 0;
    int hr = SharpOSHost_AmsiOpenSession(&s);
    if (session != nullptr) *session = (void*)(uintptr_t)s;
    return (long)hr;
}
CRT_REAL(AmsiOpenSession);

extern "C" void AmsiCloseSession(void* /*amsiContext*/, void* /*session*/) {
    TRACE_REAL(AmsiCloseSession);
    SharpOSHost_AmsiCloseSession();
}
CRT_REAL(AmsiCloseSession);

extern "C" long AmsiScanString(void* /*amsiContext*/, const wchar_t* /*string*/,
                                const wchar_t* /*contentName*/, void* /*session*/,
                                unsigned int* outResult) {
    TRACE_REAL(AmsiScanString);
    return (long)SharpOSHost_AmsiScan(outResult);
}
CRT_REAL(AmsiScanString);

extern "C" long AmsiScanBuffer(void* /*amsiContext*/, const void* /*buffer*/,
                                unsigned int /*length*/, const wchar_t* /*contentName*/,
                                void* /*session*/, unsigned int* outResult) {
    TRACE_REAL(AmsiScanBuffer);
    return (long)SharpOSHost_AmsiScan(outResult);
}
CRT_REAL(AmsiScanBuffer);

extern "C" int SharpOSHost_AmsiNotifyOperation(void);
extern "C" long AmsiNotifyOperation(void* /*amsiContext*/, const wchar_t* /*op*/,
                                     const wchar_t* /*contentName*/) {
    TRACE_REAL(AmsiNotifyOperation);
    return (long)SharpOSHost_AmsiNotifyOperation();
}
CRT_REAL(AmsiNotifyOperation);

extern "C" long AmsiNotifyOperationA(void* /*amsiContext*/, const char* /*op*/,
                                      const char* /*contentName*/) {
    TRACE_REAL(AmsiNotifyOperationA);
    return (long)SharpOSHost_AmsiNotifyOperation();
}
CRT_REAL(AmsiNotifyOperationA);

// step126.18: kernel32 drive-info / process-list shims for FileSystem
// provider startup. Kernel policy: single virtual C: drive backed by
// \sharpos\; single process pid=1. Unblocks Get-ChildItem/Set-Location/etc.
extern "C" unsigned int SharpOSHost_GetLogicalDrives(void);
extern "C" int          SharpOSHost_GetVolumeInformation(unsigned int* outSerial,
                                                         unsigned int* outMaxComp,
                                                         unsigned int* outFsFlags);
extern "C" int          SharpOSHost_EnumProcesses(unsigned int* outPid);

extern "C" unsigned int GetLogicalDrives(void) {
    TRACE_REAL(GetLogicalDrives);
    g_LastError = 0;
    return SharpOSHost_GetLogicalDrives();
}
CRT_REAL(GetLogicalDrives);

// BOOL GetVolumeInformationW(LPCWSTR root, LPWSTR nameBuf, DWORD nameSize,
//   LPDWORD serial, LPDWORD maxComp, LPDWORD fsFlags, LPWSTR fsNameBuf,
//   DWORD fsNameSize)
extern "C" int GetVolumeInformationW(const wchar_t* /*lpRootPathName*/,
                                      wchar_t* lpVolumeNameBuffer,
                                      unsigned int nVolumeNameSize,
                                      unsigned int* lpVolumeSerialNumber,
                                      unsigned int* lpMaximumComponentLength,
                                      unsigned int* lpFileSystemFlags,
                                      wchar_t* lpFileSystemNameBuffer,
                                      unsigned int nFileSystemNameSize) {
    TRACE_REAL(GetVolumeInformationW);
    int ok = SharpOSHost_GetVolumeInformation(lpVolumeSerialNumber,
                                              lpMaximumComponentLength,
                                              lpFileSystemFlags);
    g_LastError = ok ? 0 : 87;
    if (ok && lpVolumeNameBuffer && nVolumeNameSize > 0) {
        // Volume label "SharpOS" + L'\0' if it fits.
        const wchar_t* lbl = L"SharpOS";
        unsigned int i = 0;
        while (lbl[i] && i + 1 < nVolumeNameSize) { lpVolumeNameBuffer[i] = lbl[i]; i++; }
        lpVolumeNameBuffer[i] = 0;
    }
    if (ok && lpFileSystemNameBuffer && nFileSystemNameSize > 0) {
        const wchar_t* fs = L"FAT";
        unsigned int i = 0;
        while (fs[i] && i + 1 < nFileSystemNameSize) { lpFileSystemNameBuffer[i] = fs[i]; i++; }
        lpFileSystemNameBuffer[i] = 0;
    }
    return ok;
}
CRT_REAL(GetVolumeInformationW);

// BOOL K32EnumProcesses(DWORD* lpidProcess, DWORD cb, LPDWORD lpcbNeeded)
// ULONG GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved,
//                            PIP_ADAPTER_ADDRESSES AdapterAddresses,
//                            PULONG SizePointer)
// PS PSDrive auto-mount enumerates net adapters via this. ERROR_NO_DATA (232)
// = "no adapters" → init proceeds without trying to mount any network drives.
extern "C" unsigned long GetAdaptersAddresses(unsigned long /*Family*/,
                                               unsigned long /*Flags*/,
                                               void* /*Reserved*/,
                                               void* /*AdapterAddresses*/,
                                               unsigned long* SizePointer) {
    TRACE_REAL(GetAdaptersAddresses);
    if (SizePointer) *SizePointer = 0;
    return 232;  // ERROR_NO_DATA
}
CRT_REAL(GetAdaptersAddresses);

// DWORD WNetGetConnectionW(LPCWSTR lpLocalName, LPWSTR lpRemoteName,
//                           LPDWORD lpnLength)
// PS calls this during PSDrive auto-mount to classify drives local vs network.
// ERROR_NOT_CONNECTED (2250) = "this local name is not redirected to a
// network resource" → PS treats drive as local, init proceeds.
extern "C" unsigned long WNetGetConnectionW(const wchar_t* /*lpLocalName*/,
                                             wchar_t* /*lpRemoteName*/,
                                             unsigned long* lpnLength) {
    TRACE_REAL(WNetGetConnectionW);
    if (lpnLength) *lpnLength = 0;
    return 2250;  // ERROR_NOT_CONNECTED
}
CRT_REAL(WNetGetConnectionW);

// WinVerifyTrust: Authenticode signature verification entry point.
//   LONG WinVerifyTrust(HWND hwnd, GUID* pgActionID, void* pWVTData);
// Return TRUST_E_NOSIGNATURE (0x800B0100) = "file is not signed". On success
// (return 0) PS extracts the signer cert via WTHelperProvDataFromStateData;
// we didn't populate pWVTData, so that extraction throws. Returning
// "not signed" makes PS skip cert extraction and fall back to AppLocker /
// system policy — both stubbed to "trusted" → FullLanguage.
extern "C" long WinVerifyTrust(void* /*hwnd*/, void* /*pgActionID*/, void* /*pWVTData*/) {
    TRACE_REAL(WinVerifyTrust);
    return (long)0x800B0100;  // TRUST_E_NOSIGNATURE
}
CRT_REAL(WinVerifyTrust);

// wintrust helpers. PowerShell asks for the provider data behind a state
// handle after WinVerifyTrust answers, to describe the signer. Kernel policy
// (OS/src/PAL/SharpOSHost/AuthenticodePolicy.cs) has nothing to describe: no
// verification ran, so there is no provider data, signer or certificate.
// These exist because the P/Invoke has to *resolve* — importing PSReadLine
// failed at entry-point lookup, before any call.
extern "C" void* SharpOSHost_WTHelperProvDataFromStateData(void* hStateData);
extern "C" void* SharpOSHost_WTHelperGetProvSignerFromChain(void* provData,
                                                            unsigned int idxSigner,
                                                            int fCounterSigner,
                                                            unsigned int idxCounterSigner);
extern "C" void* SharpOSHost_WTHelperGetProvCertFromChain(void* signer,
                                                          unsigned int idxCert);

extern "C" void* WTHelperProvDataFromStateData(void* hStateData) {
    TRACE_REAL(WTHelperProvDataFromStateData);
    return SharpOSHost_WTHelperProvDataFromStateData(hStateData);
}
CRT_REAL(WTHelperProvDataFromStateData);

extern "C" void* WTHelperGetProvSignerFromChain(void* provData,
                                                unsigned int idxSigner,
                                                int fCounterSigner,
                                                unsigned int idxCounterSigner) {
    TRACE_REAL(WTHelperGetProvSignerFromChain);
    return SharpOSHost_WTHelperGetProvSignerFromChain(provData, idxSigner,
                                                      fCounterSigner, idxCounterSigner);
}
CRT_REAL(WTHelperGetProvSignerFromChain);

extern "C" void* WTHelperGetProvCertFromChain(void* signer, unsigned int idxCert) {
    TRACE_REAL(WTHelperGetProvCertFromChain);
    return SharpOSHost_WTHelperGetProvCertFromChain(signer, idxCert);
}
CRT_REAL(WTHelperGetProvCertFromChain);

// UINT GetDriveTypeW(LPCWSTR lpRootPathName) — extract drive letter, delegate.
extern "C" unsigned int GetDriveTypeW(const wchar_t* lpRootPathName) {
    TRACE_REAL(GetDriveTypeW);
    int letter = 0;
    if (lpRootPathName != nullptr && lpRootPathName[0] != 0) letter = (int)lpRootPathName[0];
    g_LastError = 0;
    return SharpOSHost_GetDriveType(letter);
}
CRT_REAL(GetDriveTypeW);

extern "C" int K32EnumProcesses(unsigned int* lpidProcess, unsigned int cb, unsigned int* lpcbNeeded) {
    TRACE_REAL(K32EnumProcesses);
    unsigned int pid = 0;
    int count = SharpOSHost_EnumProcesses(&pid);
    unsigned int needed = (unsigned int)count * 4;
    if (lpcbNeeded) *lpcbNeeded = needed;
    if (lpidProcess == nullptr || cb < 4) {
        g_LastError = 0;
        return 1;  // BCL reads lpcbNeeded
    }
    if (count >= 1 && cb >= 4) lpidProcess[0] = pid;
    g_LastError = 0;
    return 1;
}
CRT_REAL(K32EnumProcesses);

// step126.11: user32 shims. Kernel policy in UserUiPolicy.cs.
extern "C" int   SharpOSHost_SystemParametersInfo(unsigned int action, unsigned int param,
                                                  unsigned char* pvParam, unsigned int fWinIni);
extern "C" int   SharpOSHost_GetSystemMetrics(int nIndex);
extern "C" void* SharpOSHost_GetConsoleWindow(void);

extern "C" int SystemParametersInfoW(unsigned int uiAction, unsigned int uiParam,
                                      void* pvParam, unsigned int fWinIni) {
    TRACE_REAL(SystemParametersInfoW);
    int ok = SharpOSHost_SystemParametersInfo(uiAction, uiParam,
                                              (unsigned char*)pvParam, fWinIni);
    g_LastError = ok ? 0 : 50;  // ERROR_NOT_SUPPORTED
    return ok;
}
CRT_REAL(SystemParametersInfoW);

extern "C" int SystemParametersInfoA(unsigned int uiAction, unsigned int uiParam,
                                      void* pvParam, unsigned int fWinIni) {
    TRACE_REAL(SystemParametersInfoA);
    int ok = SharpOSHost_SystemParametersInfo(uiAction, uiParam,
                                              (unsigned char*)pvParam, fWinIni);
    g_LastError = ok ? 0 : 50;
    return ok;
}
CRT_REAL(SystemParametersInfoA);

extern "C" int GetSystemMetrics(int nIndex) {
    TRACE_REAL(GetSystemMetrics);
    return SharpOSHost_GetSystemMetrics(nIndex);
}
CRT_REAL(GetSystemMetrics);

extern "C" void* GetConsoleWindow(void) {
    TRACE_REAL(GetConsoleWindow);
    return SharpOSHost_GetConsoleWindow();
}
CRT_REAL(GetConsoleWindow);

// EnumWindows — Process.MainWindowHandle walks every top-level window. There
// are none here, so report a successful enumeration of zero windows without
// ever invoking the callback: MainWindowHandle stays IntPtr.Zero and
// MainWindowTitle comes back empty, which is what a windowless host means.
extern "C" int EnumWindows(void* /*lpEnumFunc*/, intptr_t /*lParam*/) {
    TRACE_REAL(EnumWindows);
    g_LastError = 0;
    return 1;
}
CRT_REAL(EnumWindows);

// step126.13: kernel32 OpenProcess + GetCPInfoEx + advapi32 LookupAccountName.
// Kernel policy in ProcessAndCodepage.cs.
extern "C" void* SharpOSHost_OpenProcess(unsigned int dwProcessId);
extern "C" int   SharpOSHost_GetCPInfoEx(void);
extern "C" int   SharpOSHost_LookupAccountName(unsigned int* outSidSize,
                                                unsigned int* outDomainSize,
                                                int* outUse);

extern "C" void* OpenProcess(unsigned long /*dwDesiredAccess*/,
                              int /*bInheritHandle*/,
                              unsigned long dwProcessId) {
    TRACE_REAL(OpenProcess);
    void* h = SharpOSHost_OpenProcess((unsigned int)dwProcessId);
    g_LastError = h ? 0 : 87 /*ERROR_INVALID_PARAMETER*/;
    return h;
}
CRT_REAL(OpenProcess);

extern "C" int GetCPInfoExW(unsigned int /*CodePage*/, unsigned long /*dwFlags*/, void* /*out*/) {
    TRACE_REAL(GetCPInfoExW);
    int err = SharpOSHost_GetCPInfoEx();
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(GetCPInfoExW);

extern "C" int GetCPInfoExA(unsigned int /*CodePage*/, unsigned long /*dwFlags*/, void* /*out*/) {
    TRACE_REAL(GetCPInfoExA);
    int err = SharpOSHost_GetCPInfoEx();
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(GetCPInfoExA);

extern "C" int LookupAccountNameW(const wchar_t* /*lpSystemName*/,
                                   const wchar_t* /*lpAccountName*/,
                                   void* /*Sid*/, unsigned long* cbSid,
                                   wchar_t* /*ReferencedDomainName*/,
                                   unsigned long* cchReferencedDomainName,
                                   int* peUse) {
    TRACE_REAL(LookupAccountNameW);
    int err = SharpOSHost_LookupAccountName((unsigned int*)cbSid,
                                             (unsigned int*)cchReferencedDomainName,
                                             peUse);
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(LookupAccountNameW);

// step126.10: ole32/combase COM init shims. Kernel policy in ComPolicy.cs.
extern "C" int   SharpOSHost_CoInitializeEx(int coInit);
extern "C" int   SharpOSHost_CoInitialize(void);
extern "C" void  SharpOSHost_CoUninitialize(void);
extern "C" int   SharpOSHost_CoCreateInstance(void** outIface);
extern "C" void* SharpOSHost_CoTaskMemAlloc(uint64_t size);
extern "C" void  SharpOSHost_CoTaskMemFree(void* ptr);

extern "C" long CoInitializeEx(void* /*reserved*/, unsigned long dwCoInit) {
    TRACE_REAL(CoInitializeEx);
    return (long)SharpOSHost_CoInitializeEx((int)dwCoInit);
}
CRT_REAL(CoInitializeEx);

extern "C" long CoInitialize(void* /*reserved*/) {
    TRACE_REAL(CoInitialize);
    return (long)SharpOSHost_CoInitialize();
}
CRT_REAL(CoInitialize);

extern "C" void CoUninitialize(void) {
    TRACE_REAL(CoUninitialize);
    SharpOSHost_CoUninitialize();
}
CRT_REAL(CoUninitialize);

extern "C" long CoCreateInstance(const void* /*rclsid*/, void* /*pUnkOuter*/,
                                  unsigned long /*dwClsContext*/, const void* /*riid*/,
                                  void** ppv) {
    TRACE_REAL(CoCreateInstance);
    return (long)SharpOSHost_CoCreateInstance(ppv);
}
CRT_REAL(CoCreateInstance);

extern "C" void* CoTaskMemAlloc(size_t cb) {
    TRACE_REAL(CoTaskMemAlloc);
    return SharpOSHost_CoTaskMemAlloc((uint64_t)cb);
}
CRT_REAL(CoTaskMemAlloc);

extern "C" void CoTaskMemFree(void* pv) {
    TRACE_REAL(CoTaskMemFree);
    SharpOSHost_CoTaskMemFree(pv);
}
CRT_REAL(CoTaskMemFree);

// ─── step126.5: kernel32 directory ops — pretend "already exists" ──────
// PowerShell tries to create module/cache/profile directories on startup.
// We have a read-only FS — claim every target already exists, then any
// subsequent file create attempts in those directories will fail with
// ERROR_PATH_NOT_FOUND, which BCL surfaces as catchable IO exception.
// BCL FileSystem.CreateDirectory's default `allowExisting=true` path
// silently succeeds when ERROR_ALREADY_EXISTS is returned.

// Kernel-side policy in OS/src/PAL/SharpOSHost/FileSystemPolicy.cs.
extern "C" int SharpOSHost_CreateDirectory(void);
extern "C" int SharpOSHost_RemoveDirectory(void);
extern "C" int SharpOSHost_SetEnvironmentVariable(void);

extern "C" int CreateDirectoryW(const wchar_t* /*lpPathName*/,
                                 void* /*lpSecurityAttributes*/) {
    TRACE_REAL(CreateDirectoryW);
    int err = SharpOSHost_CreateDirectory();
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(CreateDirectoryW);

extern "C" int RemoveDirectoryW(const wchar_t* /*lpPathName*/) {
    TRACE_REAL(RemoveDirectoryW);
    int err = SharpOSHost_RemoveDirectory();
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(RemoveDirectoryW);

extern "C" int SetEnvironmentVariableW(const wchar_t* /*lpName*/,
                                        const wchar_t* /*lpValue*/) {
    TRACE_REAL(SetEnvironmentVariableW);
    int err = SharpOSHost_SetEnvironmentVariable();
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(SetEnvironmentVariableW);

extern "C" int SetEnvironmentVariableA(const char* /*lpName*/,
                                        const char* /*lpValue*/) {
    TRACE_REAL(SetEnvironmentVariableA);
    int err = SharpOSHost_SetEnvironmentVariable();
    g_LastError = (uint32_t)err;
    return err == 0 ? 1 : 0;
}
CRT_REAL(SetEnvironmentVariableA);

// FormatMessageW — exists at line ~2588 with FROM_STRING support for mscorrc.
// We just need to wire it into the kernel32 resolver below.
//
// FormatMessageA — ANSI variant. PowerShell may call this for Win32Exception
// fallback; minimal stub returning 0 = no chars (BCL handles empty as default).
// Kernel-side policy in OS/src/PAL/SharpOSHost/FileSystemPolicy.cs.
extern "C" int SharpOSHost_FormatMessage(void);

extern "C" unsigned long FormatMessageA(unsigned long dwFlags,
                                         const void* /*lpSource*/,
                                         unsigned long /*dwMessageId*/,
                                         unsigned long /*dwLanguageId*/,
                                         char* lpBuffer,
                                         unsigned long /*nSize*/,
                                         char** /*Arguments*/) {
    TRACE_REAL(FormatMessageA);
    // Clear out param (ABI-level marshalling — handle ALLOCATE_BUFFER vs
    // caller-buffer flag here, not in kernel).
    if (dwFlags & 0x100u) {
        char** outPtr = (char**)lpBuffer;
        if (outPtr != nullptr) *outPtr = nullptr;
    } else if (lpBuffer != nullptr) {
        lpBuffer[0] = 0;
    }
    g_LastError = (uint32_t)SharpOSHost_FormatMessage();
    return 0;
}
CRT_REAL(FormatMessageA);

// ─── step126: kernel32 Console facade — thin marshal to kernel C# ─────
// Backing: stdout/stderr → SharpOSHost_DebugWrite path through
// ConsoleWin32.cs. Standard input is currently inert (returns 0 bytes).
// All BCL System.Console init paths route through here:
//   GetStdHandle → fake sentinel handle
//   GetFileType  → FILE_TYPE_CHAR for std handles, DISK for files
//   GetConsoleMode → reasonable defaults (ENABLE_PROCESSED_OUTPUT etc.)
//   WriteConsoleW → UTF-16 → UART byte stream
//   WriteFile (to std handle) → routed to console
//   GetConsoleScreenBufferInfo → synthetic 80x25

extern "C" uint64_t SharpOSHost_GetStdHandle(int nStdHandle);
extern "C" int      SharpOSHost_ConsoleWriteW(uint64_t hConsole, const wchar_t* buffer,
                                              uint32_t nChars, uint32_t* numCharsWritten);
extern "C" int      SharpOSHost_ConsoleWriteFile(uint64_t hHandle, const unsigned char* buffer,
                                                 uint32_t nBytes, uint32_t* numBytesWritten);
extern "C" int      SharpOSHost_GetConsoleMode(uint64_t hConsole, uint32_t* outMode);
extern "C" int      SharpOSHost_SetConsoleMode(uint64_t hConsole, uint32_t mode);
extern "C" uint32_t SharpOSHost_GetFileType(uint64_t hHandle);
extern "C" int      SharpOSHost_GetConsoleScreenBufferInfo(uint64_t hConsole, void* outInfo);
extern "C" int      SharpOSHost_SetConsoleCursorPosition(uint64_t hConsole, int packedCoord);
extern "C" int      SharpOSHost_SetConsoleTextAttribute(uint64_t hConsole, unsigned short attrs);

extern "C" void* GetStdHandle(unsigned long nStdHandle) {
    TRACE_REAL(GetStdHandle);
    int s = (int)(long)nStdHandle;  // -10 / -11 / -12 as DWORD
    uint64_t h = SharpOSHost_GetStdHandle(s);
    return (void*)(uintptr_t)h;
}
CRT_REAL(GetStdHandle);

extern "C" int WriteConsoleW(void* hConsole, const void* lpBuffer,
                              unsigned long nChars, unsigned long* lpCharsWritten,
                              void* /*lpReserved*/) {
    TRACE_REAL(WriteConsoleW);
    uint32_t written = 0;
    int ok = SharpOSHost_ConsoleWriteW((uint64_t)(uintptr_t)hConsole,
                                       (const wchar_t*)lpBuffer,
                                       (uint32_t)nChars, &written);
    if (lpCharsWritten != nullptr) *lpCharsWritten = (unsigned long)written;
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(WriteConsoleW);

// WriteFile is also used for file I/O. Route to console when the handle
// matches one of our std sentinels (SharpOSHost_ConsoleWriteFile returns
// 0 if not a console handle — then caller can fall back to the file
// CreateFileW path. For now we only support std-handle WriteFile; the
// file CreateFileW path doesn't go through WriteFile in our PEIMG flow.
extern "C" int WriteFile(void* hHandle, const void* lpBuffer,
                          unsigned long nBytes, unsigned long* lpBytesWritten,
                          void* /*lpOverlapped*/) {
    TRACE_REAL(WriteFile);
    uint32_t written = 0;
    int ok = SharpOSHost_ConsoleWriteFile((uint64_t)(uintptr_t)hHandle,
                                          (const unsigned char*)lpBuffer,
                                          (uint32_t)nBytes, &written);
    if (lpBytesWritten != nullptr) *lpBytesWritten = (unsigned long)written;
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(WriteFile);

extern "C" int GetConsoleMode(void* hConsole, unsigned long* lpMode) {
    TRACE_REAL(GetConsoleMode);
    uint32_t mode = 0;
    int ok = SharpOSHost_GetConsoleMode((uint64_t)(uintptr_t)hConsole, &mode);
    if (lpMode != nullptr) *lpMode = (unsigned long)mode;
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(GetConsoleMode);

extern "C" int SetConsoleMode(void* hConsole, unsigned long dwMode) {
    TRACE_REAL(SetConsoleMode);
    int ok = SharpOSHost_SetConsoleMode((uint64_t)(uintptr_t)hConsole, (uint32_t)dwMode);
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(SetConsoleMode);

extern "C" unsigned long GetFileType(void* hHandle) {
    TRACE_REAL(GetFileType);
    uint32_t t = SharpOSHost_GetFileType((uint64_t)(uintptr_t)hHandle);
    g_LastError = 0;
    return (unsigned long)t;
}
CRT_REAL(GetFileType);

extern "C" int GetConsoleScreenBufferInfo(void* hConsole, void* lpConsoleScreenBufferInfo) {
    TRACE_REAL(GetConsoleScreenBufferInfo);
    int ok = SharpOSHost_GetConsoleScreenBufferInfo((uint64_t)(uintptr_t)hConsole,
                                                    lpConsoleScreenBufferInfo);
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(GetConsoleScreenBufferInfo);

// GetConsoleCursorInfo / SetConsoleCursorInfo — PSReadLine reads the cursor
// shape on entry and hides the cursor around repaints. Kernel policy in
// ConsoleWin32.cs.
extern "C" int SharpOSHost_GetConsoleCursorInfo(uint64_t hConsole, void* lpConsoleCursorInfo);
extern "C" int SharpOSHost_SetConsoleCursorInfo(uint64_t hConsole, void* lpConsoleCursorInfo);

extern "C" int GetConsoleCursorInfo(void* hConsole, void* lpConsoleCursorInfo) {
    TRACE_REAL(GetConsoleCursorInfo);
    int ok = SharpOSHost_GetConsoleCursorInfo((uint64_t)(uintptr_t)hConsole, lpConsoleCursorInfo);
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(GetConsoleCursorInfo);

extern "C" int SetConsoleCursorInfo(void* hConsole, void* lpConsoleCursorInfo) {
    TRACE_REAL(SetConsoleCursorInfo);
    int ok = SharpOSHost_SetConsoleCursorInfo((uint64_t)(uintptr_t)hConsole, lpConsoleCursorInfo);
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(SetConsoleCursorInfo);

// GetCurrentConsoleFontEx — PSReadLine queries the console font before drawing.
// Kernel policy in ConsoleWin32.cs; the struct is bounded by its own cbSize.
extern "C" int SharpOSHost_GetCurrentConsoleFontEx(uint64_t hConsole, int bMaximumWindow,
                                                   void* lpConsoleCurrentFontEx);

extern "C" int GetCurrentConsoleFontEx(void* hConsole, int bMaximumWindow,
                                       void* lpConsoleCurrentFontEx) {
    TRACE_REAL(GetCurrentConsoleFontEx);
    int ok = SharpOSHost_GetCurrentConsoleFontEx((uint64_t)(uintptr_t)hConsole,
                                                 bMaximumWindow, lpConsoleCurrentFontEx);
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(GetCurrentConsoleFontEx);

extern "C" int SetConsoleCursorPosition(void* hConsole, int packedCoord) {
    TRACE_REAL(SetConsoleCursorPosition);
    int ok = SharpOSHost_SetConsoleCursorPosition((uint64_t)(uintptr_t)hConsole, packedCoord);
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(SetConsoleCursorPosition);

extern "C" int SetConsoleTextAttribute(void* hConsole, unsigned short wAttributes) {
    TRACE_REAL(SetConsoleTextAttribute);
    int ok = SharpOSHost_SetConsoleTextAttribute((uint64_t)(uintptr_t)hConsole, wAttributes);
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(SetConsoleTextAttribute);

// step126.9: kernel-side policy in ConsoleWin32.cs (SetConsoleCtrlHandler,
// GetStartupInfo).
extern "C" int  SharpOSHost_SetConsoleCtrlHandler(void);
extern "C" void SharpOSHost_GetStartupInfo(unsigned int* lpInfo, unsigned int structSize);

extern "C" int SetConsoleCtrlHandler(void* /*HandlerRoutine*/, int /*Add*/) {
    TRACE_REAL(SetConsoleCtrlHandler);
    int ok = SharpOSHost_SetConsoleCtrlHandler();
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(SetConsoleCtrlHandler);

extern "C" void GetStartupInfoW(void* lpStartupInfo) {
    TRACE_REAL(GetStartupInfoW);
    // STARTUPINFOW is 104 bytes on x64 (LPSTR/LPWSTR=8, DWORDs=4).
    // Kernel writes cb at offset 0 and zeroes the rest. Caller's cb field
    // is normally pre-set with sizeof — but BCL Process startup code
    // doesn't always init it. We unconditionally write 104.
    SharpOSHost_GetStartupInfo((unsigned int*)lpStartupInfo, 104);
}
CRT_REAL(GetStartupInfoW);

extern "C" void GetStartupInfoA(void* lpStartupInfo) {
    TRACE_REAL(GetStartupInfoA);
    SharpOSHost_GetStartupInfo((unsigned int*)lpStartupInfo, 104);
}
CRT_REAL(GetStartupInfoA);

// step126.14: ReadConsole — kernel-side reads from PS/2 keyboard via
// LineEditor. Signature accepts optional CONSOLE_READCONSOLE_CONTROL
// (we ignore it; line-mode is the only mode supported).
extern "C" int SharpOSHost_ReadConsole(wchar_t* lpBuffer,
                                        unsigned int nCharsToRead,
                                        unsigned int* lpNumberOfCharsRead);

extern "C" int ReadConsoleW(void* /*hConsoleInput*/,
                             void* lpBuffer,
                             unsigned long nCharsToRead,
                             unsigned long* lpNumberOfCharsRead,
                             void* /*pInputControl*/) {
    TRACE_REAL(ReadConsoleW);
    unsigned int written = 0;
    int ok = SharpOSHost_ReadConsole((wchar_t*)lpBuffer, (unsigned int)nCharsToRead, &written);
    if (lpNumberOfCharsRead != nullptr) *lpNumberOfCharsRead = (unsigned long)written;
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(ReadConsoleW);

// Console *event* input. ReadConsoleW hands back a finished line (kernel-side
// LineEditor owns the editing); PSReadLine does its own editing and needs raw
// key events instead — virtual key codes plus modifier state. Kernel policy in
// OS/src/PAL/SharpOSHost/ConsoleInput.cs; INPUT_RECORD is written there.
extern "C" int SharpOSHost_ReadConsoleInput(void* buffer, unsigned int length,
                                            unsigned int* eventsRead);
extern "C" int SharpOSHost_PeekConsoleInput(void* buffer, unsigned int length,
                                            unsigned int* eventsRead);
extern "C" int SharpOSHost_GetNumberOfConsoleInputEvents(unsigned int* count);

extern "C" int ReadConsoleInputW(void* /*hConsoleInput*/, void* lpBuffer,
                                  unsigned long nLength, unsigned long* lpNumberOfEventsRead) {
    TRACE_REAL(ReadConsoleInputW);
    unsigned int read = 0;
    int ok = SharpOSHost_ReadConsoleInput(lpBuffer, (unsigned int)nLength, &read);
    if (lpNumberOfEventsRead != nullptr) *lpNumberOfEventsRead = (unsigned long)read;
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(ReadConsoleInputW);

extern "C" int ReadConsoleInputA(void* hConsoleInput, void* lpBuffer,
                                  unsigned long nLength, unsigned long* lpNumberOfEventsRead) {
    TRACE_REAL(ReadConsoleInputA);
    return ReadConsoleInputW(hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
}
CRT_REAL(ReadConsoleInputA);

extern "C" int PeekConsoleInputW(void* /*hConsoleInput*/, void* lpBuffer,
                                  unsigned long nLength, unsigned long* lpNumberOfEventsRead) {
    TRACE_REAL(PeekConsoleInputW);
    unsigned int read = 0;
    int ok = SharpOSHost_PeekConsoleInput(lpBuffer, (unsigned int)nLength, &read);
    if (lpNumberOfEventsRead != nullptr) *lpNumberOfEventsRead = (unsigned long)read;
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(PeekConsoleInputW);

extern "C" int GetNumberOfConsoleInputEvents(void* /*hConsoleInput*/,
                                              unsigned long* lpcNumberOfEvents) {
    TRACE_REAL(GetNumberOfConsoleInputEvents);
    unsigned int count = 0;
    int ok = SharpOSHost_GetNumberOfConsoleInputEvents(&count);
    if (lpcNumberOfEvents != nullptr) *lpcNumberOfEvents = (unsigned long)count;
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(GetNumberOfConsoleInputEvents);

extern "C" int ReadConsoleA(void* /*hConsoleInput*/,
                             void* lpBuffer,
                             unsigned long nCharsToRead,
                             unsigned long* lpNumberOfCharsRead,
                             void* /*pInputControl*/) {
    TRACE_REAL(ReadConsoleA);
    // Read wide chars into temporary stack buffer, narrow to ASCII bytes.
    wchar_t tmp[256];
    unsigned int toRead = nCharsToRead > 256 ? 256 : (unsigned int)nCharsToRead;
    unsigned int written = 0;
    int ok = SharpOSHost_ReadConsole(tmp, toRead, &written);
    if (ok && lpBuffer != nullptr) {
        unsigned char* outA = (unsigned char*)lpBuffer;
        for (unsigned int i = 0; i < written; i++) outA[i] = (unsigned char)(tmp[i] & 0xFF);
    }
    if (lpNumberOfCharsRead != nullptr) *lpNumberOfCharsRead = (unsigned long)written;
    g_LastError = ok ? 0 : 6;
    return ok;
}
CRT_REAL(ReadConsoleA);

extern "C" int GetCPInfo(uint32_t /*cp*/, void* out) {
    TRACE_REAL(GetCPInfo);
    if (!out) return 0;
    uint8_t* p = (uint8_t*)out;
    for (int i = 0; i < 4 + 2 + 12; i++) p[i] = 0;
    *(uint32_t*)p = 1;
    return 1;
}
CRT_REAL(GetCPInfo);

extern "C" void* GetModuleHandleW(const wchar_t* /*name*/) { TRACE_REAL(GetModuleHandleW); g_LastError = 0; return (void*)(intptr_t)1; }
CRT_REAL(GetModuleHandleW);
extern "C" void* GetModuleHandleA(const char* /*name*/)    { TRACE_REAL(GetModuleHandleA); g_LastError = 0; return (void*)(intptr_t)1; }
CRT_REAL(GetModuleHandleA);

// GetModuleFileNameW — return a plausible path. Empty/zero return was
// confusing CoreCLR's HRESULT_FROM_WIN32(GetLastError()) chains where
// LastError stayed stale from a previous GetEnvironmentVariableW
// (ERROR_ENVVAR_NOT_FOUND = 0xCB), causing spurious 0x800700CB throws.
// On success, ALSO clear LastError so subsequent stale-Error chains
// don't poison HRESULT extraction.
extern "C" uint32_t GetModuleFileNameW(void* /*mod*/, wchar_t* buf, uint32_t size) {
    TRACE_REAL(GetModuleFileNameW);
    // Deliberately obvious-fake name: there is NO real exe (CoreCLR is
    // statically linked into the kernel image). Named so a disassembling
    // reader is not misled into hunting a "\sharpos\kernel.exe" artifact.
    static const wchar_t k_path[] = { '\\', 's', 'h', 'a', 'r', 'p', 'o', 's', '\\',
                                      'f', 'a', 'k', 'e', '_', 'k', 'e', 'r', 'n', 'e', 'l',
                                      '_', 'p', 'a', 't', 'h', '.', 'e', 'x', 'e', 0 };
    const uint32_t k_pathLen = 29;  // chars excluding null
    if (buf == nullptr || size == 0) {
        // ABI: returns required length (excluding null) — caller usually
        // probes for size by passing 0. We don't have that semantic on
        // every caller's path, but returning length is correct.
        g_LastError = 0;
        return k_pathLen;
    }
    uint32_t toCopy = (size - 1 < k_pathLen) ? (size - 1) : k_pathLen;
    for (uint32_t i = 0; i < toCopy; i++) buf[i] = k_path[i];
    buf[toCopy] = 0;
    if (toCopy < k_pathLen) {
        g_LastError = 122;  // ERROR_INSUFFICIENT_BUFFER
        return size;
    }
    g_LastError = 0;
    return toCopy;
}
CRT_REAL(GetModuleFileNameW);

// --- Advapi32 ETW stubs ---
//
// Все стабы возвращают 0 = ERROR_SUCCESS. ETW думает что зарегистрировалась
// и что события пишутся; на самом деле они уходят в никуда. На bare metal
// ETW потребитель отсутствует — это правильная семантика "no-op observability".
//
// Сигнатуры взяты из Advapi32.dll header'ов (evntprov.h). Мы пишем generic
// прототипы — ABI неважно, мы возвращаем 0 и игнорируем args.

extern "C" uint32_t SharpOS_EventRegister(const void* /*ProviderId*/,
                                          void* /*EnableCallback*/,
                                          void* /*CallbackContext*/,
                                          uint64_t* RegHandle) {
    if (RegHandle) *RegHandle = 1;   // non-zero pseudo-handle
    return 0;
}
extern "C" uint32_t SharpOS_EventUnregister(uint64_t /*RegHandle*/) { return 0; }
extern "C" uint32_t SharpOS_EventWriteTransfer(uint64_t /*RegHandle*/, const void* /*EventDescriptor*/,
                                               const void* /*ActivityId*/, const void* /*RelatedActivityId*/,
                                               uint32_t /*UserDataCount*/, void* /*UserData*/) { return 0; }
extern "C" uint32_t SharpOS_EventActivityIdControl(uint32_t /*ControlCode*/, void* /*ActivityId*/) { return 0; }
extern "C" uint32_t SharpOS_EventSetInformation(uint64_t /*RegHandle*/, uint32_t /*InformationClass*/,
                                                void* /*EventInformation*/, uint32_t /*InformationLength*/) { return 0; }
extern "C" int      SharpOS_EventEnabled(uint64_t /*RegHandle*/, const void* /*EventDescriptor*/) { return 0; }
extern "C" int      SharpOS_EventProviderEnabled(uint64_t /*RegHandle*/, uint8_t /*Level*/, uint64_t /*Keyword*/) { return 0; }
extern "C" uint32_t SharpOS_EventWriteString(uint64_t /*RegHandle*/, uint8_t /*Level*/, uint64_t /*Keyword*/,
                                             const wchar_t* /*String*/) { return 0; }
extern "C" uint32_t SharpOS_EventWriteEx(uint64_t /*RegHandle*/, const void* /*EventDescriptor*/,
                                         uint64_t /*Filter*/, uint32_t /*Flags*/,
                                         const void* /*ActivityId*/, const void* /*RelatedActivityId*/,
                                         uint32_t /*UserDataCount*/, void* /*UserData*/) { return 0; }

// --- libSystem.Native console shim ---
//
// Minimal Unix native substrate for System.Console output. Non-interactive:
// IsATty→0 so ConsolePal.Unix takes the simple StreamWriter path (no termios,
// no terminfo, no signal handling). Write fd 1/2 → COM1 via SharpOSHost.
// stdin reads → EOF. Everything else benign so cctor/init never throws.

extern "C" int32_t SharpOS_SN_Write(intptr_t /*fd*/, const void* buffer, int32_t bufferSize) {
    if (buffer != nullptr && bufferSize > 0)
        SharpOSHost_DebugWrite(buffer, bufferSize);
    return bufferSize;                       // pretend full write
}
extern "C" int32_t SharpOS_SN_Read(intptr_t /*fd*/, void* /*buffer*/, int32_t /*count*/) { return 0; }      // EOF
extern "C" int32_t SharpOS_SN_IsATty(intptr_t /*fd*/) { return 0; }                                          // not a tty
extern "C" int32_t SharpOS_SN_InitializeTerminalAndSignalHandling(void) { return 1; }                        // success
extern "C" void    SharpOS_SN_InitializeConsoleBeforeRead(uint8_t,uint8_t,uint8_t) {}
extern "C" void    SharpOS_SN_UninitializeConsoleAfterRead(void) {}
extern "C" void    SharpOS_SN_UninitializeTerminal(void) {}
extern "C" int32_t SharpOS_SN_GetWindowSize(intptr_t /*fd*/, void* /*winsize*/) { return -1; }               // unknown → defaults

// step 99 pass 4: BCL System.Security.Cryptography.RandomNumberGenerator
// on this fork's CoreLib calls Interop.Sys.GetCryptographicallySecureRandomBytes
// (libSystem.Native) BEFORE falling back to CryptoNative_GetRandomBytes
// (libSystem.Security.Cryptography.Native.OpenSsl). Forward to the same
// SharpOSHost_FillRandom kernel-side helper. Returns 1 on success.
extern "C" int32_t SharpOS_SN_GetCryptographicallySecureRandomBytes(uint8_t* buffer, int32_t bufferLength) {
    if (buffer == nullptr || bufferLength <= 0) return 0;
    SharpOSHost_FillRandom(buffer, bufferLength);
    return 1;
}

// step 99 pass 6: SystemNative_GetHostName(buf, bufLen) -> 0 on success,
// -1 on error. Dns.GetHostName calls this; the actual hostname string
// lives kernel-side (SystemIdentity.cs, kind=HostName). PAL forwards.
// SystemIdentity returns chars excl NUL when buffer fits; we treat the
// non-success path uniformly as -1 to match Unix PAL semantics.
extern "C" int32_t SharpOS_SN_GetHostName(char* buf, int32_t bufLen) {
    if (buf == nullptr || bufLen <= 0) return -1;
    int needed_incl_nul = SharpOSHost_GetSystemString(/*KindHostName*/6, nullptr, 0);
    if (needed_incl_nul <= 0 || bufLen < needed_incl_nul) return -1;
    int got = SharpOSHost_GetSystemString(/*KindHostName*/6, (uint8_t*)buf, bufLen);
    return got >= 0 ? 0 : -1;
}
extern "C" int32_t SharpOS_SN_ConvertErrorPlatformToPal(int32_t e) { return e; }
extern "C" int32_t SharpOS_SN_ConvertErrorPalToPlatform(int32_t e) { return e; }
extern "C" void    SharpOS_SN_GetControlCharacters(int32_t*,uint8_t*,int32_t,uint8_t*) {}
extern "C" int32_t SharpOS_SN_GetSignalForBreak(void) { return 1; }
extern "C" int32_t SharpOS_SN_SetSignalForBreak(int32_t /*v*/) { return 1; }
extern "C" int32_t SharpOS_SN_StdinReady(void) { return 0; }
extern "C" int32_t SharpOS_SN_ReadStdin(void* /*buf*/, int32_t /*n*/) { return 0; }                          // EOF
extern "C" void    SharpOS_SN_SetKeypadXmit(intptr_t /*fd*/, const char* /*s*/) {}
extern "C" void    SharpOS_SN_SetTerminalInvalidationHandler(void* /*cb*/) {}
extern "C" int32_t SharpOS_SN_Poll(void* /*pe*/, uint32_t /*cnt*/, int32_t /*ms*/, uint32_t* triggered) { if (triggered) *triggered = 0; return 0; }
extern "C" intptr_t SharpOS_SN_Dup(intptr_t oldfd) { return oldfd; }
extern "C" intptr_t SharpOS_SN_Open(const char* /*path*/, int32_t /*flags*/, int32_t /*mode*/) { return -1; }
extern "C" uint32_t SharpOS_SN_GetEUid(void) { return 0; }
extern "C" int32_t SharpOS_SN_GetPwUidR(uint32_t,void*,char*,int32_t) { return -1; }
extern "C" const char* SharpOS_SN_StrErrorR(int32_t /*code*/, char* buffer, int32_t bufferSize) {
    if (buffer && bufferSize > 0) buffer[0] = 0;
    return buffer;
}
extern "C" int32_t SharpOS_SN_SNPrintF_1I(char* str, int32_t size, const char* /*fmt*/, int32_t /*a1*/) {
    if (str && size > 0) str[0] = 0;
    return 0;
}
extern "C" int32_t SharpOS_SN_SNPrintF_1S(char* str, int32_t size, const char* /*fmt*/, const char* /*a1*/) {
    if (str && size > 0) str[0] = 0;
    return 0;
}
// errno: BCL Sys::SetErrNo/GetErrNo go through libSystem.Native. Our syscall stubs
// don't surface meaningful errors, so drop SetErrNo and return 0 from GetErrNo.
// Skip TLS — would need full PAL plumbing for no real-information benefit.
extern "C" void    SharpOS_SN_SetErrNo(int32_t /*errorCode*/) {}
extern "C" int32_t SharpOS_SN_GetErrNo(void) { return 0; }
// SystemNative_GetCwd(byte* buf, int32_t bufLen) → buf (success) | NULL (error).
// On NULL+ERANGE the BCL retries with a bigger buffer in a loop (Interop.Sys.GetCwd
// — see Interop.GetCwd.cs); returning NULL+0 (no errno) throws IOException, which
// the StackTrace symbolizer then catches → infinite recursion when AV stack walk
// retriggers File.Exists. So fill '/' and return the buffer on success.
extern "C" char* SharpOS_SN_GetCwd(char* buf, int32_t bufLen) {
    if (buf == nullptr || bufLen < 2) return nullptr;
    buf[0] = '/'; buf[1] = 0;
    return buf;
}
// SystemNative_LStat(const char* path, FileStatus* output) → 0 success / -1 error.
// We have no filesystem visible to libSystem.Native — always report ENOENT-like
// failure. BCL File.Exists / Directory.Exists then return false cleanly.
extern "C" int32_t SharpOS_SN_LStat(const char* /*path*/, void* /*output*/) {
    return -1;
}
// SystemNative_Stat — same contract as LStat, both return -1 ENOENT for us.
extern "C" int32_t SharpOS_SN_Stat(const char* /*path*/, void* /*output*/) {
    return -1;
}
// SystemNative_Stat2 / FStat / FStat2 — same signature, return -1.
extern "C" int32_t SharpOS_SN_FStat(intptr_t /*fd*/, void* /*output*/) {
    return -1;
}
// SystemNative_GetPid() — returns process id. Single-process kernel; fake.
extern "C" int32_t SharpOS_SN_GetPid() {
    return 1;
}
// SystemNative_GetUnixVersion(char* buf, int* capacity) — uname-style string into buf.
// 0 success / -1 buffer too small (and *capacity set to needed size).
// Format: "sysname release version" (per pal_runtimeinformation.c). Our identity:
// "SharpOS 1.0 unikernel".
extern "C" int32_t SharpOS_SN_GetUnixVersion(char* buf, int32_t* capacity) {
    if (capacity == nullptr) return -1;
    const char ver[] = "SharpOS 1.0 unikernel";
    const int32_t needed = (int32_t)sizeof(ver);  // includes NUL
    if (buf == nullptr || *capacity < needed) { *capacity = needed; return -1; }
    for (int i = 0; i < needed; i++) buf[i] = ver[i];
    return 0;
}
// SystemNative_GetOSArchitecture / GetProcessArchitecture — return enum value matching
// System.Runtime.InteropServices.Architecture. ARCH_X64 = 1 (we're amd64).
extern "C" int32_t SharpOS_SN_GetOSArchitecture(void) { return 1; }
extern "C" int32_t SharpOS_SN_GetProcessArchitecture(void) { return 1; }
// SystemNative_GetUnixRelease() — returns malloc'd UTF-8 string, caller free()s it
// (StringMarshalling.Utf8 in BCL → Utf8StringMarshaller.Free → routes through our
// fork's free → SharpOSHost_HeapFree). Returning NULL → BCL throws → AV cascade.
// Heap-alloc small copy of the version literal.
extern "C" char* SharpOS_SN_GetUnixRelease(void) {
    const char rel[] = "1.0";
    char* d = (char*)SharpOSHost_HeapAlloc(sizeof(rel));
    if (d == nullptr) return nullptr;
    for (size_t i = 0; i < sizeof(rel); i++) d[i] = rel[i];
    return d;
}
// SystemNative_Free / SystemNative_Malloc / SystemNative_Realloc / SystemNative_Calloc —
// BCL routes heap requests for native interop through these. Forward straight to
// our kernel heap (SharpOSHost_HeapAlloc/Free/Realloc) — same allocator GetUnixRelease
// hands strings from, so paired free works.
extern "C" void  SharpOSHost_HeapFree(void* ptr);
extern "C" void* SharpOSHost_HeapRealloc(void* ptr, size_t newSize);
extern "C" void  SharpOS_SN_Free(void* ptr) { SharpOSHost_HeapFree(ptr); }
extern "C" void* SharpOS_SN_Malloc(size_t size) { return SharpOSHost_HeapAlloc(size); }
extern "C" void* SharpOS_SN_Realloc(void* ptr, size_t newSize) { return SharpOSHost_HeapRealloc(ptr, newSize); }
extern "C" void* SharpOS_SN_Calloc(size_t n, size_t size) {
    size_t total = n * size;
    void* p = SharpOSHost_HeapAlloc(total);
    if (p != nullptr) { char* c = (char*)p; for (size_t i = 0; i < total; i++) c[i] = 0; }
    return p;
}
// Socket event port — no networking on bare metal. Return ENOTSUP (0x1003D).
// Same value Linux kernel returns when an OS lacks epoll/kqueue. BCL surfaces
// this as PlatformNotSupportedException at SocketAsyncEventArgs.* — clean fail.
extern "C" int32_t SharpOS_SN_CreateSocketEventPort(intptr_t* port) {
    if (port != nullptr) *port = -1;
    return 0x1003D;
}
extern "C" int32_t SharpOS_SN_CloseSocketEventPort(intptr_t /*port*/) { return 0; }
extern "C" int32_t SharpOS_SN_CreateSocketEventBuffer(int32_t /*count*/, void** buffer) {
    if (buffer != nullptr) *buffer = nullptr;
    return 0x1003D;
}
extern "C" int32_t SharpOS_SN_FreeSocketEventBuffer(void* /*buffer*/) { return 0; }
// SystemNative_SysLog(prio, fmt, arg1) — BCL Debug.Fail/Trace.WriteLine routes here
// as a fallback debug sink. We have COM1 — forward through our forced-print path
// (always-on, bypasses Verbose) so kernel observers see managed assert messages.
extern "C" void SharpOS_SN_SysLog(int32_t /*priority*/, const char* message, const char* arg1) {
    SharpOSHost_DebugPrintForced("[managed syslog] ");
    // BCL passes "%s" as the message and the real text as arg1 — print whichever
    // is non-null (both, if both). Skip printf substitution since we don't have
    // vsnprintf wired and a static format covers the BCL usage.
    if (message != nullptr) SharpOSHost_DebugPrintForced(message);
    if (arg1 != nullptr) {
        SharpOSHost_DebugPrintForced(" / arg=");
        SharpOSHost_DebugPrintForced(arg1);
    }
    SharpOSHost_DebugPrintForced("\n");
}
// SystemNative_GetSystemTimeAsTicks() → 100ns ticks since UNIX epoch (1970-01-01).
// Our SharpOSHost_GetUtcFileTime returns Windows FILETIME (since 1601-01-01); subtract
// the epoch delta (134774 days * 86400 s/day * 10M ticks/s = 11644473600000000000...
// actually 11644473600 * 10000000 = 116444736000000000). Routes through kernel
// Hal.Rtc + HPET sub-second so DateTime.UtcNow advances correctly.
extern "C" int64_t SharpOSHost_GetUtcFileTime(void);
extern "C" int64_t SharpOS_SN_GetSystemTimeAsTicks(void) {
    int64_t ft = SharpOSHost_GetUtcFileTime();
    if (ft == 0) return 0;  // RTC read failure
    return ft - 116444736000000000LL;  // FILETIME 1601 → Unix 1970 delta
}
// SystemNative_GetTimestamp() → monotonic hi-res ticks. BCL Stopwatch reads via
// this. Route through HPET raw counter (already nanosecond-grade, monotonic).
// BCL also expects companion SystemNative_GetTimestampResolution (ticks/sec) — see below.
extern "C" uint64_t SharpOSHost_GetHpetCounter(void);
extern "C" uint64_t SharpOSHost_GetHpetFrequencyHz(void);
extern "C" int64_t SharpOS_SN_GetTimestamp(void) {
    return (int64_t)SharpOSHost_GetHpetCounter();
}
extern "C" int64_t SharpOS_SN_GetTimestampResolution(void) {
    uint64_t hz = SharpOSHost_GetHpetFrequencyHz();
    return hz != 0 ? (int64_t)hz : 10000000LL;  // fallback: 100ns = 10MHz
}
// Same as GetTimestamp for us — HPET is already plenty cheap, no reason to
// degrade resolution for the low-res path.
extern "C" int64_t SharpOS_SN_GetLowResolutionTimestamp(void) {
    return (int64_t)SharpOSHost_GetHpetCounter();
}

static int sharpos_streq(const char* a, const char* b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}

// Resolve a libSystem.Native export name → our stub. Returns nullptr if
// unknown (caller logs + ERROR_PROC_NOT_FOUND).
static void* sharpos_resolve_sysnative(const char* n) {
    if (sharpos_streq(n,"SystemNative_Write"))                          return (void*)&SharpOS_SN_Write;
    if (sharpos_streq(n,"SystemNative_Read"))                           return (void*)&SharpOS_SN_Read;
    if (sharpos_streq(n,"SystemNative_IsATty"))                         return (void*)&SharpOS_SN_IsATty;
    if (sharpos_streq(n,"SystemNative_InitializeTerminalAndSignalHandling")) return (void*)&SharpOS_SN_InitializeTerminalAndSignalHandling;
    if (sharpos_streq(n,"SystemNative_InitializeConsoleBeforeRead"))    return (void*)&SharpOS_SN_InitializeConsoleBeforeRead;
    if (sharpos_streq(n,"SystemNative_UninitializeConsoleAfterRead"))   return (void*)&SharpOS_SN_UninitializeConsoleAfterRead;
    if (sharpos_streq(n,"SystemNative_UninitializeTerminal"))           return (void*)&SharpOS_SN_UninitializeTerminal;
    if (sharpos_streq(n,"SystemNative_GetWindowSize"))                  return (void*)&SharpOS_SN_GetWindowSize;
    if (sharpos_streq(n,"SystemNative_ConvertErrorPlatformToPal"))      return (void*)&SharpOS_SN_ConvertErrorPlatformToPal;
    if (sharpos_streq(n,"SystemNative_ConvertErrorPalToPlatform"))      return (void*)&SharpOS_SN_ConvertErrorPalToPlatform;
    if (sharpos_streq(n,"SystemNative_GetControlCharacters"))           return (void*)&SharpOS_SN_GetControlCharacters;
    if (sharpos_streq(n,"SystemNative_GetSignalForBreak"))              return (void*)&SharpOS_SN_GetSignalForBreak;
    if (sharpos_streq(n,"SystemNative_SetSignalForBreak"))              return (void*)&SharpOS_SN_SetSignalForBreak;
    if (sharpos_streq(n,"SystemNative_StdinReady"))                     return (void*)&SharpOS_SN_StdinReady;
    if (sharpos_streq(n,"SystemNative_ReadStdin"))                      return (void*)&SharpOS_SN_ReadStdin;
    if (sharpos_streq(n,"SystemNative_SetKeypadXmit"))                  return (void*)&SharpOS_SN_SetKeypadXmit;
    if (sharpos_streq(n,"SystemNative_SetTerminalInvalidationHandler")) return (void*)&SharpOS_SN_SetTerminalInvalidationHandler;
    if (sharpos_streq(n,"SystemNative_Poll"))                           return (void*)&SharpOS_SN_Poll;
    if (sharpos_streq(n,"SystemNative_Dup"))                            return (void*)&SharpOS_SN_Dup;
    if (sharpos_streq(n,"SystemNative_Open"))                           return (void*)&SharpOS_SN_Open;
    if (sharpos_streq(n,"SystemNative_GetEUid"))                        return (void*)&SharpOS_SN_GetEUid;
    if (sharpos_streq(n,"SystemNative_GetPwUidR"))                      return (void*)&SharpOS_SN_GetPwUidR;
    if (sharpos_streq(n,"SystemNative_StrErrorR"))                      return (void*)&SharpOS_SN_StrErrorR;
    if (sharpos_streq(n,"SystemNative_SNPrintF_1I"))                    return (void*)&SharpOS_SN_SNPrintF_1I;
    if (sharpos_streq(n,"SystemNative_SNPrintF_1S"))                    return (void*)&SharpOS_SN_SNPrintF_1S;
    if (sharpos_streq(n,"SystemNative_GetCryptographicallySecureRandomBytes")) return (void*)&SharpOS_SN_GetCryptographicallySecureRandomBytes;
    if (sharpos_streq(n,"SystemNative_GetHostName"))                    return (void*)&SharpOS_SN_GetHostName;
    if (sharpos_streq(n,"SystemNative_SetErrNo"))                       return (void*)&SharpOS_SN_SetErrNo;
    if (sharpos_streq(n,"SystemNative_GetErrNo"))                       return (void*)&SharpOS_SN_GetErrNo;
    if (sharpos_streq(n,"SystemNative_GetCwd"))                         return (void*)&SharpOS_SN_GetCwd;
    if (sharpos_streq(n,"SystemNative_GetSystemTimeAsTicks"))           return (void*)&SharpOS_SN_GetSystemTimeAsTicks;
    if (sharpos_streq(n,"SystemNative_GetTimestamp"))                   return (void*)&SharpOS_SN_GetTimestamp;
    if (sharpos_streq(n,"SystemNative_GetTimestampResolution"))         return (void*)&SharpOS_SN_GetTimestampResolution;
    if (sharpos_streq(n,"SystemNative_GetLowResolutionTimestamp"))      return (void*)&SharpOS_SN_GetLowResolutionTimestamp;
    if (sharpos_streq(n,"SystemNative_LStat"))                          return (void*)&SharpOS_SN_LStat;
    if (sharpos_streq(n,"SystemNative_Stat"))                           return (void*)&SharpOS_SN_Stat;
    if (sharpos_streq(n,"SystemNative_FStat"))                          return (void*)&SharpOS_SN_FStat;
    if (sharpos_streq(n,"SystemNative_GetPid"))                         return (void*)&SharpOS_SN_GetPid;
    if (sharpos_streq(n,"SystemNative_GetUnixVersion"))                 return (void*)&SharpOS_SN_GetUnixVersion;
    if (sharpos_streq(n,"SystemNative_GetOSArchitecture"))              return (void*)&SharpOS_SN_GetOSArchitecture;
    if (sharpos_streq(n,"SystemNative_GetProcessArchitecture"))         return (void*)&SharpOS_SN_GetProcessArchitecture;
    if (sharpos_streq(n,"SystemNative_GetUnixRelease"))                 return (void*)&SharpOS_SN_GetUnixRelease;
    if (sharpos_streq(n,"SystemNative_Free"))                           return (void*)&SharpOS_SN_Free;
    if (sharpos_streq(n,"SystemNative_Malloc"))                         return (void*)&SharpOS_SN_Malloc;
    if (sharpos_streq(n,"SystemNative_Realloc"))                        return (void*)&SharpOS_SN_Realloc;
    if (sharpos_streq(n,"SystemNative_Calloc"))                         return (void*)&SharpOS_SN_Calloc;
    if (sharpos_streq(n,"SystemNative_CreateSocketEventPort"))          return (void*)&SharpOS_SN_CreateSocketEventPort;
    if (sharpos_streq(n,"SystemNative_CloseSocketEventPort"))           return (void*)&SharpOS_SN_CloseSocketEventPort;
    if (sharpos_streq(n,"SystemNative_CreateSocketEventBuffer"))        return (void*)&SharpOS_SN_CreateSocketEventBuffer;
    if (sharpos_streq(n,"SystemNative_FreeSocketEventBuffer"))          return (void*)&SharpOS_SN_FreeSocketEventBuffer;
    if (sharpos_streq(n,"SystemNative_SysLog"))                         return (void*)&SharpOS_SN_SysLog;
    return nullptr;
}

extern "C" void* GetProcAddress(void* mod, const char* name) {
    TRACE_REAL(GetProcAddress);
    if (mod == SHARPOS_ADVAPI32_HMODULE && name != nullptr) {
        // ETW symbol table — extend по мере появления новых walls.
        if (sharpos_streq(name, "EventRegister"))         { g_LastError = 0; return (void*)&SharpOS_EventRegister; }
        if (sharpos_streq(name, "EventUnregister"))       { g_LastError = 0; return (void*)&SharpOS_EventUnregister; }
        if (sharpos_streq(name, "EventWriteTransfer"))    { g_LastError = 0; return (void*)&SharpOS_EventWriteTransfer; }
        if (sharpos_streq(name, "EventWriteEx"))          { g_LastError = 0; return (void*)&SharpOS_EventWriteEx; }
        if (sharpos_streq(name, "EventWriteString"))      { g_LastError = 0; return (void*)&SharpOS_EventWriteString; }
        if (sharpos_streq(name, "EventActivityIdControl")){ g_LastError = 0; return (void*)&SharpOS_EventActivityIdControl; }
        if (sharpos_streq(name, "EventSetInformation"))   { g_LastError = 0; return (void*)&SharpOS_EventSetInformation; }
        if (sharpos_streq(name, "EventEnabled"))          { g_LastError = 0; return (void*)&SharpOS_EventEnabled; }
        if (sharpos_streq(name, "EventProviderEnabled"))  { g_LastError = 0; return (void*)&SharpOS_EventProviderEnabled; }
        // step126: Registry — empty subsystem (kernel C# routes through
        // SharpOSHost_Reg* exports, all reads return ERROR_FILE_NOT_FOUND
        // / ERROR_NO_MORE_ITEMS, empty enums).
        if (sharpos_streq(name, "RegOpenKeyExW"))         { g_LastError = 0; return (void*)&RegOpenKeyExW; }
        if (sharpos_streq(name, "RegCloseKey"))           { g_LastError = 0; return (void*)&RegCloseKey; }
        if (sharpos_streq(name, "RegQueryValueExW"))      { g_LastError = 0; return (void*)&RegQueryValueExW; }
        if (sharpos_streq(name, "RegEnumKeyExW"))         { g_LastError = 0; return (void*)&RegEnumKeyExW; }
        if (sharpos_streq(name, "RegEnumValueW"))         { g_LastError = 0; return (void*)&RegEnumValueW; }
        if (sharpos_streq(name, "RegQueryInfoKeyW"))      { g_LastError = 0; return (void*)&RegQueryInfoKeyW; }
        if (sharpos_streq(name, "RegCreateKeyExW"))       { g_LastError = 0; return (void*)&RegCreateKeyExW; }
        if (sharpos_streq(name, "RegFlushKey"))           { g_LastError = 0; return (void*)&RegFlushKey; }
        // step126: Token/Privilege stubs — all return controlled failure
        // so ProcessManager / WindowsIdentity / etc. cctors don't throw.
        if (sharpos_streq(name, "LookupPrivilegeValueW")) { g_LastError = 0; return (void*)&LookupPrivilegeValueW; }
        if (sharpos_streq(name, "LookupPrivilegeNameW"))  { g_LastError = 0; return (void*)&LookupPrivilegeNameW; }
        if (sharpos_streq(name, "OpenProcessToken"))      { g_LastError = 0; return (void*)&OpenProcessToken; }
        if (sharpos_streq(name, "OpenThreadToken"))       { g_LastError = 0; return (void*)&OpenThreadToken; }
        if (sharpos_streq(name, "AdjustTokenPrivileges")) { g_LastError = 0; return (void*)&AdjustTokenPrivileges; }
        if (sharpos_streq(name, "GetTokenInformation"))   { g_LastError = 0; return (void*)&GetTokenInformation; }
        if (sharpos_streq(name, "ImpersonateLoggedOnUser")){ g_LastError = 0; return (void*)&ImpersonateLoggedOnUser; }
        if (sharpos_streq(name, "RevertToSelf"))          { g_LastError = 0; return (void*)&RevertToSelf; }
        if (sharpos_streq(name, "CheckTokenMembership"))  { g_LastError = 0; return (void*)&CheckTokenMembership; }
        if (sharpos_streq(name, "DuplicateTokenEx"))      { g_LastError = 0; return (void*)&DuplicateTokenEx; }
        if (sharpos_streq(name, "LookupAccountNameW"))    { g_LastError = 0; return (void*)&LookupAccountNameW; }
        if (sharpos_streq(name, "SaferIdentifyLevel"))    { g_LastError = 0; return (void*)&SaferIdentifyLevel; }
        if (sharpos_streq(name, "SaferIdentifyLevelW"))   { g_LastError = 0; return (void*)&SaferIdentifyLevel; }
        if (sharpos_streq(name, "SaferIdentifyLevelA"))   { g_LastError = 0; return (void*)&SaferIdentifyLevelA; }
        if (sharpos_streq(name, "SaferGetLevelInformation")) { g_LastError = 0; return (void*)&SaferGetLevelInformation; }
        if (sharpos_streq(name, "SaferCloseLevel"))       { g_LastError = 0; return (void*)&SaferCloseLevel; }
        if (sharpos_streq(name, "SaferComputeTokenFromLevel")) { g_LastError = 0; return (void*)&SaferComputeTokenFromLevel; }
        SharpOSHost_DebugPrintForced("[GetProcAddress advapi32] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;   // ERROR_PROC_NOT_FOUND
        return nullptr;
    }
    if (mod == SHARPOS_SYSNATIVE_HMODULE && name != nullptr) {
        void* p = sharpos_resolve_sysnative(name);
        if (p != nullptr) { g_LastError = 0; return p; }
        SharpOSHost_DebugPrintForced("[GetProcAddress libSystem.Native] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_KERNEL32_HMODULE && name != nullptr) {
        extern void* sharpos_resolve_kernel32(const char*);
        void* p = sharpos_resolve_kernel32(name);
        if (p != nullptr) { g_LastError = 0; return p; }
        // Unknown → print the exact name so we extend precisely, and
        // return nullptr (managed surfaces EntryPointNotFound, not the
        // DllNotFound panic — we progress + learn the next symbol).
        // Phase E11: route via DebugWrite (not Verbose-gated) so the
        // missing-symbol name shows up in the default-quiet log. Drop
        // back to DebugPrint after E11 acceptance.
        const char* prefix = "[GetProcAddress kernel32] unknown name=";
        int prefixLen = 0; while (prefix[prefixLen] != 0) prefixLen++;
        int nameLen = 0;   while (name[nameLen]   != 0) nameLen++;
        SharpOSHost_DebugWrite((const void*)prefix, prefixLen);
        SharpOSHost_DebugWrite((const void*)name,   nameLen);
        SharpOSHost_DebugWrite((const void*)"\n",   1);
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_OLE32_HMODULE && name != nullptr) {
        if (sharpos_streq(name, "CoCreateGuid"))      { g_LastError = 0; return (void*)&CoCreateGuid; }
        // step126.10: COM init
        if (sharpos_streq(name, "CoInitializeEx"))    { g_LastError = 0; return (void*)&CoInitializeEx; }
        if (sharpos_streq(name, "CoInitialize"))      { g_LastError = 0; return (void*)&CoInitialize; }
        if (sharpos_streq(name, "CoUninitialize"))    { g_LastError = 0; return (void*)&CoUninitialize; }
        if (sharpos_streq(name, "CoCreateInstance"))  { g_LastError = 0; return (void*)&CoCreateInstance; }
        if (sharpos_streq(name, "CoTaskMemAlloc"))    { g_LastError = 0; return (void*)&CoTaskMemAlloc; }
        if (sharpos_streq(name, "CoTaskMemFree"))     { g_LastError = 0; return (void*)&CoTaskMemFree; }
        SharpOSHost_DebugPrintForced("[GetProcAddress ole32] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_SHELL32_HMODULE && name != nullptr) {
        // step126.2: Known-folder lookups return E_FAIL (no profile/AppData
        // on unikernel). BCL Environment.GetFolderPathCore handles this by
        // returning string.Empty.
        if (sharpos_streq(name, "SHGetKnownFolderPath"))  { g_LastError = 0; return (void*)&SHGetKnownFolderPath; }
        if (sharpos_streq(name, "SHGetKnownFolderPathW")) { g_LastError = 0; return (void*)&SHGetKnownFolderPath; }
        if (sharpos_streq(name, "SHGetFolderPathW"))      { g_LastError = 0; return (void*)&SHGetFolderPathW; }
        SharpOSHost_DebugPrintForced("[GetProcAddress shell32] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_MPR_HMODULE && name != nullptr) {
        // WNetGetConnectionW: PS PSDrive auto-mount calls this for every
        // candidate drive to decide local vs network. Returning
        // ERROR_NOT_CONNECTED tells PS "this is a local drive" and the C:
        // PSDrive registers normally. Without this stub the entire init
        // cascade aborts.
        if (sharpos_streq(name, "WNetGetConnectionW")
         || sharpos_streq(name, "WNetGetConnection")) {
            g_LastError = 0;
            return (void*)&WNetGetConnectionW;
        }
        SharpOSHost_DebugPrintForced("[GetProcAddress mpr] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_WINTRUST_HMODULE && name != nullptr) {
        // WinVerifyTrust: PS SystemPolicy probes Authenticode signature on
        // pwsh.dll to decide CLM. Return 0 = ERROR_SUCCESS = trusted.
        // The W spellings are probed too; wintrust has no separate A/W bodies.
        if (sharpos_streq(name, "WinVerifyTrust") || sharpos_streq(name, "WinVerifyTrustW")) {
            g_LastError = 0;
            return (void*)&WinVerifyTrust;
        }
        if (sharpos_streq(name, "WTHelperProvDataFromStateData")
            || sharpos_streq(name, "WTHelperProvDataFromStateDataW")) {
            g_LastError = 0;
            return (void*)&WTHelperProvDataFromStateData;
        }
        if (sharpos_streq(name, "WTHelperGetProvSignerFromChain")) {
            g_LastError = 0;
            return (void*)&WTHelperGetProvSignerFromChain;
        }
        if (sharpos_streq(name, "WTHelperGetProvCertFromChain")) {
            g_LastError = 0;
            return (void*)&WTHelperGetProvCertFromChain;
        }
        SharpOSHost_DebugPrintForced("[GetProcAddress wintrust] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_IPHLPAPI_HMODULE && name != nullptr) {
        // GetAdaptersAddresses: PS PSDrive enumeration walks network adapters.
        // Returning ERROR_NO_DATA tells PS "no adapters" and init proceeds.
        if (sharpos_streq(name, "GetAdaptersAddresses")) {
            g_LastError = 0;
            return (void*)&GetAdaptersAddresses;
        }
        SharpOSHost_DebugPrintForced("[GetProcAddress iphlpapi] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_UCRTBASE_HMODULE && name != nullptr) {
        // Interop.Ucrtbase declares the CRT allocators; ours route to the
        // kernel heap. P/Invoke resolves lazily, so a name that is never
        // called never gets here — an unknown one is printed, not guessed at.
        if (sharpos_streq(name, "malloc"))  { g_LastError = 0; return (void*)&malloc; }
        if (sharpos_streq(name, "free"))    { g_LastError = 0; return (void*)&free; }
        if (sharpos_streq(name, "calloc"))  { g_LastError = 0; return (void*)&calloc; }
        if (sharpos_streq(name, "realloc")) { g_LastError = 0; return (void*)&realloc; }
        SharpOSHost_DebugPrintForced("[GetProcAddress ucrtbase] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_USER32_HMODULE && name != nullptr) {
        // step126.11: user32 — system-wide UI/accessibility queries.
        if (sharpos_streq(name, "SystemParametersInfoW")) { g_LastError = 0; return (void*)&SystemParametersInfoW; }
        if (sharpos_streq(name, "SystemParametersInfoA")) { g_LastError = 0; return (void*)&SystemParametersInfoA; }
        if (sharpos_streq(name, "SystemParametersInfo"))  { g_LastError = 0; return (void*)&SystemParametersInfoW; }
        if (sharpos_streq(name, "GetSystemMetrics"))      { g_LastError = 0; return (void*)&GetSystemMetrics; }
        if (sharpos_streq(name, "GetConsoleWindow"))      { g_LastError = 0; return (void*)&GetConsoleWindow; }
        if (sharpos_streq(name, "EnumWindows"))           { g_LastError = 0; return (void*)&EnumWindows; }
        SharpOSHost_DebugPrintForced("[GetProcAddress user32] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_AMSI_HMODULE && name != nullptr) {
        if (sharpos_streq(name, "AmsiInitialize"))      { g_LastError = 0; return (void*)&AmsiInitialize; }
        if (sharpos_streq(name, "AmsiUninitialize"))    { g_LastError = 0; return (void*)&AmsiUninitialize; }
        if (sharpos_streq(name, "AmsiOpenSession"))     { g_LastError = 0; return (void*)&AmsiOpenSession; }
        if (sharpos_streq(name, "AmsiCloseSession"))    { g_LastError = 0; return (void*)&AmsiCloseSession; }
        if (sharpos_streq(name, "AmsiScanString"))      { g_LastError = 0; return (void*)&AmsiScanString; }
        if (sharpos_streq(name, "AmsiScanBuffer"))      { g_LastError = 0; return (void*)&AmsiScanBuffer; }
        if (sharpos_streq(name, "AmsiNotifyOperation")) { g_LastError = 0; return (void*)&AmsiNotifyOperation; }
        if (sharpos_streq(name, "AmsiNotifyOperationA")){ g_LastError = 0; return (void*)&AmsiNotifyOperationA; }
        SharpOSHost_DebugPrintForced("[GetProcAddress amsi] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_WLDP_HMODULE && name != nullptr) {
        // step126.4: Lock Down Policy — all stubs return "no restrictions".
        if (sharpos_streq(name, "WldpGetLockdownPolicy"))         { g_LastError = 0; return (void*)&WldpGetLockdownPolicy; }
        if (sharpos_streq(name, "WldpQueryDynamicCodeTrust"))     { g_LastError = 0; return (void*)&WldpQueryDynamicCodeTrust; }
        if (sharpos_streq(name, "WldpSetDynamicCodeTrust"))       { g_LastError = 0; return (void*)&WldpSetDynamicCodeTrust; }
        if (sharpos_streq(name, "WldpIsClassInApprovedList"))     { g_LastError = 0; return (void*)&WldpIsClassInApprovedList; }
        if (sharpos_streq(name, "WldpQueryWindowsLockdownMode"))  { g_LastError = 0; return (void*)&WldpQueryWindowsLockdownMode; }
        // PS 7.x uses WldpQueryWindowsLockdownPolicy (newer name). Without
        // this stub PS catches EntryPointNotFoundException and defaults to
        // Enforce mode → ConstrainedLanguage → built-in cmdlets do not
        // auto-load → "Get-ChildItem is not recognized". Same signature
        // (UNLOCKED = 0), so just alias to the existing Mode handler.
        if (sharpos_streq(name, "WldpQueryWindowsLockdownPolicy")){ g_LastError = 0; return (void*)&WldpQueryWindowsLockdownMode; }
        if (sharpos_streq(name, "WldpIsDynamicCodePolicyEnabled")){ g_LastError = 0; return (void*)&WldpIsDynamicCodePolicyEnabled; }
        if (sharpos_streq(name, "WldpCanExecuteFile"))            { g_LastError = 0; return (void*)&WldpCanExecuteFile; }
        SharpOSHost_DebugPrintForced("[GetProcAddress wldp] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_BCRYPT_HMODULE && name != nullptr) {
        if (sharpos_streq(name, "BCryptGenRandom"))             { g_LastError = 0; return (void*)&BCryptGenRandom; }
        if (sharpos_streq(name, "BCryptOpenAlgorithmProvider")) { g_LastError = 0; return (void*)&BCryptOpenAlgorithmProvider; }
        if (sharpos_streq(name, "BCryptCloseAlgorithmProvider")){ g_LastError = 0; return (void*)&BCryptCloseAlgorithmProvider; }
        if (sharpos_streq(name, "BCryptCreateHash"))            { g_LastError = 0; return (void*)&BCryptCreateHash; }
        if (sharpos_streq(name, "BCryptHashData"))              { g_LastError = 0; return (void*)&BCryptHashData; }
        if (sharpos_streq(name, "BCryptFinishHash"))            { g_LastError = 0; return (void*)&BCryptFinishHash; }
        if (sharpos_streq(name, "BCryptDestroyHash"))           { g_LastError = 0; return (void*)&BCryptDestroyHash; }
        if (sharpos_streq(name, "BCryptGetProperty"))           { g_LastError = 0; return (void*)&BCryptGetProperty; }
        SharpOSHost_DebugPrintForced("[GetProcAddress bcrypt] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_SECUR32_HMODULE && name != nullptr) {
        if (sharpos_streq(name, "GetUserNameExW")) { g_LastError = 0; return (void*)&GetUserNameExW; }
        SharpOSHost_DebugPrintForced("[GetProcAddress secur32] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_SYSCRYPTO_HMODULE && name != nullptr) {
        if (sharpos_streq(name, "CryptoNative_GetRandomBytes"))       { g_LastError = 0; return (void*)&CryptoNative_GetRandomBytes; }
        if (sharpos_streq(name, "CryptoNative_EnsureOpenSslInitialized")) { g_LastError = 0; return (void*)&CryptoNative_EnsureOpenSslInitialized; }
        if (sharpos_streq(name, "CryptoNative_EvpSha256"))            { g_LastError = 0; return (void*)&CryptoNative_EvpSha256; }
        if (sharpos_streq(name, "CryptoNative_EvpMdCtxCreate"))       { g_LastError = 0; return (void*)&CryptoNative_EvpMdCtxCreate; }
        if (sharpos_streq(name, "CryptoNative_EvpDigestUpdate"))      { g_LastError = 0; return (void*)&CryptoNative_EvpDigestUpdate; }
        if (sharpos_streq(name, "CryptoNative_EvpDigestReset"))       { g_LastError = 0; return (void*)&CryptoNative_EvpDigestReset; }
        if (sharpos_streq(name, "CryptoNative_EvpDigestFinalEx"))     { g_LastError = 0; return (void*)&CryptoNative_EvpDigestFinalEx; }
        if (sharpos_streq(name, "CryptoNative_EvpDigestCurrent"))     { g_LastError = 0; return (void*)&CryptoNative_EvpDigestCurrent; }
        if (sharpos_streq(name, "CryptoNative_EvpDigestOneShot"))     { g_LastError = 0; return (void*)&CryptoNative_EvpDigestOneShot; }
        if (sharpos_streq(name, "CryptoNative_EvpMdCtxDestroy"))      { g_LastError = 0; return (void*)&CryptoNative_EvpMdCtxDestroy; }
        if (sharpos_streq(name, "CryptoNative_EvpMdSize"))            { g_LastError = 0; return (void*)&CryptoNative_EvpMdSize; }
        if (sharpos_streq(name, "CryptoNative_GetMaxMdSize"))         { g_LastError = 0; return (void*)&CryptoNative_GetMaxMdSize; }
        SharpOSHost_DebugPrintForced("[GetProcAddress syscrypto] unknown name=");
        SharpOSHost_DebugPrintForced(name);
        SharpOSHost_DebugPrintForced("\n");
        g_LastError = 127;
        return nullptr;
    }
    g_LastError = 127;   // ERROR_PROC_NOT_FOUND — we have no exports
    return nullptr;
}
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

// qsort — recursive Lomuto-partition quicksort. CoreCLR uses qsort during
// type loading and JIT setup, typically on small arrays; O(n²) worst case
// is acceptable, recursion depth bounded by ~log2(n) on random inputs.
typedef int (*qsort_cmp_t)(const void*, const void*);

static inline void qsort_swap(char* a, char* b, size_t sz) {
    while (sz--) { char t = *a; *a = *b; *b = t; ++a; ++b; }
}

extern "C" void qsort(void* base, size_t n, size_t sz, qsort_cmp_t cmp) {
    if (n < 2 || sz == 0 || base == nullptr || cmp == nullptr) return;
    char* arr = (char*)base;

    // Lomuto partition с last element as pivot.
    char* pivot = arr + (n - 1) * sz;
    size_t i = 0;
    for (size_t j = 0; j < n - 1; j++) {
        char* elem = arr + j * sz;
        if (cmp(elem, pivot) < 0) {
            if (i != j) qsort_swap(arr + i * sz, elem, sz);
            i++;
        }
    }
    qsort_swap(arr + i * sz, pivot, sz);
    qsort(arr, i, sz, cmp);
    qsort(arr + (i + 1) * sz, n - i - 1, sz, cmp);
}
CRT_REAL(qsort);

// RtlInstallFunctionTableCallback — registers a callback for dynamic PE
// function tables (used by CoreCLR's code-heap manager so its JIT-emitted
// code regions can resolve unwind info during SEH walks). Our SehUnwind.cs
// RtlLookupFunctionEntry handles static .pdata в kernel image; dynamic
// regions don't have unwind entries yet, but returning success keeps the
// runtime moving forward — failures на NX/instr-fetch будут видны через
// our hardware fault handler if exec actually hits a JIT'd address.
//
// Signature (Win32):
//   BOOLEAN RtlInstallFunctionTableCallback(
//       DWORD64 TableIdentifier, DWORD64 BaseAddress, DWORD Length,
//       PGET_RUNTIME_FUNCTION_CALLBACK Callback, PVOID Context,
//       PCWSTR OutOfProcessCallbackDll);
// Step 1: forward the JIT code-heap unwind callback into the kernel SEH
// registry (OS/src/PAL/SharpOSHost/SehUnwind.cs) instead of discarding it.
// Without this, managed exceptions can't unwind through JIT frames (no
// static .pdata) → unhandled panic. Weak fallback for the non-kernel link.
extern "C" __attribute__((weak)) void SharpOSHost_RegisterFunctionTableCallback(
    uint64_t /*base*/, uint32_t /*len*/, void* /*callback*/, void* /*context*/) {}

extern "C" int RtlInstallFunctionTableCallback(uint64_t /*tableId*/,
                                                uint64_t baseAddress,
                                                uint32_t length,
                                                void* callback,
                                                void* context,
                                                const wchar_t* /*oopDll*/) {
    SharpOSHost_DebugPrint("[RtlInstallFunctionTableCallback] base=0x");
    SharpOSHost_DebugPrintHex(baseAddress);
    SharpOSHost_DebugPrint(" len=0x");
    SharpOSHost_DebugPrintHex((uint64_t)length);
    SharpOSHost_DebugPrint("\n");
    SharpOSHost_RegisterFunctionTableCallback(baseAddress, length, callback, context);
    g_LastError = 0;
    return 1;   // TRUE — success
}
CRT_REAL(RtlInstallFunctionTableCallback);

// RtlAddFunctionTable — registers a loaded image's STATIC .pdata
// (sorted RUNTIME_FUNCTION[], RVAs relative to BaseAddress). CoreCLR's
// PEImageLayout calls this for R2R images (e.g. System.Private.CoreLib
// precompiled code mapped into the VM window) — peimagelayout.cpp's
// block is re-enabled under TARGET_SHARPOS. Without registering, the
// kernel SEH walker has no unwind info for R2R frames → "invalid Rip"
// → unhandled C++ exception. Forward to the kernel registry; the real
// search lives C#-side (SehUnwind.cs) per CLAUDE.md invariant 1.
// Signature (Win32): BOOLEAN RtlAddFunctionTable(PRUNTIME_FUNCTION,
//   DWORD EntryCount, DWORD64 BaseAddress).
extern "C" int RtlAddFunctionTable(void* functionTable, uint32_t entryCount,
                                   uint64_t baseAddress) {
    SharpOSHost_DebugPrint("[RtlAddFunctionTable] base=0x");
    SharpOSHost_DebugPrintHex(baseAddress);
    SharpOSHost_DebugPrint(" count=0x");
    SharpOSHost_DebugPrintHex((uint64_t)entryCount);
    SharpOSHost_DebugPrint("\n");
    if (functionTable != nullptr && entryCount != 0)
        SharpOSHost_RegisterStaticFunctionTable(baseAddress, functionTable, entryCount);
    g_LastError = 0;
    return 1;   // TRUE — success
}
CRT_REAL(RtlAddFunctionTable);

// RtlDeleteFunctionTable — unregisters a static function table previously
// added via RtlAddFunctionTable or RtlInstallFunctionTableCallback. No-op
// for us: registries are append-only for the process lifetime (images and
// JIT heaps are not unloaded on this unikernel).
extern "C" int RtlDeleteFunctionTable(void* /*functionTable*/) {
    g_LastError = 0;
    return 1;
}
CRT_REAL(RtlDeleteFunctionTable);

// Phase E10 Path B: register a stub heap (LoaderAllocator precode /
// call-counting / VSD / dynamic-helper) as a leaf-unwind range.
// SehUnwind synthesizes a "ret-only" RUNTIME_FUNCTION for any RIP in
// this range so the unwinder pops [rsp] into Rip and steps past the
// stub to the JIT method that called it. Without this, exceptions
// thrown from a runtime helper called BY a stub can't unwind past
// the stub layer — see step103 (ThreadPool init throw).
extern "C" __attribute__((weak)) void SharpOSHost_RegisterStubRange(
    uint64_t /*base*/, uint64_t /*length*/) {}

extern "C" void SharpOSRegisterStubHeap(void* start, uint64_t length) {
    if (start == nullptr || length == 0) return;
    SharpOSHost_DebugPrint("[StubHeap reg] start=0x");
    SharpOSHost_DebugPrintHex((uint64_t)start);
    SharpOSHost_DebugPrint(" len=0x");
    SharpOSHost_DebugPrintHex(length);
    SharpOSHost_DebugPrint("\n");
    SharpOSHost_RegisterStubRange((uint64_t)start, length);
}

// Phase E11: IO completion port -- Win32 names → SharpOSHost_Iocp* in
// kernel C#. Backs CoreCLR's LowLevelLifoSemaphore.Windows.cs which is
// used by PortableThreadPool / TimerQueue.Portable. Implementation is a
// LIFO counting semaphore via kernel.Threading.Semaphore (already LIFO);
// no file association, no overlapped completion. Just enough for the
// LIFO sem use case.
extern "C" __attribute__((weak)) uint64_t SharpOSHost_IocpCreate(int /*maxConcurrent*/) { return 0; }
extern "C" __attribute__((weak)) int      SharpOSHost_IocpWait(uint64_t /*handle*/, int /*timeoutMs*/) { return 0; }
extern "C" __attribute__((weak)) int      SharpOSHost_IocpPost(uint64_t /*handle*/, int /*count*/) { return 0; }

// CreateIoCompletionPort(file, existingPort, completionKey, threadCount)
// Win32 semantics:
//   file == INVALID_HANDLE_VALUE && existingPort == NULL → create a
//   standalone IOCP not associated with any file. That's the only case
//   PortableThreadPool ever uses (LIFO sem). Any other shape returns
//   NULL and we leave LastError = ERROR_INVALID_PARAMETER.
extern "C" void* CreateIoCompletionPort(void* file, void* existingPort,
                                        uint64_t /*completionKey*/, uint32_t threadCount) {
    if (existingPort != nullptr || (intptr_t)file != -1) {
        g_LastError = 87;   // ERROR_INVALID_PARAMETER
        return nullptr;
    }
    int cap = threadCount == 0 ? 1 : (int)threadCount;
    uint64_t h = SharpOSHost_IocpCreate(cap);
    if (h == 0) { g_LastError = 8 /*ERROR_NOT_ENOUGH_MEMORY*/; return nullptr; }
    g_LastError = 0;
    return (void*)h;
}
CRT_REAL(CreateIoCompletionPort);

// GetQueuedCompletionStatus(port, *bytes, *key, *overlapped, timeoutMs)
// Blocks until PostQueuedCompletionStatus pings us (or timeout). Win32
// returns TRUE on success, FALSE on timeout (LastError = WAIT_TIMEOUT).
extern "C" int GetQueuedCompletionStatus(void* port, uint32_t* lpNumBytes,
                                         uint64_t* lpKey, void** lpOverlapped,
                                         uint32_t dwMilliseconds) {
    if (lpNumBytes   != nullptr) *lpNumBytes   = 0;
    if (lpKey        != nullptr) *lpKey        = 0;
    if (lpOverlapped != nullptr) *lpOverlapped = nullptr;
    if (port == nullptr) { g_LastError = 6 /*ERROR_INVALID_HANDLE*/; return 0; }
    int tmo = (int)dwMilliseconds;
    if (dwMilliseconds == 0xFFFFFFFFu) tmo = -1;   // INFINITE
    int ok = SharpOSHost_IocpWait((uint64_t)port, tmo);
    if (ok == 0) { g_LastError = 258 /*WAIT_TIMEOUT*/; return 0; }
    g_LastError = 0;
    return 1;
}
CRT_REAL(GetQueuedCompletionStatus);

extern "C" int PostQueuedCompletionStatus(void* port, uint32_t /*dwBytes*/,
                                          uint64_t /*dwKey*/, void* /*lpOverlapped*/) {
    if (port == nullptr) { g_LastError = 6 /*ERROR_INVALID_HANDLE*/; return 0; }
    int ok = SharpOSHost_IocpPost((uint64_t)port, 1);
    if (ok == 0) { g_LastError = 8 /*ERROR_NOT_ENOUGH_MEMORY*/; return 0; }
    g_LastError = 0;
    return 1;
}
CRT_REAL(PostQueuedCompletionStatus);

// ---------------------------------------------------------------------------
// kernel32/kernelbase/ntdll P/Invoke resolver. The framework assemblies are
// Windows-flavored; their [DllImport("kernel32.dll")] surface is statically
// linked into this image. GetProcAddress(SHARPOS_KERNEL32_HMODULE, name)
// funnels here. Defined at end of TU so every stub symbol above is visible.
// Conservative starter set (all confirmed defined above); unknown names are
// printed by GetProcAddress so we extend precisely, per the file's
// "extend по мере появления новых walls" philosophy.
extern "C" void* sharpos_resolve_kernel32(const char* n) {
    // Errno / process / thread identity
    if (sharpos_streq(n,"GetLastError"))                 return (void*)&GetLastError;
    if (sharpos_streq(n,"SetLastError"))                 return (void*)&SetLastError;
    if (sharpos_streq(n,"GetCurrentProcess"))            return (void*)&GetCurrentProcess;
    if (sharpos_streq(n,"GetCurrentThread"))             return (void*)&GetCurrentThread;
    if (sharpos_streq(n,"GetCurrentProcessId"))          return (void*)&GetCurrentProcessId;
    if (sharpos_streq(n,"GetCurrentThreadId"))           return (void*)&GetCurrentThreadId;
    if (sharpos_streq(n,"GetThreadIOPendingFlag"))       return (void*)&GetThreadIOPendingFlag;
    if (sharpos_streq(n,"IsDebuggerPresent"))            return (void*)&IsDebuggerPresent;
    if (sharpos_streq(n,"TerminateProcess"))             return (void*)&TerminateProcess;
    if (sharpos_streq(n,"RaiseFailFastException"))       return (void*)&RaiseFailFastException;
    // Time / perf
    if (sharpos_streq(n,"QueryPerformanceCounter"))      return (void*)&QueryPerformanceCounter;
    if (sharpos_streq(n,"QueryPerformanceFrequency"))    return (void*)&QueryPerformanceFrequency;
    if (sharpos_streq(n,"GetTickCount64"))               return (void*)&GetTickCount64;
    if (sharpos_streq(n,"GetSystemTimeAsFileTime"))      return (void*)&GetSystemTimeAsFileTime;
    if (sharpos_streq(n,"GetSystemTime"))                return (void*)&GetSystemTime;
    // Memory
    if (sharpos_streq(n,"VirtualAlloc"))                 return (void*)&VirtualAlloc;
    if (sharpos_streq(n,"VirtualFree"))                  return (void*)&VirtualFree;
    if (sharpos_streq(n,"VirtualProtect"))               return (void*)&VirtualProtect;
    if (sharpos_streq(n,"VirtualQuery"))                 return (void*)&VirtualQuery;
    if (sharpos_streq(n,"GetProcessHeap"))               return (void*)&GetProcessHeap;
    if (sharpos_streq(n,"HeapAlloc"))                    return (void*)&HeapAlloc;
    if (sharpos_streq(n,"HeapFree"))                     return (void*)&HeapFree;
    if (sharpos_streq(n,"HeapCreate"))                   return (void*)&HeapCreate;
    if (sharpos_streq(n,"HeapDestroy"))                  return (void*)&HeapDestroy;
    if (sharpos_streq(n,"LocalAlloc"))                   return (void*)&LocalAlloc;
    if (sharpos_streq(n,"LocalFree"))                    return (void*)&LocalFree;
    if (sharpos_streq(n,"GlobalMemoryStatusEx"))         return (void*)&GlobalMemoryStatusEx;
    if (sharpos_streq(n,"GetLargePageMinimum"))          return (void*)&GetLargePageMinimum;
    // System info / topology
    if (sharpos_streq(n,"GetSystemInfo"))                return (void*)&GetSystemInfo;
    if (sharpos_streq(n,"GetProcessAffinityMask"))       return (void*)&GetProcessAffinityMask;
    if (sharpos_streq(n,"GetProcessGroupAffinity"))      return (void*)&GetProcessGroupAffinity;
    if (sharpos_streq(n,"GetThreadGroupAffinity"))       return (void*)&GetThreadGroupAffinity;
    if (sharpos_streq(n,"GetLogicalProcessorInformation"))   return (void*)&GetLogicalProcessorInformation;
    if (sharpos_streq(n,"GetLogicalProcessorInformationEx")) return (void*)&GetLogicalProcessorInformationEx;
    if (sharpos_streq(n,"IsProcessorFeaturePresent"))    return (void*)&IsProcessorFeaturePresent;
    if (sharpos_streq(n,"GetEnabledXStateFeatures"))     return (void*)&GetEnabledXStateFeatures;
    if (sharpos_streq(n,"GetNumaHighestNodeNumber"))     return (void*)&GetNumaHighestNodeNumber;
    if (sharpos_streq(n,"IsProcessInJob"))               return (void*)&IsProcessInJob;
    if (sharpos_streq(n,"QueryInformationJobObject"))    return (void*)&QueryInformationJobObject;
    // Module / proc address
    if (sharpos_streq(n,"LoadLibraryExW"))               return (void*)&LoadLibraryExW;
    if (sharpos_streq(n,"LoadLibraryExA"))               return (void*)&LoadLibraryExA;
    if (sharpos_streq(n,"LoadLibraryW"))                 return (void*)&LoadLibraryW;
    if (sharpos_streq(n,"LoadLibraryA"))                 return (void*)&LoadLibraryA;
    if (sharpos_streq(n,"FreeLibrary"))                  return (void*)&FreeLibrary;
    if (sharpos_streq(n,"GetProcAddress"))               return (void*)&GetProcAddress;
    if (sharpos_streq(n,"GetModuleHandleW"))             return (void*)&GetModuleHandleW;
    if (sharpos_streq(n,"GetModuleHandleA"))             return (void*)&GetModuleHandleA;
    if (sharpos_streq(n,"GetModuleFileNameW"))           return (void*)&GetModuleFileNameW;
    // Synchronization / threads
    if (sharpos_streq(n,"CreateThread"))                 return (void*)&CreateThread;
    if (sharpos_streq(n,"ExitThread"))                   return (void*)&ExitThread;
    if (sharpos_streq(n,"ResumeThread"))                 return (void*)&ResumeThread;
    if (sharpos_streq(n,"GetThreadPriority"))            return (void*)&GetThreadPriority;
    if (sharpos_streq(n,"SetThreadPriority"))            return (void*)&SetThreadPriority;
    if (sharpos_streq(n,"SetThreadErrorMode"))           return (void*)&SetThreadErrorMode;
    if (sharpos_streq(n,"SetThreadStackGuarantee"))      return (void*)&SetThreadStackGuarantee;
    if (sharpos_streq(n,"CreateEventW"))                 return (void*)&CreateEventW;
    if (sharpos_streq(n,"CreateEventA"))                 return (void*)&CreateEventA;
    if (sharpos_streq(n,"CreateEventExW"))               return (void*)&CreateEventExW;
    if (sharpos_streq(n,"CreateSemaphoreW"))             return (void*)&CreateSemaphoreW;
    if (sharpos_streq(n,"CreateSemaphoreExW"))           return (void*)&CreateSemaphoreExW;
    if (sharpos_streq(n,"CreateMutexW"))                 return (void*)&CreateMutexW;
    if (sharpos_streq(n,"OpenMutexW"))                   return (void*)&OpenMutexW;
    if (sharpos_streq(n,"OpenMutexA"))                   return (void*)&OpenMutexA;
    if (sharpos_streq(n,"CreateMutexExW"))               return (void*)&CreateMutexExW;
    if (sharpos_streq(n,"SetEvent"))                     return (void*)&SetEvent;
    if (sharpos_streq(n,"ResetEvent"))                   return (void*)&ResetEvent;
    if (sharpos_streq(n,"ReleaseSemaphore"))             return (void*)&ReleaseSemaphore;
    if (sharpos_streq(n,"ReleaseMutex"))                 return (void*)&ReleaseMutex;
    if (sharpos_streq(n,"WaitOnAddress"))                return (void*)&WaitOnAddress;
    if (sharpos_streq(n,"WakeByAddressSingle"))          return (void*)&WakeByAddressSingle;
    if (sharpos_streq(n,"WakeByAddressAll"))             return (void*)&WakeByAddressAll;
    // Phase E11: IOCP shim for LowLevelLifoSemaphore.Windows.cs
    if (sharpos_streq(n,"CreateIoCompletionPort"))       return (void*)&CreateIoCompletionPort;
    if (sharpos_streq(n,"GetQueuedCompletionStatus"))    return (void*)&GetQueuedCompletionStatus;
    if (sharpos_streq(n,"PostQueuedCompletionStatus"))   return (void*)&PostQueuedCompletionStatus;
    if (sharpos_streq(n,"InitializeConditionVariable")) return (void*)&InitializeConditionVariable;
    if (sharpos_streq(n,"SleepConditionVariableCS"))    return (void*)&SleepConditionVariableCS;
    if (sharpos_streq(n,"SleepConditionVariableSRW"))   return (void*)&SleepConditionVariableSRW;
    if (sharpos_streq(n,"WakeConditionVariable"))       return (void*)&WakeConditionVariable;
    if (sharpos_streq(n,"WakeAllConditionVariable"))    return (void*)&WakeAllConditionVariable;
    if (sharpos_streq(n,"GetSystemTimes"))              return (void*)&GetSystemTimes;
    if (sharpos_streq(n,"QueryUnbiasedInterruptTime"))   return (void*)&QueryUnbiasedInterruptTime;
    if (sharpos_streq(n,"GetCurrentProcessorNumberEx"))  return (void*)&GetCurrentProcessorNumberEx;
    if (sharpos_streq(n,"CloseHandle"))                  return (void*)&CloseHandle;
    if (sharpos_streq(n,"DuplicateHandle"))              return (void*)&DuplicateHandle;
    if (sharpos_streq(n,"WaitForSingleObject"))          return (void*)&WaitForSingleObject;
    if (sharpos_streq(n,"WaitForSingleObjectEx"))        return (void*)&WaitForSingleObjectEx;
    if (sharpos_streq(n,"WaitForMultipleObjects"))       return (void*)&WaitForMultipleObjects;
    if (sharpos_streq(n,"WaitForMultipleObjectsEx"))     return (void*)&WaitForMultipleObjectsEx;
    if (sharpos_streq(n,"Sleep"))                        return (void*)&Sleep;
    if (sharpos_streq(n,"SleepEx"))                      return (void*)&SleepEx;
    if (sharpos_streq(n,"SwitchToThread"))               return (void*)&SwitchToThread;
    if (sharpos_streq(n,"InitializeCriticalSection"))    return (void*)&InitializeCriticalSection;
    if (sharpos_streq(n,"EnterCriticalSection"))         return (void*)&EnterCriticalSection;
    if (sharpos_streq(n,"LeaveCriticalSection"))         return (void*)&LeaveCriticalSection;
    if (sharpos_streq(n,"DeleteCriticalSection"))        return (void*)&DeleteCriticalSection;
    if (sharpos_streq(n,"AcquireSRWLockExclusive"))      return (void*)&AcquireSRWLockExclusive;
    if (sharpos_streq(n,"ReleaseSRWLockExclusive"))      return (void*)&ReleaseSRWLockExclusive;
    if (sharpos_streq(n,"SleepConditionVariableSRW"))    return (void*)&SleepConditionVariableSRW;
    // Strings / codepage
    if (sharpos_streq(n,"MultiByteToWideChar"))          return (void*)&MultiByteToWideChar;
    if (sharpos_streq(n,"WideCharToMultiByte"))          return (void*)&WideCharToMultiByte;
    if (sharpos_streq(n,"GetConsoleOutputCP"))           return (void*)&GetConsoleOutputCP;
    if (sharpos_streq(n,"GetOEMCP"))                     return (void*)&GetOEMCP;
    if (sharpos_streq(n,"GetACP"))                       return (void*)&GetACP;
    if (sharpos_streq(n,"GetConsoleCP"))                 return (void*)&GetConsoleCP;
    if (sharpos_streq(n,"GetCPInfo"))                    return (void*)&GetCPInfo;
    if (sharpos_streq(n,"OutputDebugStringA"))           return (void*)&OutputDebugStringA;
    if (sharpos_streq(n,"OutputDebugStringW"))           return (void*)&OutputDebugStringW;
    // Environment / command line
    if (sharpos_streq(n,"GetEnvironmentVariableW"))      return (void*)&GetEnvironmentVariableW;
    if (sharpos_streq(n,"GetEnvironmentVariableA"))      return (void*)&GetEnvironmentVariableA;
    if (sharpos_streq(n,"GetEnvironmentStringsW"))       return (void*)&GetEnvironmentStringsW;
    // step 99: system/env string getters (BCL Environment.* / Path.* / Directory.*)
    if (sharpos_streq(n,"GetCurrentDirectoryW"))         return (void*)&GetCurrentDirectoryW;
    if (sharpos_streq(n,"GetTempPathW"))                 return (void*)&GetTempPathW;
    if (sharpos_streq(n,"GetSystemDirectoryW"))          return (void*)&GetSystemDirectoryW;
    if (sharpos_streq(n,"GetWindowsDirectoryW"))         return (void*)&GetWindowsDirectoryW;
    if (sharpos_streq(n,"GetComputerNameExW"))           return (void*)&GetComputerNameExW;
    if (sharpos_streq(n,"GetVersionExW"))                return (void*)&GetVersionExW;
    if (sharpos_streq(n,"RtlGetVersion"))                return (void*)&RtlGetVersion;
    if (sharpos_streq(n,"RtlQueryProcessPlaceholderCompatibilityMode")) return (void*)&RtlQueryProcessPlaceholderCompatibilityMode;
    if (sharpos_streq(n,"GetLogicalDrives"))             return (void*)&GetLogicalDrives;
    if (sharpos_streq(n,"GetVolumeInformationW"))        return (void*)&GetVolumeInformationW;
    if (sharpos_streq(n,"GetDriveTypeW"))                return (void*)&GetDriveTypeW;
    if (sharpos_streq(n,"K32EnumProcesses"))             return (void*)&K32EnumProcesses;
    if (sharpos_streq(n,"GetFileAttributesExW"))         return (void*)&GetFileAttributesExW;
    if (sharpos_streq(n,"GetFileAttributesW"))           return (void*)&GetFileAttributesW;
    if (sharpos_streq(n,"FindFirstFileW"))               return (void*)&FindFirstFileW;
    if (sharpos_streq(n,"FindFirstFileExW"))             return (void*)&FindFirstFileExW;
    if (sharpos_streq(n,"FindNextFileW"))                return (void*)&FindNextFileW;
    if (sharpos_streq(n,"FindClose"))                    return (void*)&FindClose;
    if (sharpos_streq(n,"GetTempPath2W"))                return (void*)&GetTempPath2W;
    if (sharpos_streq(n,"GetSystemTimePreciseAsFileTime"))return (void*)&GetSystemTimePreciseAsFileTime;
    if (sharpos_streq(n,"SetThreadDescription"))         return (void*)&SetThreadDescription;
    if (sharpos_streq(n,"GetComputerNameW"))             return (void*)&GetComputerNameW;
    if (sharpos_streq(n,"GetTimeZoneInformation"))       return (void*)&GetTimeZoneInformation;
    if (sharpos_streq(n,"GetDynamicTimeZoneInformation"))return (void*)&GetDynamicTimeZoneInformation;
    if (sharpos_streq(n,"DeleteFileW"))                  return (void*)&DeleteFileW;
    if (sharpos_streq(n,"FreeEnvironmentStringsW"))      return (void*)&FreeEnvironmentStringsW;
    if (sharpos_streq(n,"GetCommandLineW"))              return (void*)&GetCommandLineW;
    if (sharpos_streq(n,"GetFullPathNameW"))             return (void*)&GetFullPathNameW;
    // step125: advapi32 Registry (empty subsystem in C# kernel side).
    if (sharpos_streq(n,"RegOpenKeyExW"))                return (void*)&RegOpenKeyExW;
    if (sharpos_streq(n,"RegCloseKey"))                  return (void*)&RegCloseKey;
    if (sharpos_streq(n,"RegQueryValueExW"))             return (void*)&RegQueryValueExW;
    if (sharpos_streq(n,"RegEnumKeyExW"))                return (void*)&RegEnumKeyExW;
    if (sharpos_streq(n,"RegEnumValueW"))                return (void*)&RegEnumValueW;
    if (sharpos_streq(n,"RegQueryInfoKeyW"))             return (void*)&RegQueryInfoKeyW;
    if (sharpos_streq(n,"RegCreateKeyExW"))              return (void*)&RegCreateKeyExW;
    if (sharpos_streq(n,"RegFlushKey"))                  return (void*)&RegFlushKey;
    // step126: kernel32 Console facade
    if (sharpos_streq(n,"GetStdHandle"))                 return (void*)&GetStdHandle;
    if (sharpos_streq(n,"GetStdHandleW"))                return (void*)&GetStdHandle;
    if (sharpos_streq(n,"SetConsoleOutputCP"))           return (void*)&SetConsoleOutputCP;
    if (sharpos_streq(n,"SetConsoleCP"))                 return (void*)&SetConsoleCP;
    if (sharpos_streq(n,"WriteConsoleW"))                return (void*)&WriteConsoleW;
    if (sharpos_streq(n,"WriteFile"))                    return (void*)&WriteFile;
    if (sharpos_streq(n,"GetConsoleMode"))               return (void*)&GetConsoleMode;
    if (sharpos_streq(n,"SetConsoleMode"))               return (void*)&SetConsoleMode;
    if (sharpos_streq(n,"GetFileType"))                  return (void*)&GetFileType;
    if (sharpos_streq(n,"GetConsoleScreenBufferInfo"))   return (void*)&GetConsoleScreenBufferInfo;
    if (sharpos_streq(n,"SetConsoleCursorPosition"))     return (void*)&SetConsoleCursorPosition;
    if (sharpos_streq(n,"SetConsoleTextAttribute"))      return (void*)&SetConsoleTextAttribute;
    // step126.9: W-suffixed aliases — same impl as the non-suffixed version.
    // (Some PowerShell binaries import these with the W suffix even though
    // the function takes only HANDLE; we just map both to the same shim.)
    if (sharpos_streq(n,"GetConsoleModeW"))              return (void*)&GetConsoleMode;
    if (sharpos_streq(n,"SetConsoleModeW"))              return (void*)&SetConsoleMode;
    if (sharpos_streq(n,"GetCurrentConsoleFontEx"))      return (void*)&GetCurrentConsoleFontEx;
    if (sharpos_streq(n,"GetConsoleCursorInfo"))         return (void*)&GetConsoleCursorInfo;
    if (sharpos_streq(n,"SetConsoleCursorInfo"))         return (void*)&SetConsoleCursorInfo;
    if (sharpos_streq(n,"GetCurrentConsoleFontExW"))     return (void*)&GetCurrentConsoleFontEx;
    if (sharpos_streq(n,"GetConsoleScreenBufferInfoW"))  return (void*)&GetConsoleScreenBufferInfo;
    if (sharpos_streq(n,"SetConsoleCtrlHandler"))        return (void*)&SetConsoleCtrlHandler;
    if (sharpos_streq(n,"SetConsoleCtrlHandlerW"))       return (void*)&SetConsoleCtrlHandler;
    if (sharpos_streq(n,"GetStartupInfoW"))              return (void*)&GetStartupInfoW;
    if (sharpos_streq(n,"GetStartupInfoA"))              return (void*)&GetStartupInfoA;
    if (sharpos_streq(n,"GetStartupInfoWA"))             return (void*)&GetStartupInfoW;  // typo'd by PowerShell
    if (sharpos_streq(n,"OpenProcess"))                  return (void*)&OpenProcess;
    if (sharpos_streq(n,"GetCPInfoExW"))                 return (void*)&GetCPInfoExW;
    if (sharpos_streq(n,"GetCPInfoExA"))                 return (void*)&GetCPInfoExA;
    if (sharpos_streq(n,"ReadConsole"))                  return (void*)&ReadConsoleW;
    if (sharpos_streq(n,"ReadConsoleW"))                 return (void*)&ReadConsoleW;
    if (sharpos_streq(n,"ReadConsoleA"))                 return (void*)&ReadConsoleA;
    // Console event input — PSReadLine does its own line editing and reads key
    // events rather than lines. Kernel policy in ConsoleInput.cs.
    if (sharpos_streq(n,"ReadConsoleInput"))             return (void*)&ReadConsoleInputW;
    if (sharpos_streq(n,"ReadConsoleInputW"))            return (void*)&ReadConsoleInputW;
    if (sharpos_streq(n,"ReadConsoleInputA"))            return (void*)&ReadConsoleInputA;
    if (sharpos_streq(n,"PeekConsoleInput"))             return (void*)&PeekConsoleInputW;
    if (sharpos_streq(n,"PeekConsoleInputW"))            return (void*)&PeekConsoleInputW;
    if (sharpos_streq(n,"GetNumberOfConsoleInputEvents")) return (void*)&GetNumberOfConsoleInputEvents;
    // GetConsoleWindow lives in kernel32 on Windows; it was only reachable
    // through the user32 sentinel, so PSReadLine's P/Invoke could not resolve it
    // and its whole initialization died on the entry-point lookup.
    if (sharpos_streq(n,"GetConsoleWindow"))             return (void*)&GetConsoleWindow;
    // step126.5: directory ops + env
    if (sharpos_streq(n,"CreateDirectoryW"))             return (void*)&CreateDirectoryW;
    if (sharpos_streq(n,"RemoveDirectoryW"))             return (void*)&RemoveDirectoryW;
    if (sharpos_streq(n,"SetEnvironmentVariableW"))      return (void*)&SetEnvironmentVariableW;
    if (sharpos_streq(n,"SetEnvironmentVariableA"))      return (void*)&SetEnvironmentVariableA;
    if (sharpos_streq(n,"FormatMessageW"))               return (void*)&FormatMessageW;
    if (sharpos_streq(n,"FormatMessageA"))               return (void*)&FormatMessageA;
    // Files / pipes
    if (sharpos_streq(n,"CreateFileW"))                  return (void*)&CreateFileW;
    if (sharpos_streq(n,"CreateFileMappingW"))           return (void*)&CreateFileMappingW;
    if (sharpos_streq(n,"FlushViewOfFile"))              return (void*)&FlushViewOfFile;
    if (sharpos_streq(n,"CreateNamedPipeA"))             return (void*)&CreateNamedPipeA;
    if (sharpos_streq(n,"ReadFile"))                     return (void*)&ReadFile;
    if (sharpos_streq(n,"SetFilePointer"))               return (void*)&SetFilePointer;
    if (sharpos_streq(n,"SetFilePointerEx"))             return (void*)&SetFilePointerEx;
    if (sharpos_streq(n,"GetFileInformationByHandleEx")) return (void*)&GetFileInformationByHandleEx;
    if (sharpos_streq(n,"FillConsoleOutputCharacterW")) return (void*)&FillConsoleOutputCharacterW;
    if (sharpos_streq(n,"FillConsoleOutputCharacter"))  return (void*)&FillConsoleOutputCharacterW;
    if (sharpos_streq(n,"FillConsoleOutputCharacterA")) return (void*)&FillConsoleOutputCharacterA;
    if (sharpos_streq(n,"FillConsoleOutputAttribute"))  return (void*)&FillConsoleOutputAttribute;
    if (sharpos_streq(n,"GetFileSize"))                  return (void*)&GetFileSize;
    // Misc / EH / icache
    if (sharpos_streq(n,"FlushInstructionCache"))        return (void*)&FlushInstructionCache;
    if (sharpos_streq(n,"FlushProcessWriteBuffers"))     return (void*)&FlushProcessWriteBuffers;
    if (sharpos_streq(n,"NtQuerySystemInformation"))     return (void*)&NtQuerySystemInformation;
    if (sharpos_streq(n,"NtQueryDirectoryFile"))         return (void*)&NtQueryDirectoryFile;
    if (sharpos_streq(n,"NtClose"))                      return (void*)&NtClose;
    if (sharpos_streq(n,"RtlCaptureContext"))            return (void*)&RtlCaptureContext;
    if (sharpos_streq(n,"RtlInstallFunctionTableCallback")) return (void*)&RtlInstallFunctionTableCallback;
    if (sharpos_streq(n,"RtlDeleteFunctionTable"))       return (void*)&RtlDeleteFunctionTable;
    return nullptr;   // unknown → GetProcAddress prints the name
}
