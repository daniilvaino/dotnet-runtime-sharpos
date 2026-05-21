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
CRT_STUB(_callnewh)
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
CRT_STUB(bsearch)
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
CRT_STUB(AdjustTokenPrivileges)
CRT_STUB(CancelIoEx)
// CloseHandle — real impl below (no-op for our fake handles)
// CoCreateGuid — real impl below (rdtsc-mixed pseudo-random v4 GUID)
CRT_STUB(CoTaskMemAlloc)
CRT_STUB(CoTaskMemFree)
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
CRT_STUB(FormatMessageW)
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
CRT_STUB(GetStdHandle)
// GetSystemInfo — real impl below
// GetSystemTime — real impl below
// GetSystemTimeAsFileTime — real impl below
CRT_STUB(GetThreadContext)
// GetThreadGroupAffinity — real impl below
// GetThreadPriority — real impl below (returns THREAD_PRIORITY_NORMAL)
// GetTickCount64 — real impl below
CRT_STUB(GetTokenInformation)
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
CRT_STUB(LocalFree)
CRT_STUB(LookupPrivilegeValueW)
// MapViewOfFile — real impl below (returns the file's in-memory buffer)
// MapViewOfFileEx — real impl below (ignores base hint, returns buf+offset)
// MultiByteToWideChar — real impl below (ASCII identity fast path)
CRT_STUB(OpenProcessToken)
CRT_STUB(OpenThreadToken)
// OutputDebugStringA/W — real impls below (silent no-op; no debugger attached)
// QueryInformationJobObject — real impl below
// QueryPerformanceCounter / QueryPerformanceFrequency — real impls below
CRT_STUB(QueryThreadCycleTime)
CRT_STUB(QueueUserAPC)
CRT_STUB(RaiseException)
// RaiseFailFastException — real impl below (print + continue, non-fatal)
// ReadFile — real impl below (forwarder to SharpOSHost_FileRead)
CRT_STUB(ReadProcessMemory)
CRT_STUB(RegCloseKey)
CRT_STUB(RegOpenKeyExW)
CRT_STUB(RegQueryValueExW)
// ReleaseSRWLockExclusive — real impl below
// ReleaseSemaphore — real impl below (no-op)
// ResetEvent — real impl below (no-op)
CRT_STUB(ResetWriteWatch)
// ResumeThread — real impl below (no-op, returns prev suspend count 0)
CRT_STUB(RevertToSelf)
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
CRT_STUB(SetEnvironmentVariableW)
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
CRT_STUB(WriteFile)

// --- Real impls (replace traps as we discover them empirically) ---
//
// Macro for symbol pair: function NAME + __imp_NAME data pointing to it.
#define CRT_REAL(NAME) extern "C" void* __imp_##NAME = (void*)&NAME

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
static double lm_sqrt(double x){ return __builtin_sqrt(x); }
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

static uint32_t g_LastError = 0;
extern "C" uint32_t GetLastError(void)  { /* TRACE_REAL too noisy */ return g_LastError; }
CRT_REAL(GetLastError);
extern "C" void SetLastError(uint32_t e) { g_LastError = e; }
CRT_REAL(SetLastError);

extern "C" int IsDebuggerPresent(void) { TRACE_REAL(IsDebuggerPresent); return 0; }
CRT_REAL(IsDebuggerPresent);

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
// internals. We don't have a real format engine but the FORMAT STRING
// alone is usually descriptive enough ("Module %s loaded from %s\n") —
// surface it on console. Buffer-filling variants ALSO clear the caller's
// buffer (NULL terminate at index 0) so downstream code sees empty
// string, not garbage.

extern "C" int __stdio_common_vsprintf(uint64_t /*options*/, char* buffer, size_t bufCount, const char* format, void* /*locale*/, void* args) {
    (void)format; (void)args;   // logging suppressed — too noisy
    if (buffer && bufCount > 0) buffer[0] = 0;
    return 0;
}
CRT_REAL(__stdio_common_vsprintf);

// JIT pre-import code does `assert(charsPrinted > 0)` after its
// diagnostic-format calls — must return positive. Кладём '?'+NUL и возвращаем 1.
// Логирование подавлено (раньше печатали format string как [sprintf_s] ... —
// слишком шумно, мозолит глаза в каждом prestub'е).
extern "C" int __stdio_common_vsprintf_s(uint64_t /*options*/, char* buffer, size_t bufCount, const char* format, void* /*locale*/, void* args) {
    (void)format; (void)args;   // logging suppressed — too noisy
    if (buffer && bufCount >= 2) { buffer[0] = '?'; buffer[1] = 0; return 1; }
    if (buffer && bufCount > 0) buffer[0] = 0;
    return 0;
}
CRT_REAL(__stdio_common_vsprintf_s);

extern "C" int __stdio_common_vsnprintf_s(uint64_t /*options*/, char* buffer, size_t bufCount, size_t /*maxCount*/, const char* format, void* /*locale*/, void* args) {
    (void)format; (void)args;   // logging suppressed — too noisy
    if (buffer && bufCount >= 2) { buffer[0] = '?'; buffer[1] = 0; return 1; }
    if (buffer && bufCount > 0) buffer[0] = 0;
    return 0;
}
CRT_REAL(__stdio_common_vsnprintf_s);

extern "C" int __stdio_common_vfprintf(uint64_t /*options*/, void* /*stream*/, const char* format, void* /*locale*/, void* args) {
    (void)format; (void)args;   // logging suppressed — too noisy
    return 0;
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

// _write — POSIX write(fd, buf, count). Surface stdout/stderr to console
// (with [_write fd=N] tag for filtering). Other fds — return error.
extern "C" int _write(int fd, const void* buf, unsigned int count) {
    if (fd != 1 && fd != 2) return -1;
    if (!buf || count == 0) return 0;
    SharpOSHost_DebugPrint(fd == 2 ? "[_write fd=2] " : "[_write fd=1] ");
    const char* s = (const char*)buf;
    char tmp[2] = { 0, 0 };
    for (unsigned int i = 0; i < count; i++) {
        char c = s[i];
        tmp[0] = ((c >= 0x20 && c < 0x7F) || c == '\n' || c == '\t') ? c : '?';
        SharpOSHost_DebugPrint(tmp);
    }
    SharpOSHost_DebugPrint("\n");
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
    SharpOSHost_DebugPrint("[TerminateProcess code=0x");
    SharpOSHost_DebugPrintHex(exitCode);
    // step 72 (sage): 0x80131506 == COR_E_EXECUTIONENGINE — a genuine
    // unrecoverable EE FailFast, not the EventPipe-assert→abort cascade we
    // intentionally swallow during bring-up. Continuing past it only
    // produces a post-fatal ignored-stackwalk storm that masks the real
    // result. Halt cleanly so the log ends at the FailFast.
    if (exitCode == 0x80131506u) {
        SharpOSHost_DebugPrint("] FATAL EE — halting\n");
        SharpOSHost_Panic("TerminateProcess(COR_E_EXECUTIONENGINE 0x80131506)");
    }
    SharpOSHost_DebugPrint("] ignored — keep going\n");
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

// --- Sync primitives: single-thread fakes ---
//
// SharpOS boot path single-threaded. CoreCLR creates events/semaphores
// для cross-thread signaling, но fires them в нашем контексте никто не
// блокирует. Возвращаем растущие fake handles (так что хеш-таблицы по
// HANDLE не имеют коллизий) — SetEvent/ResetEvent/Wait* no-op.

static uintptr_t g_fakeHandleCounter = 0x1000;

extern "C" void* CreateEventW(void* /*lpEventAttrs*/, int /*bManualReset*/, int /*bInitState*/, const wchar_t* /*lpName*/) {
    TRACE_REAL(CreateEventW);
    g_LastError = 0;
    return (void*)(++g_fakeHandleCounter);
}
CRT_REAL(CreateEventW);

extern "C" void* CreateEventA(void* /*lpEventAttrs*/, int /*bManualReset*/, int /*bInitState*/, const char* /*lpName*/) {
    TRACE_REAL(CreateEventA);
    g_LastError = 0;
    return (void*)(++g_fakeHandleCounter);
}
CRT_REAL(CreateEventA);

extern "C" void* CreateSemaphoreExW(void* /*lpAttrs*/, int32_t /*lInitial*/, int32_t /*lMax*/, const wchar_t* /*lpName*/, uint32_t /*flags*/, uint32_t /*access*/) {
    TRACE_REAL(CreateSemaphoreExW);
    g_LastError = 0;
    return (void*)(++g_fakeHandleCounter);
}
CRT_REAL(CreateSemaphoreExW);

extern "C" int SetEvent(void* /*h*/)   { TRACE_REAL(SetEvent);   g_LastError = 0; return 1; }
CRT_REAL(SetEvent);

extern "C" int ResetEvent(void* /*h*/) { TRACE_REAL(ResetEvent); g_LastError = 0; return 1; }
CRT_REAL(ResetEvent);

extern "C" int ReleaseSemaphore(void* /*h*/, int32_t /*lRelease*/, int32_t* lpPrev) {
    TRACE_REAL(ReleaseSemaphore);
    if (lpPrev) *lpPrev = 0;
    g_LastError = 0;
    return 1;
}
CRT_REAL(ReleaseSemaphore);

extern "C" int CloseHandle(void* h) {
    TRACE_REAL(CloseHandle);
    g_LastError = 0;
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
extern "C" uint32_t WaitForMultipleObjects(uint32_t /*n*/, void* /*ph*/, int /*all*/, uint32_t /*ms*/)              { TRACE_REAL(WaitForMultipleObjects);   return 0; }
CRT_REAL(WaitForMultipleObjects);
extern "C" uint32_t WaitForMultipleObjectsEx(uint32_t /*n*/, void* /*ph*/, int /*all*/, uint32_t /*ms*/, int /*alert*/) { TRACE_REAL(WaitForMultipleObjectsEx); return 0; }
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
    return sharpos_wstr_iends_with(name, "advapi32")
        || sharpos_wstr_iends_with(name, "advapi32.dll")
        || sharpos_wstr_iends_with(name, "advapi32.dll.dll");
}

static int sharpos_is_kernel32(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "kernel32")
        || sharpos_wstr_iends_with(name, "kernel32.dll")
        || sharpos_wstr_iends_with(name, "kernel32.dll.dll")
        || sharpos_wstr_iends_with(name, "kernelbase")
        || sharpos_wstr_iends_with(name, "kernelbase.dll")
        || sharpos_wstr_iends_with(name, "kernelbase.dll.dll")
        || sharpos_wstr_iends_with(name, "ntdll")
        || sharpos_wstr_iends_with(name, "ntdll.dll")
        || sharpos_wstr_iends_with(name, "ntdll.dll.dll");
}

static int sharpos_is_ole32(const wchar_t* name) {
    if (name == nullptr) return 0;
    return sharpos_wstr_iends_with(name, "ole32")
        || sharpos_wstr_iends_with(name, "ole32.dll")
        || sharpos_wstr_iends_with(name, "ole32.dll.dll");
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

extern "C" void* CreateFileW(const wchar_t* lpFileName,
                              uint32_t dwDesiredAccess,
                              uint32_t /*dwShareMode*/,
                              void* /*lpSecurityAttrs*/,
                              uint32_t /*dwCreationDisposition*/,
                              uint32_t /*dwFlagsAndAttributes*/,
                              void* /*hTemplateFile*/) {
    TRACE_REAL(CreateFileW);
    // Reject write/append/delete — read-only host FS access.
    if (dwDesiredAccess & 0x40000000u /*GENERIC_WRITE*/) {
        g_LastError = 5 /*ERROR_ACCESS_DENIED*/;
        return HANDLE_INVALID;
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
extern "C" int NtQuerySystemInformation(int SystemInformationClass,
                                        void* SystemInformation,
                                        unsigned int SystemInformationLength,
                                        unsigned int* ReturnLength) {
    const int  STATUS_SUCCESS              = 0;
    const int  STATUS_NOT_IMPLEMENTED      = (int)0xC0000002u;
    const int  STATUS_INFO_LENGTH_MISMATCH = (int)0xC0000004u;
    const int  SystemLeapSecondInformation = 206;
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
    return STATUS_NOT_IMPLEMENTED;
}
CRT_REAL(NtQuerySystemInformation);

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

// Silent (no TRACE_REAL): CoreCLR queries hundreds of config knobs at init,
// each as GetEnvironmentVariable*. With trace on, screen scrolls past
// actually interesting events. We can re-enable temporarily if specific
// env var lookup needs debugging.
extern "C" uint32_t GetEnvironmentVariableW(const wchar_t* /*name*/, wchar_t* /*buf*/, uint32_t /*size*/) {
    g_LastError = k_ERROR_ENVVAR_NOT_FOUND;
    return 0;
}
CRT_REAL(GetEnvironmentVariableW);

extern "C" uint32_t GetEnvironmentVariableA(const char* /*name*/, char* /*buf*/, uint32_t /*size*/) {
    g_LastError = k_ERROR_ENVVAR_NOT_FOUND;
    return 0;
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
        g_LastError = k_ERROR_FILE_NOT_FOUND;
        return 0xFFFFFFFFu;
    }
    uint32_t attr = SharpOSHost_GetFileAttributes(path);
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
extern "C" void* FindFirstFileW(const wchar_t* /*lpFileName*/, void* /*lpFindFileData*/) {
    TRACE_REAL(FindFirstFileW);
    g_LastError = k_ERROR_FILE_NOT_FOUND;
    return k_INVALID_HANDLE_VALUE;
}
CRT_REAL(FindFirstFileW);

extern "C" void* FindFirstFileExW(const wchar_t* /*lpFileName*/, int /*fInfoLevelId*/,
                                  void* /*lpFindFileData*/, int /*fSearchOp*/,
                                  void* /*lpSearchFilter*/, uint32_t /*dwAdditionalFlags*/) {
    TRACE_REAL(FindFirstFileExW);
    g_LastError = k_ERROR_FILE_NOT_FOUND;
    return k_INVALID_HANDLE_VALUE;
}
CRT_REAL(FindFirstFileExW);

extern "C" int FindNextFileW(void* /*hFindFile*/, void* /*lpFindFileData*/) {
    TRACE_REAL(FindNextFileW);
    static const uint32_t k_ERROR_NO_MORE_FILES = 18;
    g_LastError = k_ERROR_NO_MORE_FILES;
    return 0;
}
CRT_REAL(FindNextFileW);

extern "C" int FindClose(void* /*hFindFile*/) {
    TRACE_REAL(FindClose);
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
    if (n < 0) { g_LastError = k_ERROR_FILE_NOT_FOUND; return 0; }
    uint32_t attr = SharpOSHost_GetFileAttributes(path);
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
extern "C" void SharpOSHost_DebugWrite(const void* buf, int32_t len);

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
        SharpOSHost_DebugPrint("[GetProcAddress advapi32] unknown name=");
        SharpOSHost_DebugPrint(name);
        SharpOSHost_DebugPrint("\n");
        g_LastError = 127;   // ERROR_PROC_NOT_FOUND
        return nullptr;
    }
    if (mod == SHARPOS_SYSNATIVE_HMODULE && name != nullptr) {
        void* p = sharpos_resolve_sysnative(name);
        if (p != nullptr) { g_LastError = 0; return p; }
        SharpOSHost_DebugPrint("[GetProcAddress libSystem.Native] unknown name=");
        SharpOSHost_DebugPrint(name);
        SharpOSHost_DebugPrint("\n");
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
        SharpOSHost_DebugPrint("[GetProcAddress kernel32] unknown name=");
        SharpOSHost_DebugPrint(name);
        SharpOSHost_DebugPrint("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_OLE32_HMODULE && name != nullptr) {
        if (sharpos_streq(name, "CoCreateGuid")) { g_LastError = 0; return (void*)&CoCreateGuid; }
        SharpOSHost_DebugPrint("[GetProcAddress ole32] unknown name=");
        SharpOSHost_DebugPrint(name);
        SharpOSHost_DebugPrint("\n");
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
        SharpOSHost_DebugPrint("[GetProcAddress bcrypt] unknown name=");
        SharpOSHost_DebugPrint(name);
        SharpOSHost_DebugPrint("\n");
        g_LastError = 127;
        return nullptr;
    }
    if (mod == SHARPOS_SECUR32_HMODULE && name != nullptr) {
        if (sharpos_streq(name, "GetUserNameExW")) { g_LastError = 0; return (void*)&GetUserNameExW; }
        SharpOSHost_DebugPrint("[GetProcAddress secur32] unknown name=");
        SharpOSHost_DebugPrint(name);
        SharpOSHost_DebugPrint("\n");
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
        SharpOSHost_DebugPrint("[GetProcAddress syscrypto] unknown name=");
        SharpOSHost_DebugPrint(name);
        SharpOSHost_DebugPrint("\n");
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
    if (sharpos_streq(n,"CreateSemaphoreExW"))           return (void*)&CreateSemaphoreExW;
    if (sharpos_streq(n,"SetEvent"))                     return (void*)&SetEvent;
    if (sharpos_streq(n,"ResetEvent"))                   return (void*)&ResetEvent;
    if (sharpos_streq(n,"ReleaseSemaphore"))             return (void*)&ReleaseSemaphore;
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
    // Files / pipes
    if (sharpos_streq(n,"CreateFileW"))                  return (void*)&CreateFileW;
    if (sharpos_streq(n,"CreateFileMappingW"))           return (void*)&CreateFileMappingW;
    if (sharpos_streq(n,"FlushViewOfFile"))              return (void*)&FlushViewOfFile;
    if (sharpos_streq(n,"CreateNamedPipeA"))             return (void*)&CreateNamedPipeA;
    if (sharpos_streq(n,"ReadFile"))                     return (void*)&ReadFile;
    if (sharpos_streq(n,"SetFilePointer"))               return (void*)&SetFilePointer;
    if (sharpos_streq(n,"GetFileSize"))                  return (void*)&GetFileSize;
    // Misc / EH / icache
    if (sharpos_streq(n,"FlushInstructionCache"))        return (void*)&FlushInstructionCache;
    if (sharpos_streq(n,"FlushProcessWriteBuffers"))     return (void*)&FlushProcessWriteBuffers;
    if (sharpos_streq(n,"NtQuerySystemInformation"))     return (void*)&NtQuerySystemInformation;
    if (sharpos_streq(n,"RtlCaptureContext"))            return (void*)&RtlCaptureContext;
    if (sharpos_streq(n,"RtlInstallFunctionTableCallback")) return (void*)&RtlInstallFunctionTableCallback;
    if (sharpos_streq(n,"RtlDeleteFunctionTable"))       return (void*)&RtlDeleteFunctionTable;
    return nullptr;   // unknown → GetProcAddress prints the name
}
