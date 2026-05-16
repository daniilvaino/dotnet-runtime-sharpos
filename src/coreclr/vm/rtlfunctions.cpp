// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//
// RtlFunctions.CPP
//

//
// Various functions for interacting with ntdll.
//
//

// Precompiled Header

#include "common.h"

#include "rtlfunctions.h"

#if defined(TARGET_SHARPOS)
extern "C" void SharpOSHost_DebugPrint(const char*);
extern "C" void SharpOSHost_DebugPrintHex(uint64_t);
// __imp_RtlVirtualUnwind is the resolvable data pointer emitted by
// CRT_STUB(RtlVirtualUnwind) in crt_imp_stubs.cpp; at the final kernel
// image link (/FORCE:MULTIPLE, OS.obj first) it points to the C#
// [RuntimeExport] RtlVirtualUnwind (SehUnwind.cs). Links standalone for
// coreclr.dll, no winnt.h prototype collision (it's the data alias).
extern "C" void* __imp_RtlVirtualUnwind;
#endif


#ifdef HOST_AMD64

#if defined(TARGET_SHARPOS)
// Bare metal: the EnsureRtlFunctions() call site in EEStartupHelper
// (ceemain.cpp:761, #ifndef TARGET_UNIX) is NOT on the SharpOS
// coreclr_initialize path — verified empirically: with Verbose on, the
// [InstallEEFunctionTable] marker (same TU) fires but [EnsureRtlFunctions]
// never does. So the runtime rebind in EnsureRtlFunctions() below never
// executes; RtlVirtualUnwind_Unsafe would stay NULL and the first managed
// `throw` does `call 0` → #PF RIP=0 (instr-fetch). Bind it STATICALLY:
// &SharpOS_RtlVirtualUnwind_Thunk is a link-time constant, so the pointer
// is correct in .data from image load — no dependency on EEStartup
// ordering, ntdll, GetProcAddress, or C++ dynamic initializers. The thunk
// forwards through __imp_RtlVirtualUnwind (itself a static .data alias to
// the in-image C# [RuntimeExport] RtlVirtualUnwind, SehUnwind.cs — proven
// working by the kernel EH battery L1..L17), dereferenced at call time
// when an unwind actually happens (image fully loaded by then).
static PEXCEPTION_ROUTINE SharpOS_RtlVirtualUnwind_Thunk(
    ULONG HandlerType, ULONG64 ImageBase, ULONG64 ControlPc,
    PT_RUNTIME_FUNCTION FunctionEntry, PCONTEXT ContextRecord,
    PVOID* HandlerData, PULONG64 EstablisherFrame,
    PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)
{
    return ((RtlVirtualUnwindFn*)__imp_RtlVirtualUnwind)(
        HandlerType, ImageBase, ControlPc, FunctionEntry, ContextRecord,
        HandlerData, EstablisherFrame, ContextPointers);
}
RtlVirtualUnwindFn*                 RtlVirtualUnwind_Unsafe         = (RtlVirtualUnwindFn*)&SharpOS_RtlVirtualUnwind_Thunk;
#else
RtlVirtualUnwindFn*                 RtlVirtualUnwind_Unsafe         = NULL;
#endif

HRESULT EnsureRtlFunctions()
{
    CONTRACTL
    {
        NOTHROW;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

#if defined(TARGET_SHARPOS)
    // Redundant belt-and-suspenders: RtlVirtualUnwind_Unsafe is already
    // bound STATICALLY at file scope (SharpOS_RtlVirtualUnwind_Thunk, see
    // above) because this function is not reached on the SharpOS
    // coreclr_initialize path. We keep the rebind + probe print here so
    // that IF the startup path ever changes to include EEStartupHelper's
    // EnsureRtlFunctions() call, the marker confirms it and the value is
    // re-asserted (idempotent — same in-image C# RtlVirtualUnwind).
    RtlVirtualUnwind_Unsafe = (RtlVirtualUnwindFn*)__imp_RtlVirtualUnwind;
    SharpOSHost_DebugPrint("[EnsureRtlFunctions] RtlVirtualUnwind_Unsafe bound via __imp_ (SHARPOS)\n");
    return S_OK;
#endif

    HMODULE hModuleNtDll = CLRLoadLibrary(W("ntdll"));

    if (hModuleNtDll == NULL)
        return E_FAIL;

#define ENSURE_FUNCTION_RENAME(clrname, ntname)   \
    if (NULL == clrname) { clrname = (ntname##Fn*)GetProcAddress(hModuleNtDll, #ntname); } \
    if (NULL == clrname) { return E_FAIL; } \
    { }

    ENSURE_FUNCTION_RENAME(RtlVirtualUnwind_Unsafe, RtlVirtualUnwind       );

    return S_OK;
}

#else // HOST_AMD64

HRESULT EnsureRtlFunctions()
{
    LIMITED_METHOD_CONTRACT;
    return S_OK;
}

#endif // HOST_AMD64

#ifndef HOST_X86

#define DYNAMIC_FUNCTION_TABLE_MAX_RANGE INT32_MAX

VOID InstallEEFunctionTable (
        PVOID pvTableID,
        PVOID pvStartRange,
        ULONG cbRange,
        PGET_RUNTIME_FUNCTION_CALLBACK pfnGetRuntimeFunctionCallback,
        PVOID pvContext)
{
    CONTRACTL
    {
        THROWS;
        GC_NOTRIGGER;
        MODE_ANY;
        PRECONDITION(cbRange <= DYNAMIC_FUNCTION_TABLE_MAX_RANGE);
    }
    CONTRACTL_END;

#if defined(TARGET_SHARPOS)
    // Unambiguous marker: proves this function is actually reached (i.e.
    // a JIT code heap is being registered) regardless of which slice of
    // the serial log is captured. Low-frequency (once per code heap).
    SharpOSHost_DebugPrint("[InstallEEFunctionTable] start=0x");
    SharpOSHost_DebugPrintHex((uint64_t)pvStartRange);
    SharpOSHost_DebugPrint(" len=0x");
    SharpOSHost_DebugPrintHex((uint64_t)cbRange);
    SharpOSHost_DebugPrint("\n");

    // Bare metal: there is no CLR module file path, so GetClrModuleDirectory
    // throws — and that throw (inside this function) means the JIT code-heap
    // function table is NEVER registered, so managed exceptions can't unwind
    // through JIT frames. wszModuleName is only the out-of-process debugger
    // callback DLL (irrelevant in-process), so register directly with NULL.
    if (!RtlInstallFunctionTableCallback(
            ((ULONG_PTR)pvTableID) | 3,
            (ULONG_PTR)pvStartRange,
            cbRange,
            pfnGetRuntimeFunctionCallback,
            pvContext,
            NULL))
    {
        COMPlusThrowOM();
    }
    return;
#endif

    static LPWSTR wszModuleName = NULL;

    if (wszModuleName == NULL)
    {
        StackSString ssTempName;

        IfFailThrow(GetClrModuleDirectory(ssTempName));

        ssTempName.Append(MAIN_DAC_MODULE_DLL_NAME_W);

        NewArrayHolder<WCHAR> wzTempName(ssTempName.GetCopyOfUnicodeString());

        // publish result
        if (InterlockedCompareExchangeT(&wszModuleName, (LPWSTR)wzTempName, nullptr) == nullptr)
        {
            wzTempName.SuppressRelease();
        }
    }

    if (!RtlInstallFunctionTableCallback(
            ((ULONG_PTR)pvTableID) | 3,  // the low 2 bits must be set so NT knows
                                         // it's not really a pointer.  See
                                         // DeleteEEFunctionTable.
            (ULONG_PTR)pvStartRange,
            cbRange,
            pfnGetRuntimeFunctionCallback,
            pvContext,
            wszModuleName))
    {
        COMPlusThrowOM();
    }
}

#endif // HOST_X86
