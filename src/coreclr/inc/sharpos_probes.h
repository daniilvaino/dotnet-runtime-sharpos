// SharpOS fork — kernel-managed diagnostic probes.
//
// Every TU in the CoreCLR fork that traces through SharpOSHost_DebugPrint*
// includes this instead of declaring local externs. When SHARPOS_QUIET_PROBES
// is defined at build time, the two probe symbols collapse to no-ops at
// preprocessor expansion — the C++→C ABI→managed transition disappears for
// all 700+ chatty callsites. With it undefined we get the same symbols as
// before, resolved by the kernel's [RuntimeExport]'ed receiver.
//
// Why preprocessor not runtime gate: the receiver is a managed function;
// even when its body short-circuits on a Verbose flag, the call itself
// pays a native→managed transition. With QUIET defined, the entire call
// chain is dead-code-eliminated by the C++ compiler before linking.

#pragma once
#include <stdint.h>

// Bare-metal SharpOS builds default to quiet probes — the 700+ chatty
// callsites collapse to ((void)0). Opt back into verbose by defining
// SHARPOS_VERBOSE_PROBES at build time (one TU or fork-wide).
#if defined(TARGET_SHARPOS) && !defined(SHARPOS_VERBOSE_PROBES)
  #define SHARPOS_QUIET_PROBES 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SHARPOS_QUIET_PROBES
  #define SharpOSHost_DebugPrint(s)    ((void)0)
  #define SharpOSHost_DebugPrintHex(v) ((void)0)
#else
  void SharpOSHost_DebugPrint(const char*);
  void SharpOSHost_DebugPrintHex(uint64_t);
#endif

#ifdef __cplusplus
}
#endif
