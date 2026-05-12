add_subdirectory(SOS)

# SharpOS port: superpmi — JIT testing host tool, uses PAL_SHLIB_SUFFIX / Linux
# CreateProcess wrappers. Не нужен для kernel image. См. work/PAL/CORECLR_PORT_WINAPI_DEBT.md.
if (NOT CLR_CMAKE_TARGET_BROWSER AND NOT CLR_CMAKE_TARGET_SHARPOS)
  add_subdirectory(superpmi)
endif()
