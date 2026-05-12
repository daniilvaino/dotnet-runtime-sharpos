# gc/sharpos/ — SharpOS GC environment overlay (third CoreCLR platform).
#
# Parallel к gc/windows/ (Win32-direct) и gc/unix/ (POSIX-direct), но
# routes через SharpOSHost_* C-ABI (per work/PAL/Platform_Bundle FINALIZED).
#
# Phase 6.1.1 minimum: skeleton с placeholder source. GCToOSInterface
# implementations будут наполняться by demand:
#   - Memory operations → SharpOSHost_AllocPages etc. (per D9 forward/)
#   - Threading → ABORT_FATAL stub (per D5, deferred к Phase 6.2)
#   - Time → SharpOSHost_GetTickCount etc.
#   - Events/semaphores → minimal stubs (ZeroGC config → unreachable)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories("../env")
include_directories("..")

# SharpOS port: link против vanilla gc/windows/gcenv.windows.cpp напрямую —
# implements full GCToOSInterface + GCEvent через Win32 API. HOST_WINDOWS
# доступен, all references resolve.
set(GC_PAL_SOURCES
    ../windows/gcenv.windows.cpp
)

add_library(gc_pal STATIC ${GC_PAL_SOURCES})

# gcenv.windows.cpp expects psapi.h linker symbol (GetPerformanceInfo etc.).
target_link_libraries(gc_pal PUBLIC psapi.lib)
