# pal/sharpos/ — SharpOS PAL backend.
#
# Replaces pal/src/ on TARGET_SHARPOS (custom CoreCLR target, not Unix not
# Windows). Per Phase 2 Redesign + D9 — flat domain structure:
#   memory.cpp / thread.cpp / file.cpp / sync.cpp / time.cpp / exception/
#
# Step 3 (configure proof gate prep): minimum cmake to declare coreclrpal
# target + placeholder source. Real implementation comes in Step 5.
#
# Step 5 will add D11 firewall infrastructure (forced include
# sharpos_no_winapi.h + fake windows.h в forbidden_headers/ + #pragma GCC
# poison for WinAPI identifiers + object-level audit) per Round 7
# finalization.

project(coreclrpal_sharpos)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Mirror pal/src/ include structure for compatibility with vm/ expectations.
include_directories(BEFORE ${COREPAL_SOURCE_DIR}/src/include)

# Architecture detection. TARGET_SHARPOS currently x64 only.
if (CLR_CMAKE_TARGET_ARCH_AMD64)
    set(PAL_ARCH_SOURCES_DIR amd64)
else()
    message(FATAL_ERROR "pal/sharpos/ currently supports x64 only")
endif()

set(SHARPOS_PAL_SOURCES
    _placeholder.cpp
    # winapi_shim.cpp — stubs для функций которые vm/utilcode expect от
    # Linux PAL или missing Windows-side libs (см. work/PAL/CORECLR_PORT_WINAPI_DEBT.md).
    # На HOST_WINDOWS routed на native Win32; при kernel link заменить на
    # kernel-native impls.
    winapi_shim.cpp
)

add_library(coreclrpal STATIC ${SHARPOS_PAL_SOURCES})

# Stub targets pal/src/ defines but we don't (yet) implement. Empty
# placeholders so dependent targets can link/depend on them.
if(NOT TARGET coreclrpal_dac)
    add_library(coreclrpal_dac STATIC _placeholder.cpp)
endif()

if(NOT TARGET coreclrtraceptprovider)
    add_library(coreclrtraceptprovider STATIC _placeholder.cpp)
endif()

if(NOT TARGET tracepointprovider)
    add_library(tracepointprovider OBJECT _placeholder.cpp)
endif()

# eventprovider: создаётся в vm/eventing/CMakeLists.txt через
# pal/src/eventprovider/dummyprovider — auto-generated stubs для FireEtXplat*
# functions из ClrEtwAll.man. См. vm/eventing/CMakeLists.txt SharpOS block.
