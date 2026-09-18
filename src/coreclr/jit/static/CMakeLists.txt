project(ClrJit)

set_source_files_properties(${JIT_EXPORTS_FILE} PROPERTIES GENERATED TRUE)

add_library_clr(clrjit_static
    OBJECT
    ${JIT_SOURCES}
    ${JIT_ARCH_SOURCES}
)

# SharpOS cross-host: см. utilcode/CMakeLists.txt — PAL цели под хост не строится.
if(CLR_CMAKE_HOST_UNIX AND NOT CLR_CROSS_COMPONENTS_BUILD)
    add_dependencies(clrjit_static coreclrpal gcinfo)
elseif(CLR_CROSS_COMPONENTS_BUILD)
    add_dependencies(clrjit_static gcinfo)
endif()

target_include_directories(clrjit_static PRIVATE ${JIT_SOURCE_DIR})
target_precompile_headers(clrjit_static PRIVATE [["jitpch.h"]])
