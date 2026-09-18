set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(UTILCODE_COMMON_SOURCES
  clrhost_nodependencies.cpp
  ccomprc.cpp
  ex.cpp
  sbuffer.cpp
  sstring_com.cpp
  fstring.cpp
  namespaceutil.cpp
  makepath.cpp
  splitpath.cpp
  clrconfig.cpp
  configuration.cpp
  collections.cpp
  posterror.cpp
  fstream.cpp
  clrhelpers.cpp
  stgpool.cpp
  stgpooli.cpp
  stgpoolreadonly.cpp
  utsem.cpp
  check.cpp
  log.cpp
  arraylist.cpp
  comex.cpp
  guidfromname.cpp
  memorypool.cpp
  loaderheap.cpp
  interleavedloaderheap.cpp
  loaderheap_shared.cpp
  explicitcontrolloaderheap.cpp
  rangelist.cpp
  outstring.cpp
  ilformatter.cpp
  opinfo.cpp
  corimage.cpp
  format1.cpp
  prettyprintsig.cpp
  sha1.cpp
  sigbuilder.cpp
  sigparser.cpp
  sstring.cpp
  util_nodependencies.cpp
  safewrap.cpp
  clrhost.cpp
  cycletimer.cpp
  md5.cpp
  util.cpp
  stresslog.cpp
  debug.cpp
  pedecoder.cpp
  winfix.cpp
  longfilepathwrappers.cpp
  yieldprocessornormalized.cpp
)

# These source file do not yet compile on Linux.
# They should be moved out from here into the declaration
# of UTILCODE_SOURCES above after fixing compiler errors.
if(CLR_CMAKE_TARGET_WIN32)
  list(APPEND UTILCODE_COMMON_SOURCES
    dacutil.cpp
    dlwrap.cpp
    stacktrace.cpp
  )
endif(CLR_CMAKE_TARGET_WIN32)

set(UTILCODE_SOURCES
  ${UTILCODE_COMMON_SOURCES}
  allocmemtracker.cpp
  executableallocator.cpp
)

set(UTILCODE_DAC_SOURCES
  ${UTILCODE_COMMON_SOURCES}
  hostimpl.cpp
)


set(UTILCODE_STATICNOHOST_SOURCES
  ${UTILCODE_COMMON_SOURCES}
  hostimpl.cpp
)

set (UTILCODE_DEPENDENCIES eventing_headers)

convert_to_absolute_path(UTILCODE_SOURCES ${UTILCODE_SOURCES})
convert_to_absolute_path(UTILCODE_DAC_SOURCES ${UTILCODE_DAC_SOURCES})
convert_to_absolute_path(UTILCODE_STATICNOHOST_SOURCES ${UTILCODE_STATICNOHOST_SOURCES})

if(NOT CLR_CMAKE_TARGET_ARCH_WASM)
add_library_clr(utilcode_dac STATIC ${UTILCODE_DAC_SOURCES})
endif()
add_library_clr(utilcode OBJECT ${UTILCODE_SOURCES})
add_library_clr(utilcodestaticnohost STATIC ${UTILCODE_STATICNOHOST_SOURCES})

target_link_libraries(utilcodestaticnohost PUBLIC coreclrminipal)

if(CLR_CMAKE_HOST_UNIX OR CLR_CMAKE_TARGET_SHARPOS)
  # SharpOS port: also link the compiled-in native string table so
  # CCompRC::LoadString resolves resource IDs via in-process bsearch
  # (no mscorrc.dll runtime lookup). See coreclr/CMakeLists.txt.
  target_link_libraries(utilcodestaticnohost PUBLIC nativeresourcestring)
  if (NOT CLR_CMAKE_TARGET_ARCH_WASM)
    target_link_libraries(utilcode_dac PUBLIC nativeresourcestring)
    if(CLR_CMAKE_HOST_UNIX)
      add_dependencies(utilcode_dac coreclrpal)
    endif()
  endif()
  target_link_libraries(utilcode INTERFACE nativeresourcestring)
  if(CLR_CMAKE_HOST_UNIX)
    add_dependencies(utilcode coreclrpal)
  endif()
endif()

if(CLR_CMAKE_TARGET_SHARPOS)
  # SharpOS port: ccomprc.cpp now references nativeStringResourceTable_mscorrc
  # (Unix-style path). Make mscorrc OBJECT lib a PUBLIC dep so every consumer
  # of utilcodestaticnohost / utilcode_dac (coreclr, mscordbi, mscordac,
  # coreshim, ilasm, ildasm, jit) automatically pulls the symbol — no per-
  # consumer link edit. See docs/eh-model.md "GetThrowableMessage".
  target_link_libraries(utilcodestaticnohost PUBLIC mscorrc)
  if (NOT CLR_CMAKE_TARGET_ARCH_WASM)
    target_link_libraries(utilcode_dac PUBLIC mscorrc)
  endif()
  target_link_libraries(utilcode INTERFACE mscorrc)
endif()


if(CLR_CMAKE_HOST_WIN32)
    target_compile_definitions(utilcodestaticnohost PRIVATE _CRTIMP=) # use static version of crt

    link_natvis_sources_for_target(utilcodestaticnohost INTERFACE utilcode.natvis)
    link_natvis_sources_for_target(utilcode_dac INTERFACE utilcode.natvis)
    link_natvis_sources_for_target(utilcode INTERFACE utilcode.natvis)
endif(CLR_CMAKE_HOST_WIN32)

if (NOT CLR_CMAKE_TARGET_ARCH_WASM)
  set_target_properties(utilcode_dac PROPERTIES DAC_COMPONENT TRUE)
  target_compile_definitions(utilcode_dac PRIVATE SELF_NO_HOST)
  add_dependencies(utilcode_dac ${UTILCODE_DEPENDENCIES})
  target_precompile_headers(utilcode_dac PRIVATE [["stdafx.h"]])
  endif()
target_compile_definitions(utilcodestaticnohost PRIVATE SELF_NO_HOST)
add_dependencies(utilcode ${UTILCODE_DEPENDENCIES})
add_dependencies(utilcodestaticnohost ${UTILCODE_DEPENDENCIES})
target_precompile_headers(utilcode PRIVATE [["stdafx.h"]])
target_precompile_headers(utilcodestaticnohost PRIVATE [["stdafx.h"]])
