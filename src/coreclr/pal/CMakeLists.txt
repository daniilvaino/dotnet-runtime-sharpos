project(COREPAL)

include(../clrfeatures.cmake)

include_directories(${COREPAL_SOURCE_DIR}/inc)
include_directories(${COREPAL_SOURCE_DIR}/src)
include_directories(${COREPAL_SOURCE_DIR}/../inc)

if (NOT CLR_CMAKE_TARGET_BROWSER)
    add_compile_options(-fexceptions)
else()
    add_compile_options(-fwasm-exceptions)
    add_link_options(-fwasm-exceptions -sEXIT_RUNTIME=1)
endif()

# SharpOS PAL: pal/sharpos/ replaces pal/src/ on TARGET_SHARPOS.
# Per Phase 2 Redesign + D9 — pal/sharpos/ is a parallel directory, additive
# only, no modifications to pal/src/. Tests are skipped on TARGET_SHARPOS too.
# SharpOS cross-host: в сборке кросс-инструментов наш PAL не собирается. Она
# идёт под хост (macOS, Linux), а pal/sharpos/ написан под цель и включает
# windows.h, которого на хосте нет. Хостовым инструментам PAL цели не нужен —
# им нужен только JIT.
if (CLR_CMAKE_TARGET_SHARPOS AND NOT CLR_CROSS_COMPONENTS_BUILD)
    add_subdirectory(sharpos)
elseif (NOT CLR_CMAKE_TARGET_SHARPOS)
    add_subdirectory(src)
    add_subdirectory(tests)
endif()
