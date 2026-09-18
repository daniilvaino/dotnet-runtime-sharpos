if(CLR_CMAKE_TARGET_WIN32 AND FEATURE_EVENT_TRACE)
    add_subdirectory(clretwrc)
endif(CLR_CMAKE_TARGET_WIN32 AND FEATURE_EVENT_TRACE)
if (NOT (CLR_CMAKE_TARGET_WIN32 AND FEATURE_CROSSBITNESS))
    # SharpOS toolchain: отладочные компоненты (DAC и интерфейс отладчика)
    # пропускаются на любом хосте. Генерация mscordaccore.exp опирается на то,
    # что lib.exe из .def делает и .lib, и объект экспорта; llvm-lib делает
    # только .lib, и цель обрывается — а вместе с ней и весь поднабор clr, из-за
    # чего до crossgen'а corelib и упаковки дело не доходит.
    # Ядру SharpOS эти компоненты не нужны: оно линкует coreclr_static.lib,
    # отладчик к нему не цепляется.
    if (NOT CLR_CMAKE_TARGET_ARCH_WASM AND NOT CLR_CMAKE_SHARPOS_TOOLCHAIN)
        add_subdirectory(mscordbi)
        add_subdirectory(mscordac)
    endif()
    add_subdirectory(mscoree)
endif()
if (NOT CLR_CMAKE_TARGET_ARCH_WASM)
    add_subdirectory(mscorpe)
endif()
add_subdirectory(mscorrc)
