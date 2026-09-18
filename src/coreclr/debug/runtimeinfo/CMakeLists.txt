set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(RUNTIMEINFO_SOURCES
    runtimeinfo.cpp
)

add_library_clr(runtimeinfo STATIC ${RUNTIMEINFO_SOURCES})

function(generate_module_index Target ModuleIndexFile)
    # Win32 may be false when cross compiling
    if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        set(scriptExt ".cmd")
    else()
        set(scriptExt ".sh")
    endif()

    add_custom_command(
        OUTPUT ${ModuleIndexFile}
        COMMAND ${CLR_ENG_NATIVE_DIR}/genmoduleindex${scriptExt} $<TARGET_FILE:${Target}> ${ModuleIndexFile} ${CMAKE_READELF}
        DEPENDS ${Target}
        COMMENT "Generating ${Target} module index file -> ${ModuleIndexFile}"
    )

    set_source_files_properties(
        ${ModuleIndexFile}
        PROPERTIES GENERATED TRUE
    )

    add_dependencies(runtimeinfo ${Target})
    target_sources(runtimeinfo PRIVATE ${ModuleIndexFile})
endfunction(generate_module_index)

if(NOT DEFINED CLR_CROSS_COMPONENTS_BUILD)
    generate_module_index(coreclr ${CMAKE_CURRENT_BINARY_DIR}/runtimemoduleindex.h)
    # SharpOS cross-host: при сборке с unix-хоста отладочные компоненты не
    # собираются (см. dlls/CMakeLists.txt), и ссылаться на них нельзя — cmake
    # падает с "No target mscordbi". Но runtimeinfo.cpp включает эти заголовки
    # прямо внутрь инициализатора структуры, поэтому просто пропустить их
    # нельзя: кладём пустые указатели. Формат — байт длины, затем сам
    # идентификатор (см. eng/native/genmoduleindex.sh), так что 0x00 означает
    # "указателя нет". Отладчик к ядру SharpOS не цепляется, читать их некому.
    if(CMAKE_HOST_WIN32 OR NOT CLR_CMAKE_TARGET_SHARPOS)
        generate_module_index(mscordaccore ${CMAKE_CURRENT_BINARY_DIR}/dacmoduleindex.h)
        generate_module_index(mscordbi ${CMAKE_CURRENT_BINARY_DIR}/dbimoduleindex.h)
    else()
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dacmoduleindex.h "0x00,\n")
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dbimoduleindex.h "0x00,\n")
    endif()
endif()

# publish runtimeinfo lib
install_clr(TARGETS runtimeinfo DESTINATIONS lib COMPONENT runtime)
