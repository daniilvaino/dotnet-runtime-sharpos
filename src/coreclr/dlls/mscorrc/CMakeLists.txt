include_directories("../../pal/prebuilt/corerror")

add_definitions(-DFX_VER_INTERNALNAME_STR=mscorrc.dll)

# SharpOS: compile-in mscorrc as a native string table (OBJECT lib),
# same as the Unix path. We are HOST_WIN32 but TARGET_SHARPOS — there is
# no separate mscorrc.dll runtime, the table is statically linked into
# the kernel image. See coreclr/CMakeLists.txt "Native string resource
# pipeline".
if(CLR_CMAKE_HOST_WIN32 AND NOT CLR_CMAKE_TARGET_SHARPOS)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /NOENTRY")

    # remove /guard:cf, /guard:ehcont, and /CETCOMPAT from resource-only libraries
    set_property(DIRECTORY PROPERTY CLR_CONTROL_FLOW_GUARD OFF)

    if (CLR_CMAKE_HOST_ARCH_AMD64)
        set_property(DIRECTORY PROPERTY CLR_EH_CONTINUATION OFF)
        string(REPLACE "/CETCOMPAT" "" CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS})
    endif (CLR_CMAKE_HOST_ARCH_AMD64)

    add_library_clr(mscorrc SHARED
        include.rc
    )
    install_clr(TARGETS mscorrc DESTINATIONS . sharedFramework COMPONENT runtime)

else()
    build_resources(${CMAKE_CURRENT_SOURCE_DIR}/include.rc mscorrc TARGET_CPP_FILE)
    if(CLR_CMAKE_TARGET_SHARPOS)
        # SharpOS port: STATIC (not OBJECT) so PUBLIC target_link_libraries
        # propagates the table symbol transitively through utilcode to all
        # downstream consumers (mscordbi / mscordac / coreshim / ilasm /
        # ildasm / jit) — OBJECT libs do not propagate this way in CMake.
        add_library_clr(mscorrc STATIC ${TARGET_CPP_FILE})
    else()
        add_library_clr(mscorrc OBJECT ${TARGET_CPP_FILE})
    endif()

endif()
