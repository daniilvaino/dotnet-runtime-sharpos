include(CheckCSourceCompiles)
include(CheckIncludeFiles)
include(CheckFunctionExists)

if(CLR_CMAKE_HOST_WIN32)
    # Our posix abstraction layer will provide these headers
    set(HAVE_ELF_H 1)
    set(HAVE_ENDIAN_H 1)

    # MSVC compiler is currently missing C11 stdalign.h header
    # Fake it until support is added
    check_include_files(stdalign.h HAVE_STDALIGN_H)
    if (NOT HAVE_STDALIGN_H)
        configure_file(${CLR_SRC_NATIVE_DIR}/external/libunwind/include/remote/win/fakestdalign.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/stdalign.h COPYONLY)
    endif (NOT HAVE_STDALIGN_H)

    # MSVC compiler is currently missing C11 stdatomic.h header
    check_c_source_compiles("#include <stdatomic.h> void main() { _Atomic int a; }" HAVE_STDATOMIC_H)
    if (NOT HAVE_STDATOMIC_H)
        configure_file(${CLR_SRC_NATIVE_DIR}/external/libunwind/include/remote/win/fakestdatomic.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/stdatomic.h COPYONLY)
    endif (NOT HAVE_STDATOMIC_H)

    # MSVC compiler is currently missing C11 _Thread_local
    check_c_source_compiles("void main() { _Thread_local int a; }"  HAVE_THREAD_LOCAL)
    if (NOT HAVE_THREAD_LOCAL)
        add_definitions(-D_Thread_local=)
    endif (NOT HAVE_THREAD_LOCAL)
else(CLR_CMAKE_HOST_WIN32)
    check_include_files(elf.h HAVE_ELF_H)
    check_include_files(sys/elf.h HAVE_SYS_ELF_H)

    check_include_files(endian.h HAVE_ENDIAN_H)
    check_include_files(sys/endian.h HAVE_SYS_ENDIAN_H)
endif(CLR_CMAKE_HOST_WIN32)

check_include_files(link.h HAVE_LINK_H)
check_include_files(sys/link.h HAVE_SYS_LINK_H)

check_function_exists(pipe2 HAVE_PIPE2)

# macOS 26: check_function_exists отвечает "да", хотя функции в системе нет.
# Apple перечислила _pipe2 в tbd-заглушке libSystem из SDK, поэтому линковщик
# пробу принимает, но dyld её не экспортирует: dlsym(RTLD_DEFAULT, "pipe2")
# возвращает 0, и unistd.h её не объявляет. Вызов уходит через заглушку импорта
# на нулевой адрес — PAL падает по SIGSEGV прямо в CreateProcessPipe при
# инициализации, то есть любой загрузивший его инструмент (у нас crossgen2)
# умирает молча, ещё до первой строчки полезной работы.
# На Apple pipe2 нет ни в одной версии, так что признак просто гасим — в PAL
# рядом лежит равноценный путь pipe() + fcntl(FD_CLOEXEC).
# (В src/native/libs/configure.cmake ту же функцию проверяют через
#  check_symbol_exists по unistd.h — эта проверка на macOS отвечает верно.)
if(APPLE AND HAVE_PIPE2)
  set(HAVE_PIPE2 0 CACHE INTERNAL "pipe2 в macOS отсутствует, несмотря на заглушку в SDK" FORCE)
endif()

check_c_source_compiles("
int main(int argc, char **argv)
{
    __builtin_unreachable();

    return 0;
}" HAVE__BUILTIN_UNREACHABLE)

configure_file(${CMAKE_CURRENT_LIST_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/config.h)
add_definitions(-DHAVE_CONFIG_H=1)

configure_file(${CLR_SRC_NATIVE_DIR}/external/libunwind/include/libunwind-common.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/libunwind-common.h)
configure_file(${CLR_SRC_NATIVE_DIR}/external/libunwind/include/libunwind.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/libunwind.h)
configure_file(${CLR_SRC_NATIVE_DIR}/external/libunwind/include/tdep/libunwind_i.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/tdep/libunwind_i.h)
