# Кросс-тулчейн: сборка форка CoreCLR под SharpOS с unix-хоста (macOS / Linux).
#
# Зачем. Цель SharpOS — Windows ABI, а хост — не Windows. Без этого файла cmake
# берёт систему хоста (Darwin) и подмешивает яблочные флаги `-arch arm64` и
# `-isysroot .../MacOSX.sdk`: clang-cl их молча игнорирует, но при сшивании
# `arm64` утекает как имя входного файла и lld-link падает с
# `could not open 'arm64'`. CMAKE_SYSTEM_NAME=Windows это отключает и включает
# MSVC-подобные правила сборки.
#
# Инструменты. Всё из LLVM, MSVC на хосте не нужен:
#   clang-cl  — компилятор (на macOS он уже по умолчанию целится в windows-msvc)
#   lld-link  — компоновщик вместо link.exe
#   llvm-lib  — вместо lib.exe
#   llvm-rc   — вместо rc.exe
#   llvm-ml   — вместо ml64.exe (см. ветку TARGET_SHARPOS в configurecompiler.cmake)
#
# Заголовки и библиотеки MSVC берутся из sysroot'а, который делает xwin:
#   xwin --accept-license --cache-dir <dir> --arch x86_64 \
#        --sdk-version 10.0.22621 splat --preserve-ms-arch-notation
# Путь передаётся через -DSHARPOS_XWIN_SPLAT=<dir>/splat. Файлы остаются
# микрософтовскими: xwin их только скачивает, лицензию не меняет.
#
# Вызов:
#   ./build.sh -subset clr -os windows -arch x64 -configuration Debug \
#     -cmakeargs "-DCLR_CMAKE_TARGET_SHARPOS=1 \
#                 -DCMAKE_TOOLCHAIN_FILE=<repo>/eng/native/sharpos-crosshost.cmake \
#                 -DSHARPOS_XWIN_SPLAT=<splat>"
# Плюс CLR_CROSS_COMPILER_DEFAULT=1 в окружении, иначе build-runtime.sh
# перебьёт компилятор через init-compiler.sh.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)
set(CMAKE_CROSSCOMPILING TRUE)

# cmake переисполняет тулчейн внутри пробных подпроектов (try_compile), а туда
# -D с командной строки не доходит. Поэтому значение берётся ещё и из окружения
# и явно пробрасывается в пробы.
if(NOT SHARPOS_XWIN_SPLAT AND DEFINED ENV{SHARPOS_XWIN_SPLAT})
  set(SHARPOS_XWIN_SPLAT "$ENV{SHARPOS_XWIN_SPLAT}")
endif()
if(NOT SHARPOS_XWIN_SPLAT)
  message(FATAL_ERROR "Задайте -DSHARPOS_XWIN_SPLAT=<путь к splat от xwin> или одноимённую переменную окружения (в нём должны лежать crt/ и sdk/)")
endif()
set(SHARPOS_XWIN_SPLAT "${SHARPOS_XWIN_SPLAT}" CACHE PATH "sysroot MSVC + Windows SDK от xwin" FORCE)
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES SHARPOS_XWIN_SPLAT)
foreach(_probe crt/include sdk/include/um crt/lib/x64 sdk/lib/ucrt/x64)
  if(NOT EXISTS "${SHARPOS_XWIN_SPLAT}/${_probe}")
    message(FATAL_ERROR "В sysroot не хватает ${_probe}: ${SHARPOS_XWIN_SPLAT}")
  endif()
endforeach()

find_program(SHARPOS_CLANG_CL NAMES clang-cl
             HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin /usr/lib/llvm/bin)
find_program(SHARPOS_LLD_LINK NAMES lld-link
             HINTS /opt/homebrew/opt/lld/bin /opt/homebrew/opt/llvm/bin /usr/local/opt/lld/bin /usr/lib/llvm/bin)
find_program(SHARPOS_LLVM_LIB NAMES llvm-lib
             HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin /usr/lib/llvm/bin)
find_program(SHARPOS_LLVM_RC  NAMES llvm-rc
             HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin /usr/lib/llvm/bin)
find_program(SHARPOS_LLVM_ML  NAMES llvm-ml
             HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin /usr/lib/llvm/bin)
foreach(_tool SHARPOS_CLANG_CL SHARPOS_LLD_LINK SHARPOS_LLVM_LIB SHARPOS_LLVM_RC SHARPOS_LLVM_ML)
  if(${_tool} MATCHES "NOTFOUND")
    message(FATAL_ERROR "${_tool} не найден. macOS: brew install llvm lld. Linux: пакеты llvm и lld.")
  endif()
endforeach()

set(CMAKE_C_COMPILER        "${SHARPOS_CLANG_CL}")
set(CMAKE_CXX_COMPILER      "${SHARPOS_CLANG_CL}")
set(CMAKE_LINKER            "${SHARPOS_LLD_LINK}")
set(CMAKE_AR                "${SHARPOS_LLVM_LIB}")
set(CMAKE_RC_COMPILER       "${SHARPOS_LLVM_RC}")
set(CMAKE_ASM_MASM_COMPILER "${SHARPOS_LLVM_ML}")

# Триплет и sysroot. Флаги идут в CMAKE_*_FLAGS_INIT, чтобы попасть и в пробы
# компилятора, которые cmake гоняет до чтения остальных настроек.
# Целевой триплет задаётся через COMPILER_TARGET, а не флагом: cmake тогда сам
# добавит --target И выведет из него архитектуру. Если писать --target руками в
# флагах, объекты выходят x64, а компоновщику всё равно идёт /machine:ARM64 —
# cmake берёт архитектуру из умолчания clang-cl, а оно на arm64-маке arm64.
set(CMAKE_C_COMPILER_TARGET   x86_64-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET x86_64-pc-windows-msvc)

set(_sharpos_flags "/vctoolsdir ${SHARPOS_XWIN_SPLAT}/crt /winsdkdir ${SHARPOS_XWIN_SPLAT}/sdk -fuse-ld=lld")
# Самодельные команды cmake (preprocess_file и подобные) зовут компилятор
# напрямую и CMAKE_*_FLAGS не получают — им нужен sysroot отдельным списком.
set(SHARPOS_SYSROOT_COMPILE_FLAGS
    "/vctoolsdir;${SHARPOS_XWIN_SPLAT}/crt;/winsdkdir;${SHARPOS_XWIN_SPLAT}/sdk"
    CACHE STRING "Флаги sysroot для самодельных вызовов компилятора" FORCE)

# Компилятор ресурсов (llvm-rc) свои пути включения не наследует ни от
# /winsdkdir, ни от CMAKE_C_FLAGS — ему нужен явный -I, иначе .rc не находит
# даже verrsrc.h.
# llvm-ml по умолчанию собирает 32-битный код, в отличие от ml64. Без -m64
# ассемблер ругается "register %r12 is only available in 64-bit mode" и
# ".seh_* directives are not supported on this target".
set(CMAKE_ASM_MASM_FLAGS_INIT "-m64")

set(CMAKE_RC_FLAGS_INIT "-I ${SHARPOS_XWIN_SPLAT}/sdk/include/um -I ${SHARPOS_XWIN_SPLAT}/sdk/include/shared -I ${SHARPOS_XWIN_SPLAT}/sdk/include/ucrt -I ${SHARPOS_XWIN_SPLAT}/crt/include")

set(CMAKE_C_FLAGS_INIT   "${_sharpos_flags}")
set(CMAKE_CXX_FLAGS_INIT "${_sharpos_flags}")

# Пути к библиотекам приходится задавать отдельно: сшивание cmake ведёт через
# lld-link НАПРЯМУЮ (vs_link_exe), а не через драйвер clang-cl, поэтому
# /winsdkdir и /vctoolsdir до компоновщика не доходят и он не находит даже
# kernel32.lib.
set(_sharpos_libpaths "/LIBPATH:${SHARPOS_XWIN_SPLAT}/crt/lib/x64 /LIBPATH:${SHARPOS_XWIN_SPLAT}/sdk/lib/um/x64 /LIBPATH:${SHARPOS_XWIN_SPLAT}/sdk/lib/ucrt/x64")
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_sharpos_libpaths}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_sharpos_libpaths}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_sharpos_libpaths}")

# Поиск целевых артефактов — только в sysroot, хостовые /usr/lib и /usr/include
# для виндовой цели непригодны.
set(CMAKE_FIND_ROOT_PATH "${SHARPOS_XWIN_SPLAT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
