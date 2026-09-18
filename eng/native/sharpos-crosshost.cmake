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

# Версия LLVM имеет значение, и подходит узкий диапазон. Две независимые
# диагностики clang режут CoreCLR с разных концов:
#
#   __try в функции с объектом, требующим раскрутки   19 ✅  21 ✅  22 ✅  23 ❌
#   no_builtin на defaulted-функции                   19 ❌            22 ✅
#
# Первое: при HOST_WINDOWS подключается inc/palclr.h, где PAL_TRY раскрывается
# в настоящий __try, а рядом живут кадры вроде DebuggerU2MCatchHandlerFrame
# (vm/threads.cpp). Второе приходит из заголовков MSVC. Оба места не наши.
#
# Берём 22: именно этой версией форк собирается на Windows (clang-cl 22.1.1),
# то есть диапазон совместимости выверен там на практике. Гнаться за свежим
# LLVM смысла нет — brew ставит самый новый, и он как раз не подходит.
# Переопределяется через -DSHARPOS_LLVM_BIN=<путь>.
set(_sharpos_llvm_hints
    ${SHARPOS_LLVM_BIN}
    /opt/homebrew/opt/llvm@22/bin /usr/local/opt/llvm@22/bin /usr/lib/llvm-22/bin
    /opt/homebrew/opt/llvm@21/bin /usr/local/opt/llvm@21/bin /usr/lib/llvm-21/bin
    /opt/homebrew/opt/llvm/bin    /usr/local/opt/llvm/bin    /usr/lib/llvm/bin)

find_program(SHARPOS_CLANG_CL NAMES clang-cl HINTS ${_sharpos_llvm_hints})
find_program(SHARPOS_LLVM_LIB NAMES llvm-lib HINTS ${_sharpos_llvm_hints})
find_program(SHARPOS_LLVM_RC  NAMES llvm-rc  HINTS ${_sharpos_llvm_hints})
# lld-link ставится отдельной формулой; его версия с версией clang не связана.
find_program(SHARPOS_LLD_LINK NAMES lld-link
             HINTS ${_sharpos_llvm_hints} /opt/homebrew/opt/lld/bin /usr/local/opt/lld/bin)

# Ассемблер MASM. Первым ищется JWasm, и это осознанно: llvm-ml не умеет
# SECTIONREL — перемещение IMAGE_REL_AMD64_SECREL, которым берётся смещение
# переменной внутри блока TLS. Без него не собирается INLINE_GETTHREAD, а это
# встроенный быстрый путь получения текущего потока. JWasm его выдаёт и на
# наших исходниках берёт все 22 файла; у llvm-ml их было четыре. Данные
# раскрутки стека у обоих совпадают — сверено по llvm-readobj.
#
# JWasm в пакетных системах нет, собирается из исходников:
#   git clone https://github.com/Baron-von-Riedesel/JWasm
#   # в GccUnix.mak убрать ключи GNU ld: -s и -Wl,-Map
#   # <шим> — каталог с malloc.h, переадресующим на stdlib.h (на macOS его нет)
#   make -f GccUnix.mak "extra_c_flags=-DNDEBUG -O2 -I<шим> -Wno-error"
#   cp build/GccUnixR/jwasm ~/.local/bin/
find_program(SHARPOS_JWASM NAMES jwasm
             HINTS ${SHARPOS_JWASM_BIN} $ENV{HOME}/.local/bin /usr/local/bin /opt/homebrew/bin)
find_program(SHARPOS_LLVM_ML NAMES llvm-ml HINTS ${_sharpos_llvm_hints})

if(NOT SHARPOS_JWASM MATCHES "NOTFOUND")
  set(SHARPOS_ASM_MASM "${SHARPOS_JWASM}")
  set(SHARPOS_ASM_MASM_TARGET_FLAG "-win64" CACHE STRING "Ключ разрядности ассемблера" FORCE)
else()
  set(SHARPOS_ASM_MASM "${SHARPOS_LLVM_ML}")
  set(SHARPOS_ASM_MASM_TARGET_FLAG "-m64" CACHE STRING "Ключ разрядности ассемблера" FORCE)
  message(WARNING "JWasm не найден, откат на llvm-ml: SECTIONREL он не поддерживает, сборка упрётся в INLINE_GETTHREAD")
endif()

foreach(_tool SHARPOS_CLANG_CL SHARPOS_LLD_LINK SHARPOS_LLVM_LIB SHARPOS_LLVM_RC SHARPOS_ASM_MASM)
  if(${_tool} MATCHES "NOTFOUND")
    message(FATAL_ERROR "${_tool} не найден. macOS: brew install llvm@19 lld. Linux: пакеты llvm-19 и lld. JWasm — из исходников, см. выше.")
  endif()
endforeach()

set(CMAKE_C_COMPILER        "${SHARPOS_CLANG_CL}")
set(CMAKE_CXX_COMPILER      "${SHARPOS_CLANG_CL}")
set(CMAKE_LINKER            "${SHARPOS_LLD_LINK}")
set(CMAKE_AR                "${SHARPOS_LLVM_LIB}")
set(CMAKE_RC_COMPILER       "${SHARPOS_LLVM_RC}")
set(CMAKE_ASM_MASM_COMPILER "${SHARPOS_ASM_MASM}")

# Триплет и sysroot. Флаги идут в CMAKE_*_FLAGS_INIT, чтобы попасть и в пробы
# компилятора, которые cmake гоняет до чтения остальных настроек.
# Целевой триплет задаётся через COMPILER_TARGET, а не флагом: cmake тогда сам
# добавит --target И выведет из него архитектуру. Если писать --target руками в
# флагах, объекты выходят x64, а компоновщику всё равно идёт /machine:ARM64 —
# cmake берёт архитектуру из умолчания clang-cl, а оно на arm64-маке arm64.
set(CMAKE_C_COMPILER_TARGET   x86_64-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET x86_64-pc-windows-msvc)

# -mcx16 разрешает cmpxchg16b, без него clang 19 отвергает
# _InterlockedCompareExchange128 ("needs target feature cx16"). MSVC включает
# его для x64 по умолчанию, поэтому в исходниках флага нет.
# Подавление предупреждений — то же, что делает build_clr_sharpos.ps1 при сборке
# на Windows, и по той же причине: CoreCLR собирается с /WX, а набор
# предупреждений откалиброван под MSVC. У clang он другой, и гасить их по
# одному не масштабируется. Здесь эти флаги нужны отдельно, потому что через
# build.sh скрипт форка не участвует и CFLAGS никто не выставляет.
#   -Wno-unused-command-line-argument — MSVC-ключи вроде /Gm-, /MP, /homeparams
#   -Wno-c++11-narrowing — сужающие приведения в case-метках (MSVC молчит)
#   -Wno-error — остальное оставляем предупреждениями, а не ошибками
set(_sharpos_flags "/vctoolsdir ${SHARPOS_XWIN_SPLAT}/crt /winsdkdir ${SHARPOS_XWIN_SPLAT}/sdk -fuse-ld=lld -mcx16 -Wno-unused-command-line-argument -Wno-c++11-narrowing -Wno-error")
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
