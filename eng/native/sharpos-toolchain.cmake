# Тулчейн SharpOS: сборка форка CoreCLR под SharpOS (win-x64, TARGET_SHARPOS)
# на ЛЮБОМ хосте — Windows, macOS, Linux — одними и теми же инструментами.
#
# Инструменты и их версии — из toolchain.json в корне SharpOS; находит и
# проверяет их build_clr_sharpos.ps1 (через tools/Toolchain.ps1 SharpOS).
# Visual Studio и MSVC не участвуют даже на Windows:
#   clang-cl  — компилятор
#   lld-link  — компоновщик вместо link.exe
#   llvm-lib  — вместо lib.exe
#   llvm-rc   — вместо rc.exe
#   JWasm     — ассемблер MASM вместо ml64 (llvm-ml не умеет SECTIONREL, см. ниже)
# Заголовки и библиотеки MSVC CRT и Windows SDK — из splat'а, который делает
# xwin. Файлы остаются микрософтовскими: xwin их только скачивает.
#
# Пути приходят из окружения (их выставляет build_clr_sharpos.ps1 после
# проверки) или через -D:
#   SHARPOS_LLVM_BIN    каталог bin LLVM
#   SHARPOS_XWIN_SPLAT  splat от xwin (crt/ и sdk/)
#   SHARPOS_JWASM       исполняемый файл JWasm
# Из окружения — потому что cmake переисполняет тулчейн внутри пробных
# подпроектов (try_compile), а туда -D с командной строки не доходит.
#
# По признаку CLR_CMAKE_SHARPOS_TOOLCHAIN eng/native/configurecompiler.cmake и
# ещё несколько файлов выбирают ключи под этот набор инструментов (JWasm
# вместо ml64, готовые idl вместо midl, без mc и DAC). Обычная сборка
# dotnet/runtime без этого файла идёт как в апстриме.

# Сборка кросс-инструментов идёт под ХОСТ, а не под цель: crossgen2 —
# управляемый инструмент, он бежит на хосте и дёргает JIT через нативную
# прослойку libjitinterface. На unix-хосте её собирает отдельный заход cmake с
# признаком CLR_CROSS_COMPONENTS_BUILD (его ставит build-runtime.sh), и наш
# тулчейн ему не нужен: CMAKE_SYSTEM_NAME=Windows ломает настройку ("Unknown
# CMake command check_symbol_exists" в hosts/corerun). Компилятор для него —
# clang того же LLVM, его задаёт build_clr_sharpos.ps1 через CC/CXX.
# Признак передаётся и во внутренние пробы cmake: туда -D с командной строки не
# доходит, и без этого проба перечитывает тулчейн уже без признака.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES CLR_CROSS_COMPONENTS_BUILD)
if(CLR_CROSS_COMPONENTS_BUILD)
  return()
endif()

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)
set(CMAKE_CROSSCOMPILING TRUE)
set(CLR_CMAKE_SHARPOS_TOOLCHAIN 1 CACHE INTERNAL "Сборка идёт тулчейном SharpOS")
# «Хост» в терминах CoreCLR — архитектура, под которую собирается нативный
# код, и для цели SharpOS она всегда x64. gen-buildsys на arm64-маке передаёт
# свою (arm64), поэтому перебиваем: это единственное место, где она задаётся.
set(CLR_CMAKE_HOST_ARCH x64 CACHE STRING "Архитектура нативного кода SharpOS" FORCE)

foreach(_var SHARPOS_LLVM_BIN SHARPOS_XWIN_SPLAT SHARPOS_JWASM)
  if(NOT ${_var} AND DEFINED ENV{${_var}})
    file(TO_CMAKE_PATH "$ENV{${_var}}" ${_var})
  endif()
  if(NOT ${_var})
    message(FATAL_ERROR "${_var} не задан. Сборка форка идёт тулчейном SharpOS: запускайте build_clr_sharpos.ps1: он находит инструменты и сверяет версии с toolchain.json SharpOS.")
  endif()
  set(${_var} "${${_var}}" CACHE PATH "Тулчейн SharpOS" FORCE)
  list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ${_var})
endforeach()

foreach(_probe crt/include sdk/include/um crt/lib/x64 sdk/lib/ucrt/x64)
  if(NOT EXISTS "${SHARPOS_XWIN_SPLAT}/${_probe}")
    message(FATAL_ERROR "В splat не хватает ${_probe}: ${SHARPOS_XWIN_SPLAT}")
  endif()
endforeach()

# Только из каталога тулчейна: никаких системных LLVM рядом.
find_program(SHARPOS_CLANG_CL NAMES clang-cl PATHS "${SHARPOS_LLVM_BIN}" NO_DEFAULT_PATH)
find_program(SHARPOS_LLD_LINK NAMES lld-link PATHS "${SHARPOS_LLVM_BIN}" NO_DEFAULT_PATH)
find_program(SHARPOS_LLVM_LIB NAMES llvm-lib PATHS "${SHARPOS_LLVM_BIN}" NO_DEFAULT_PATH)
find_program(SHARPOS_LLVM_RC  NAMES llvm-rc  PATHS "${SHARPOS_LLVM_BIN}" NO_DEFAULT_PATH)
foreach(_tool SHARPOS_CLANG_CL SHARPOS_LLD_LINK SHARPOS_LLVM_LIB SHARPOS_LLVM_RC)
  if(${_tool} MATCHES "NOTFOUND")
    message(FATAL_ERROR "${_tool} не найден в ${SHARPOS_LLVM_BIN}. Версии — toolchain.json SharpOS, как поставить — README SharpOS.")
  endif()
endforeach()
if(NOT EXISTS "${SHARPOS_JWASM}")
  message(FATAL_ERROR "JWasm не найден: ${SHARPOS_JWASM}. Версии — toolchain.json SharpOS, как поставить — README SharpOS.")
endif()

# Версия LLVM имеет значение, и подходит узкий диапазон. Две независимые
# диагностики clang режут CoreCLR с разных концов:
#
#   __try в функции с объектом, требующим раскрутки   19 ✅  21 ✅  22 ✅  23 ❌
#   no_builtin на defaulted-функции                   19 ❌            22 ✅
#
# Первое: при HOST_WINDOWS подключается inc/palclr.h, где PAL_TRY раскрывается
# в настоящий __try, а рядом живут кадры вроде DebuggerU2MCatchHandlerFrame
# (vm/threads.cpp). Второе приходит из заголовков MSVC. Оба места не наши.
# Версия зафиксирована в toolchain.json SharpOS; build_clr_sharpos.ps1 сверяет
# её до сборки и передаёт сюда в SHARPOS_LLVM_VERSION — сверяем ещё раз тот
# clang-cl, которым cmake будет собирать.
if(NOT SHARPOS_LLVM_VERSION AND DEFINED ENV{SHARPOS_LLVM_VERSION})
  set(SHARPOS_LLVM_VERSION "$ENV{SHARPOS_LLVM_VERSION}")
endif()
if(NOT SHARPOS_LLVM_VERSION)
  message(FATAL_ERROR "SHARPOS_LLVM_VERSION не задан: запускайте сборку через build_clr_sharpos.ps1 (версия — из toolchain.json SharpOS).")
endif()
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES SHARPOS_LLVM_VERSION)
execute_process(COMMAND "${SHARPOS_CLANG_CL}" --version OUTPUT_VARIABLE _sharpos_llvm_have)
if(NOT _sharpos_llvm_have MATCHES "clang version ${SHARPOS_LLVM_VERSION}[^0-9]")
  message(FATAL_ERROR "clang-cl не той версии: нужна ${SHARPOS_LLVM_VERSION}, а он сообщает: ${_sharpos_llvm_have}")
endif()

# Ассемблер MASM — JWasm. llvm-ml не умеет SECTIONREL — перемещение
# IMAGE_REL_AMD64_SECREL, которым берётся смещение переменной внутри блока TLS.
# Без него не собирается INLINE_GETTHREAD, а это встроенный быстрый путь
# получения текущего потока. JWasm его выдаёт и берёт все 22 файла; у llvm-ml
# их было четыре. Данные раскрутки стека у обоих совпадают — сверено по
# llvm-readobj. ml64 из Visual Studio не берём, чтобы путь был один на всех
# хостах. Ключи ассемблера (-nologo -win64 и прочие) задаёт configurecompiler.cmake.
set(CMAKE_C_COMPILER        "${SHARPOS_CLANG_CL}")
set(CMAKE_CXX_COMPILER      "${SHARPOS_CLANG_CL}")
set(CMAKE_LINKER            "${SHARPOS_LLD_LINK}")
set(CMAKE_AR                "${SHARPOS_LLVM_LIB}")
set(CMAKE_RC_COMPILER       "${SHARPOS_LLVM_RC}")
set(CMAKE_ASM_MASM_COMPILER "${SHARPOS_JWASM}")

# Триплет задаётся через COMPILER_TARGET, а не флагом: cmake тогда сам добавит
# --target И выведет из него архитектуру. Если писать --target руками в
# флагах, объекты выходят x64, а компоновщику всё равно идёт /machine:ARM64 —
# cmake берёт архитектуру из умолчания clang-cl, а оно на arm64-маке arm64.
set(CMAKE_C_COMPILER_TARGET   x86_64-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET x86_64-pc-windows-msvc)

# Флаги идут в CMAKE_*_FLAGS_INIT, чтобы попасть и в пробы компилятора,
# которые cmake гоняет до чтения остальных настроек.
#   /vctoolsdir, /winsdkdir — заголовки MSVC и Windows SDK из splat'а, а не из
#                             установленной Visual Studio (на Windows тоже)
#   -mcx16 — разрешает cmpxchg16b: clang иначе отвергает
#            _InterlockedCompareExchange128 ("needs target feature cx16").
#            MSVC включает его для x64 по умолчанию, поэтому в исходниках флага нет.
#   -Wno-unused-command-line-argument — MSVC-ключи вроде /Gm-, /MP, /homeparams
#   -Wno-c++11-narrowing — сужающие приведения в case-метках (MSVC молчит)
#   -Wno-error — CoreCLR собирается с /WX, а набор предупреждений откалиброван
#                под MSVC; у clang он другой, гасить их по одному не масштабируется
set(_sharpos_flags "/vctoolsdir ${SHARPOS_XWIN_SPLAT}/crt /winsdkdir ${SHARPOS_XWIN_SPLAT}/sdk -fuse-ld=lld -mcx16 -Wno-unused-command-line-argument -Wno-c++11-narrowing -Wno-error")
set(CMAKE_C_FLAGS_INIT   "${_sharpos_flags}")
set(CMAKE_CXX_FLAGS_INIT "${_sharpos_flags}")
# Самодельные команды cmake (preprocess_file и подобные) зовут компилятор
# напрямую и CMAKE_*_FLAGS не получают — им нужен sysroot отдельным списком.
set(SHARPOS_SYSROOT_COMPILE_FLAGS
    "/vctoolsdir;${SHARPOS_XWIN_SPLAT}/crt;/winsdkdir;${SHARPOS_XWIN_SPLAT}/sdk"
    CACHE STRING "Флаги sysroot для самодельных вызовов компилятора" FORCE)

# Компилятор ресурсов (llvm-rc) свои пути включения не наследует ни от
# /winsdkdir, ни от CMAKE_C_FLAGS — ему нужен явный -I, иначе .rc не находит
# даже verrsrc.h.
set(CMAKE_RC_FLAGS_INIT "-I ${SHARPOS_XWIN_SPLAT}/sdk/include/um -I ${SHARPOS_XWIN_SPLAT}/sdk/include/shared -I ${SHARPOS_XWIN_SPLAT}/sdk/include/ucrt -I ${SHARPOS_XWIN_SPLAT}/crt/include")

# Пути к библиотекам приходится задавать отдельно: сшивание cmake ведёт через
# lld-link НАПРЯМУЮ (vs_link_exe), а не через драйвер clang-cl, поэтому
# /winsdkdir и /vctoolsdir до компоновщика не доходят и он не находит даже
# kernel32.lib.
set(_sharpos_libpaths "/LIBPATH:${SHARPOS_XWIN_SPLAT}/crt/lib/x64 /LIBPATH:${SHARPOS_XWIN_SPLAT}/sdk/lib/um/x64 /LIBPATH:${SHARPOS_XWIN_SPLAT}/sdk/lib/ucrt/x64")
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_sharpos_libpaths}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_sharpos_libpaths}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_sharpos_libpaths}")

# Поиск целевых артефактов — только в sysroot: хостовые библиотеки и
# заголовки (/usr/lib, а на Windows — установленный SDK) для цели не годятся.
set(CMAKE_FIND_ROOT_PATH "${SHARPOS_XWIN_SPLAT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
