# Индекс модуля для PE-файла, одинаково на любом хосте (cmake -P).
#
#   cmake -DMODULE=<файл .dll/.exe> -DOUTPUT=<заголовок> -P genmoduleindex-pe.cmake
#
# Результат тот же, что у genmoduleindex.cmd: длина 8, затем TimeDateStamp и
# SizeOfImage, по 4 байта в порядке little-endian. Тот скрипт берёт их из
# dumpbin (Visual Studio) — без VS он молча пишет нули; genmoduleindex.sh
# ищет ELF Build ID / Mach-O UUID и PE не понимает. Здесь поля читаются прямо
# из заголовка PE — нужен только cmake.

file(READ "${MODULE}" _mz LIMIT 2 HEX)
if(NOT _mz STREQUAL "4d5a")
  message(FATAL_ERROR "${MODULE}: не PE (нет MZ)")
endif()

# 4 байта little-endian по смещению → "b0, b1, b2, b3" (как пишет .cmd)
function(_pe_bytes offset outvar)
  file(READ "${MODULE}" _hex OFFSET ${offset} LIMIT 4 HEX)
  string(SUBSTRING "${_hex}" 0 2 _b0)
  string(SUBSTRING "${_hex}" 2 2 _b1)
  string(SUBSTRING "${_hex}" 4 2 _b2)
  string(SUBSTRING "${_hex}" 6 2 _b3)
  set(${outvar} "0x${_b0}, 0x${_b1}, 0x${_b2}, 0x${_b3}" PARENT_SCOPE)
  math(EXPR _val "0x${_b3}${_b2}${_b1}${_b0}")
  set(${outvar}_VALUE ${_val} PARENT_SCOPE)
endfunction()

_pe_bytes(60 _lfanew)                       # e_lfanew
math(EXPR _pe "${_lfanew_VALUE}")
file(READ "${MODULE}" _sig OFFSET ${_pe} LIMIT 4 HEX)
if(NOT _sig STREQUAL "50450000")
  message(FATAL_ERROR "${MODULE}: нет сигнатуры PE по смещению ${_pe}")
endif()
math(EXPR _ts_off "${_pe} + 8")             # IMAGE_FILE_HEADER.TimeDateStamp
math(EXPR _size_off "${_pe} + 24 + 56")     # IMAGE_OPTIONAL_HEADER.SizeOfImage
_pe_bytes(${_ts_off} _ts)
_pe_bytes(${_size_off} _size)

file(WRITE "${OUTPUT}" "0x08, ${_ts}, ${_size}, \n")
