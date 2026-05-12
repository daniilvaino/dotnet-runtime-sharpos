set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories("../env")

if(CLR_CMAKE_HOST_UNIX)
  set_source_files_properties(isa_detection.cpp PROPERTIES COMPILE_FLAGS -mavx2)
  set_source_files_properties(do_vxsort_avx2.cpp PROPERTIES COMPILE_FLAGS -mavx2)
  set_source_files_properties(do_vxsort_avx512.cpp PROPERTIES COMPILE_FLAGS -mavx2)
  set_source_files_properties(machine_traits.avx2.cpp PROPERTIES COMPILE_FLAGS -mavx2)
  set_source_files_properties(smallsort/bitonic_sort.AVX2.int64_t.generated.cpp PROPERTIES COMPILE_FLAGS -mavx2)
  set_source_files_properties(smallsort/bitonic_sort.AVX2.int32_t.generated.cpp PROPERTIES COMPILE_FLAGS -mavx2)
  set_source_files_properties(smallsort/bitonic_sort.AVX512.int64_t.generated.cpp PROPERTIES COMPILE_FLAGS -mavx2)
  set_source_files_properties(smallsort/bitonic_sort.AVX512.int32_t.generated.cpp PROPERTIES COMPILE_FLAGS -mavx2)
  set_source_files_properties(smallsort/avx2_load_mask_tables.cpp PROPERTIES COMPILE_FLAGS -mavx2)
endif(CLR_CMAKE_HOST_UNIX)

# SharpOS port: clang-cl на Windows host тоже требует explicit -mavx2/-mavx512f
# для intrinsics (vanilla MSVC cl.exe accepts intrinsics без флагов). Без них
# clang-cl emits "always_inline function requires target feature 'avx2'" errors.
# AVX512 files отдельно с -mavx512f. POPCNT тоже нужен (vxsort.h _mm_popcnt_u32).
if(CLR_CMAKE_TARGET_SHARPOS)
  set_source_files_properties(isa_detection.cpp PROPERTIES COMPILE_FLAGS "-mavx2 -mpopcnt")
  set_source_files_properties(do_vxsort_avx2.cpp PROPERTIES COMPILE_FLAGS "-mavx2 -mpopcnt")
  set_source_files_properties(do_vxsort_avx512.cpp PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512dq -mavx512bw -mavx2 -mpopcnt")
  set_source_files_properties(machine_traits.avx2.cpp PROPERTIES COMPILE_FLAGS "-mavx2 -mpopcnt")
  set_source_files_properties(smallsort/bitonic_sort.AVX2.int64_t.generated.cpp PROPERTIES COMPILE_FLAGS "-mavx2 -mpopcnt")
  set_source_files_properties(smallsort/bitonic_sort.AVX2.int32_t.generated.cpp PROPERTIES COMPILE_FLAGS "-mavx2 -mpopcnt")
  set_source_files_properties(smallsort/bitonic_sort.AVX512.int64_t.generated.cpp PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512dq -mavx512bw -mavx2 -mpopcnt")
  set_source_files_properties(smallsort/bitonic_sort.AVX512.int32_t.generated.cpp PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512dq -mavx512bw -mavx2 -mpopcnt")
  set_source_files_properties(smallsort/avx2_load_mask_tables.cpp PROPERTIES COMPILE_FLAGS "-mavx2 -mpopcnt")
endif(CLR_CMAKE_TARGET_SHARPOS)

set (VXSORT_SOURCES
  isa_detection.cpp
  do_vxsort_avx2.cpp
  do_vxsort_avx512.cpp
  machine_traits.avx2.cpp
  smallsort/bitonic_sort.AVX2.int64_t.generated.cpp
  smallsort/bitonic_sort.AVX2.int32_t.generated.cpp
  smallsort/bitonic_sort.AVX512.int64_t.generated.cpp
  smallsort/bitonic_sort.AVX512.int32_t.generated.cpp
  smallsort/avx2_load_mask_tables.cpp
  do_vxsort.h
)

add_library(gc_vxsort OBJECT ${VXSORT_SOURCES})
