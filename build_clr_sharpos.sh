#!/usr/bin/env bash
# build_clr_sharpos.sh
#
# Build CoreCLR fork с TARGET_SHARPOS configuration на Linux/WSL.
# Производит coreclr_sharpos_static.a + dependencies для Phase 6.1
# integration в SharpOS kernel image.
#
# Compiler: gcc/clang (Linux host). TARGET_UNIX preprocessor + pal/sharpos/
# overlay = natural fit; pal_mstypes.h's gcc-style defines работают без
# adapter shims (vs Windows host where MSVC stdlib fights pal types).
#
# Это compile farm подход, не architecture validation. Output static archive
# cross-link'нется в SharpOS kernel image (PE format). Linux host используется
# потому что TARGET_UNIX + gcc — production-tested upstream maintainers'ом
# combination. Per sage 2: "не WSL as primary architecture validator" —
# здесь WSL = build environment only.
#
# Usage:
#   ./build_clr_sharpos.sh             # incremental build
#   ./build_clr_sharpos.sh -c          # clean rebuild (deletes obj/)
#   ./build_clr_sharpos.sh -r          # Release config (default Debug)

set -euo pipefail

CLEAN=0
CONFIG=Debug

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--clean)    CLEAN=1 ;;
        -r|--release)  CONFIG=Release ;;
        -h|--help)
            echo "Usage: $0 [-c|--clean] [-r|--release]"
            exit 0 ;;
        *)
            echo "Unknown arg: $1" >&2
            exit 1 ;;
    esac
    shift
done

FORK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBJ_DIR="$FORK_ROOT/artifacts/obj/coreclr/linux.x64.$CONFIG"
LOG_FILE="$FORK_ROOT/build-sharpos-$(echo "$CONFIG" | tr '[:upper:]' '[:lower:]').log"

echo "=== SharpOS CoreCLR fork build (Linux host) ==="
echo "Fork root: $FORK_ROOT"
echo "Configuration: $CONFIG"
echo "Log: $LOG_FILE"

if [[ $CLEAN -eq 1 ]] && [[ -d "$OBJ_DIR" ]]; then
    echo "Cleaning $OBJ_DIR ..."
    rm -rf "$OBJ_DIR"
fi

# CMake args: TARGET_SHARPOS triggers наши additive patches across:
#   - clrfeatures.cmake (FEATURE_STATICALLY_LINKED)
#   - vm/ceemain.cpp (finalizer skip per D5)
#   - pal/CMakeLists.txt (pal/sharpos/ instead of pal/src/)
#   - eng/native/configurecompiler.cmake (TARGET_SHARPOS preprocessor)
#   - eng/native/configureplatform.cmake (skip CLR_CMAKE_TARGET_WIN32 on SHARPOS)
#   - src/coreclr/CMakeLists.txt (skip nativeaot, libs-native, hosts, singlefilehost)
#   - vm/eventing/CMakeLists.txt (skip EtwProvider on SHARPOS)
#   - pal/inc/pal_mstypes.h (skip __cdecl redefines on _MSC_VER)
#   - gc/env/gcenv.structs.h (skip pthread_t-based EEThreadId on SHARPOS)
CMAKE_ARGS="-DCLR_CMAKE_TARGET_SHARPOS=1"

cd "$FORK_ROOT"

echo ""
echo "Executing: ./build.sh -subset clr -configuration $CONFIG -cmakeargs \"$CMAKE_ARGS\""
echo ""

set +e
./build.sh -subset clr -configuration "$CONFIG" -cmakeargs "$CMAKE_ARGS" 2>&1 | tee "$LOG_FILE"
RC=${PIPESTATUS[0]}
set -e

echo ""
if [[ $RC -eq 0 ]]; then
    echo "=== BUILD SUCCEEDED ==="
    STATIC_LIB="$OBJ_DIR/dlls/mscoree/coreclr/libcoreclr_static.a"
    if [[ -f "$STATIC_LIB" ]]; then
        SIZE_MB=$(du -m "$STATIC_LIB" | cut -f1)
        echo "Output: libcoreclr_static.a (${SIZE_MB} MB)"
    fi
else
    echo "=== BUILD FAILED (exit $RC) ==="
    echo "Recent FAILED targets:"
    grep -E "^FAILED:|FAILED:" "$LOG_FILE" | head -10 | sed 's/^/  /'
    echo ""
    echo "See full log: $LOG_FILE"
    exit "$RC"
fi
