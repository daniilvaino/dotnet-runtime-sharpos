# build_clr_sharpos.ps1
#
# Build CoreCLR fork с TARGET_SHARPOS configuration.
# Produces coreclr_sharpos_static.lib + dependencies для Phase 6.1
# integration в SharpOS kernel image.
#
# Compiler: clang-cl (LLVM с MSVC ABI). Vanilla MSVC fails на pal_mstypes.h
# gcc-style defines (`__attribute__((noreturn))` etc.) which pal/inc/ assumes
# для TARGET_UNIX preprocessor. clang-cl supports both __GNUC__ predefines
# AND MSVC linkage — natural fit для Path A production port.
#
# Lives внутри fork repo so all fork-specific tooling stays together.
#
# Usage:
#   .\build_clr_sharpos.ps1            # incremental build
#   .\build_clr_sharpos.ps1 -NinjaClean # delete .ninja_deps only (fast unstick — see note)
#   .\build_clr_sharpos.ps1 -Clean     # full clean rebuild (deletes obj/)
#   .\build_clr_sharpos.ps1 -Configuration Release
#
# -NinjaClean note: clang-cl outputs `Note: including file:` lines that
# corrupt ninja's depfile parser between incremental builds, surfacing as
# `ninja: error: FindFirstFileExA(Note: including file: ...)` and an
# immediate abort. Deleting `.ninja_deps` forces ninja to rebuild the deps
# database in-place — ~30 sec vs ~2 min for full -Clean. Reuse this whenever
# you see that error before reaching for -Clean.

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$NinjaClean,
    [string]$Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'
# Suppress PowerShell progress bar (Remove-Item, etc.) — иначе остаётся
# visual artifact в нижней терминала line после long async output (build.cmd).
$ProgressPreference = 'SilentlyContinue'

# Script lives в fork root.
$ForkRoot = $PSScriptRoot
$ObjDir   = Join-Path $ForkRoot ('artifacts/obj/coreclr/windows.x64.' + $Configuration)
$LogFile  = Join-Path $ForkRoot ('build-sharpos-' + $Configuration.ToLower() + '.log')

# clang-cl location. Prefer LLVM standalone install at C:\Program Files\LLVM.
# Falls back на VS-bundled clang if needed.
$ClangCl = 'C:/PROGRA~1/LLVM/bin/clang-cl.exe'
if (-not (Test-Path $ClangCl)) {
    $VsClang = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin/clang-cl.exe'
    if (Test-Path $VsClang) {
        $ClangCl = 'C:/PROGRA~1/MICROS~2/2022/COMMUN~1/VC/Tools/Llvm/x64/bin/clang-cl.exe'
    } else {
        throw "clang-cl.exe not found. Install LLVM (winget install LLVM.LLVM) or VS LLVM workload."
    }
}

Write-Host "=== SharpOS CoreCLR fork build ===" -ForegroundColor Cyan
Write-Host "Fork root: $ForkRoot"
Write-Host "Configuration: $Configuration"
Write-Host "Compiler: $ClangCl"
Write-Host "Log: $LogFile"

if ($Clean -and (Test-Path $ObjDir)) {
    Write-Host "Cleaning $ObjDir ..." -ForegroundColor Yellow
    Remove-Item $ObjDir -Recurse -Force
}
elseif ($NinjaClean) {
    $NinjaDeps = Join-Path $ObjDir '.ninja_deps'
    if (Test-Path $NinjaDeps) {
        Write-Host "Removing $NinjaDeps (ninja depfile reset) ..." -ForegroundColor Yellow
        Remove-Item $NinjaDeps -Force
    } else {
        Write-Host "No .ninja_deps to remove (fresh build state)." -ForegroundColor DarkGray
    }
}

# Environment setup для CMake compiler detection.
# clang-cl flags:
#   -Wno-unused-command-line-argument
#     CoreCLR passes MSVC-specific flags (/Gm-, /MP) which clang-cl
#     recognizes but doesn't use; would be /WX-promoted to error.
#   -Wno-error
#     CoreCLR builds с /WX (warnings as errors), warning set calibrated
#     для MSVC. clang's warning set differs (strict on -Wformat, -Wsign-
#     compare, -Wunused-private-field, etc.) — fighting all через
#     individual -Wno-error=* flags не масштабируется. Single -Wno-error
#     keeps warnings visible но не promote'ит к errors.
$clangFlags = @(
    '-Wno-unused-command-line-argument'
    '-Wno-error'
    # clang treats -Wc++11-narrowing as default-error; -Wno-error не reverts его.
    # CoreCLR has many enum value case statements с negative literals (DC, 0xC0000000-style)
    # narrowed to ULONG32. Vanilla MSVC accepts implicit narrowing without warning.
    '-Wno-c++11-narrowing'
) -join ' '

$env:CC       = $ClangCl
$env:CXX      = $ClangCl
$env:CFLAGS   = $clangFlags
$env:CXXFLAGS = $clangFlags

# CMake args: TARGET_SHARPOS triggers наши additive patches across:
#   - clrfeatures.cmake (FEATURE_STATICALLY_LINKED)
#   - vm/ceemain.cpp (finalizer skip per D5)
#   - pal/CMakeLists.txt (pal/sharpos/ instead of pal/src/)
#   - eng/native/configurecompiler.cmake (TARGET_UNIX + TARGET_SHARPOS preprocessor, CXX_STANDARD 17)
#   - eng/native/configureplatform.cmake (skip CLR_CMAKE_TARGET_WIN32 on SHARPOS)
#   - src/coreclr/CMakeLists.txt (pal/ reachable on Windows host; skip nativeaot, libs-native, hosts, singlefilehost)
#   - vm/eventing/CMakeLists.txt (skip EtwProvider per Round 7)
#   - pal/inc/pal_mstypes.h (skip __cdecl redefines on _MSC_VER)
$CMakeArgs = '-DCLR_CMAKE_TARGET_SHARPOS=1'

# Skip NativeAOT csproj builds (System.Private.CoreLib-for-NAOT, etc.). Reason:
# - SharpOS kernel image uses its own NativeAOT toolchain, не CoreCLR fork's
#   nativeaot/Runtime artifacts.
# - We gated off native nativeaot/Runtime/ in src/coreclr/CMakeLists.txt → AsmOffsets.cs
#   не генерируется → NativeAOT csproj fails CSC error CS2001 на missing file.
# Подавление через `NativeAotSupported=false` skip'ит ProjectToBuild items at Subsets.props:540
# (`clr.nativeaotlibs` condition gated AND on NativeAotSupported).
# `/p:` (slash, MSBuild syntax) — не `-p:`. PowerShell видит `-p` как ambiguous
# abbreviated param (matches -pack, -pgoinstrument, -properties, -PipelineVariable).
$MsBuildProps = '/p:NativeAotSupported=false /p:SharpOSBuild=true'

Push-Location $ForkRoot
try {
    $BuildArgs = @(
        '-subset'
        'clr'
        '-configuration'
        $Configuration
        '-cmakeargs'
        $CMakeArgs
    ) + ($MsBuildProps -split ' ')

    Write-Host "`nExecuting build.cmd $($BuildArgs -join ' ')`n" -ForegroundColor Cyan

    & .\build.cmd @BuildArgs 2>&1 |
        Tee-Object -FilePath $LogFile

    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Host "`n=== BUILD SUCCEEDED ===" -ForegroundColor Green

        # step 120: merge libcmt.lib into coreclr_static.lib so kernel link
        # doesn't need to mention libcmt at all. Архитектурно libcmt — это
        # MSVC C/C++ runtime для нашего C++ форкна; kernel C# его не трогает.
        # lib.exe берёт все .obj из обеих библиотек и пакует в одну self-
        # contained .lib; kernel-side link.exe тащит .obj on-demand как обычно.
        $StaticLib = Join-Path $ObjDir 'dlls/mscoree/coreclr/coreclr_static.lib'
        if (Test-Path $StaticLib) {
            $pfx86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
            $vsInstaller = Join-Path $pfx86 'Microsoft Visual Studio\Installer\vswhere.exe'
            if (Test-Path $vsInstaller) {
                $vsRoot = & $vsInstaller -latest -property installationPath
                if ($vsRoot) {
                    $msvcDir = Join-Path $vsRoot 'VC\Tools\MSVC'
                    $msvcVer = (Get-ChildItem $msvcDir | Sort-Object Name -Descending | Select-Object -First 1).Name
                    $libExe  = Join-Path $msvcDir (Join-Path $msvcVer 'bin\Hostx64\x64\lib.exe')
                    $libcmt  = Join-Path $msvcDir (Join-Path $msvcVer 'lib\x64\libcmt.lib')
                    if ((Test-Path $libExe) -and (Test-Path $libcmt)) {
                        Write-Host "Merging libcmt.lib into coreclr_static.lib..." -ForegroundColor Cyan
                        $MergedLib = "$StaticLib.merged.tmp"
                        & $libExe /NOLOGO "/OUT:$MergedLib" $StaticLib $libcmt 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            Move-Item -Force $MergedLib $StaticLib
                            Write-Host "  coreclr_static.lib теперь self-contained (libcmt вложен)" -ForegroundColor Green
                        } else {
                            Write-Host "  lib.exe merge failed (exit $LASTEXITCODE) — kernel link will still need libcmt" -ForegroundColor Yellow
                            Remove-Item -Force $MergedLib -ErrorAction SilentlyContinue
                        }
                    } else {
                        Write-Host "lib.exe или libcmt.lib не найдены — kernel link will still need libcmt" -ForegroundColor Yellow
                    }
                }
            }
        }

        $BinDir = Join-Path $ForkRoot ('artifacts/bin/coreclr/windows.x64.' + $Configuration)
        $Outputs = @(
            @{ Path = Join-Path $ObjDir 'dlls/mscoree/coreclr/coreclr_static.lib'; Label = 'coreclr_static.lib (kernel input, libcmt merged)' }
            @{ Path = Join-Path $BinDir 'coreclr.dll';        Label = 'coreclr.dll (SHARED target)' }
            @{ Path = Join-Path $BinDir 'mscordaccore.dll';   Label = 'mscordaccore.dll (DAC)' }
            @{ Path = Join-Path $ObjDir 'dlls/mscorrc/mscorrc.lib'; Label = 'mscorrc.lib (compiled-in resources)' }
        )
        foreach ($o in $Outputs) {
            if (Test-Path $o.Path) {
                $size = (Get-Item $o.Path).Length / 1MB
                Write-Host ("  {0,-50} {1,8:N1} MB" -f $o.Label, $size) -ForegroundColor Green
            } else {
                Write-Host ("  {0,-50} MISSING" -f $o.Label) -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "`n=== BUILD FAILED (exit $exitCode) ===" -ForegroundColor Red
        Write-Host "Recent FAILED targets:" -ForegroundColor Yellow
        Select-String -Path $LogFile -Pattern 'FAILED:' |
            Select-Object -First 10 |
            ForEach-Object { Write-Host "  $($_.Line.Trim())" }
        Write-Host "`nSee full log: $LogFile"
        exit $exitCode
    }
} finally {
    Pop-Location
}
