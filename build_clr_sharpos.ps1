# build_clr_sharpos.ps1
#
# Собирает форк CoreCLR под SharpOS (win-x64, TARGET_SHARPOS). Результат —
# coreclr_static.lib и соседние библиотеки, которые ядро SharpOS линкует
# статически, плюс System.Private.CoreLib и BCL для hosted-яруса.
#
# Один путь на всех хостах. Windows, macOS и Linux собирают одними и теми же
# инструментами: clang-cl + lld-link + llvm-lib + llvm-rc + JWasm, заголовки и
# библиотеки MSVC — из splat'а xwin. Visual Studio не нужна и не используется
# даже на Windows. Как и почему — в eng/native/sharpos-toolchain.cmake.
# Скрипт ничего не ставит: находит инструменты и сверяет их версии с
# toolchain.json SharpOS (tools/Toolchain.ps1). SDK .NET ставит себе Arcade по
# global.json форка, как обычно.
#
# Почему clang-cl, а не cl.exe: pal/inc/ под TARGET_UNIX опирается на
# gcc-подобные определения (__attribute__((noreturn)) и т.п.), которые cl.exe
# не принимает; clang-cl понимает и их, и MSVC ABI.
#
# Использование:
#   ./build_clr_sharpos.ps1                  # инкрементальная сборка, Release
#   ./build_clr_sharpos.ps1 -Configuration Debug
#   ./build_clr_sharpos.ps1 -NinjaClean      # только сбросить .ninja_deps (см. ниже)
#   ./build_clr_sharpos.ps1 -Clean           # чистая пересборка (удаляет obj/)
#
# -NinjaClean: clang-cl печатает строки `Note: including file:`, которые между
# инкрементальными сборками ломают базу зависимостей ninja — сборка сразу
# падает с `ninja: error: FindFirstFileExA(Note: including file: ...)`.
# Удаление .ninja_deps чинит это за ~30 с против ~2 мин полного -Clean.

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$NinjaClean,
    # Release по умолчанию — как CoreClrForkConfig в OS/OS.csproj.
    [string]$Configuration = 'Release',
    # Ничего не делает, оставлен только чтобы старые команды не падали.
    # Раньше отдельным шагом собирался Linux SPC IL (linux.x64.*/IL), но с
    # step 124 ядро грузит Windows SPC из windows.x64.$Configuration — его
    # даёт основная сборка ниже.
    [switch]$SkipLinuxIL
)

$ErrorActionPreference = 'Stop'
# Без этого прогресс-бар Remove-Item оставляет след в нижней строке терминала
# после длинного вывода build.cmd.
$ProgressPreference = 'SilentlyContinue'

$ForkRoot = $PSScriptRoot
$ObjDir   = Join-Path $ForkRoot ('artifacts/obj/coreclr/windows.x64.' + $Configuration)
$BinDir   = Join-Path $ForkRoot ('artifacts/bin/coreclr/windows.x64.' + $Configuration)
$LogFile  = Join-Path $ForkRoot ('build-sharpos-' + $Configuration.ToLower() + '.log')

# Тулчейн — общий с SharpOS: форк лежит внутри SharpOS (или SHARPOS_ROOT).
$SharpOsRoot = if ($env:SHARPOS_ROOT) { $env:SHARPOS_ROOT } else { Split-Path -Parent $ForkRoot }
$ToolchainLib = Join-Path $SharpOsRoot 'tools/Toolchain.ps1'
if (-not (Test-Path -LiteralPath $ToolchainLib)) {
    throw "Не найден $ToolchainLib. Форк собирается тулчейном SharpOS: он должен лежать в SharpOS/dotnet-runtime-sharpos либо задайте SHARPOS_ROOT."
}
. $ToolchainLib
$WindowsHost = Test-SharpOsWindowsHost
$Rid = Get-SharpOsHostRid

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

# CMake args: TARGET_SHARPOS включает наши правки в clrfeatures.cmake,
# configurecompiler.cmake, configureplatform.cmake, src/coreclr/CMakeLists.txt,
# pal/, vm/eventing/ и т.д. Остальное (компиляторы, sysroot, JWasm, x64)
# задаёт тулчейн-файл, он приходит через переменную окружения
# CMAKE_TOOLCHAIN_FILE. Аргумент ровно один: build.cmd режет -cmakeargs по
# пробелам, и второй -D ушёл бы в MSBuild как неизвестный ключ.
$CMakeArgs = '-DCLR_CMAKE_TARGET_SHARPOS=1'

# NativeAotSupported=false: ядро SharpOS собирается своим NativeAOT, а
# nativeaot/Runtime форка отключён в src/coreclr/CMakeLists.txt (без него не
# генерируется AsmOffsets.cs, и csproj NativeAOT падают). SharpOSBuild=true —
# признак для Subsets.props.
# `/p:`, а не `-p:`: PowerShell принял бы `-p` за сокращение своих параметров.
$MsBuildProps = @('/p:NativeAotSupported=false', '/p:SharpOSBuild=true')

# Версия в ресурсах PE (VERSIONINFO) — одна на всех хостах. Arcade на
# Windows-хосте пишет artifacts/obj/_version.h сам, с «\xa9 Microsoft
# Corporation» (байт 0xA9 — ©, который llvm-rc без кодовой страницы не
# принимает), а на unix пишет только _version.c, и cmake берёт запасной
# eng/native/version/_version.h (его туда копирует copy_version_files). Уводим
# файл Arcade в сторону на любом хосте — остаётся запасной, одинаковый везде.
$ArcadeVersionFile = Join-Path $ForkRoot 'artifacts/obj/sharpos/arcade-native-version'
$MsBuildProps += "/p:NativeVersionFile=$ArcadeVersionFile"
$StaleVersionHeader = Join-Path $ForkRoot 'artifacts/obj/_version.h'
$FallbackVersionHeader = Join-Path $ForkRoot 'eng/native/version/_version.h'
if ((Test-Path -LiteralPath $StaleVersionHeader) -and
    ((Get-FileHash -LiteralPath $StaleVersionHeader).Hash -ne (Get-FileHash -LiteralPath $FallbackVersionHeader).Hash)) {
    Remove-Item -LiteralPath $StaleVersionHeader -Force
}

# Одинаковые аргументы на всех хостах; разное только имя входного скрипта.
# На Windows -ninja ничего не меняет (ninja там по умолчанию), -os/-arch — умолчания.
$BuildArgs = @('-subset', 'clr', '-configuration', $Configuration,
               '-os', 'windows', '-arch', 'x64', '-ninja',
               '-cmakeargs', $CMakeArgs) + $MsBuildProps

# python — генераторам eventing'а CoreCLR.
$saved = Enter-SharpOsToolchain -Components llvm, jwasm, winsdk, cmake, ninja, python
$extraEnv = 'CMAKE_TOOLCHAIN_FILE', 'VisualStudioVersion', 'SkipVCEnvInit', 'CLR_CROSS_COMPILER_DEFAULT', 'CC', 'CXX', 'SDKROOT'
foreach ($n in $extraEnv) { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
Push-Location $ForkRoot
try {
    $env:CMAKE_TOOLCHAIN_FILE = Join-Path $ForkRoot 'eng/native/sharpos-toolchain.cmake'

    if ($WindowsHost) {
        # build-runtime.cmd зовёт init-vs-env.cmd и vcvarsall. VisualStudioVersion
        # говорит init-vs-env «окружение VS уже есть» (и тот же номер передаётся
        # gen-buildsys.cmd позиционным аргументом), SkipVCEnvInit отключает
        # vcvarsall. Компиляторы, заголовки и библиотеки задаёт тулчейн-файл.
        $env:VisualStudioVersion = '17.0'
        $env:SkipVCEnvInit = '1'
        $Entry = '.\build.cmd'
    } else {
        # build-runtime.sh иначе прогонит init-compiler.sh и подставит свой clang.
        $env:CLR_CROSS_COMPILER_DEFAULT = '1'
        # Инструменты форка, которые бегут на самом хосте (JIT для crossgen2),
        # собираются отдельным заходом cmake без нашего тулчейна. Компилятор для
        # них — clang того же LLVM, а не системный.
        $env:CC  = Join-Path $env:SHARPOS_LLVM_BIN 'clang'
        $env:CXX = Join-Path $env:SHARPOS_LLVM_BIN 'clang++'
        if ($Rid.StartsWith('osx')) { $env:SDKROOT = (& xcrun --show-sdk-path).Trim() }
        $Entry = './build.sh'
    }

    Write-Host "=== SharpOS CoreCLR fork build ===" -ForegroundColor Cyan
    Write-Host "Fork root:     $ForkRoot"
    Write-Host "Configuration: $Configuration"
    Write-Host "Host:          $Rid"
    Write-Host "LLVM:          $env:SHARPOS_LLVM_VERSION ($env:SHARPOS_LLVM_BIN)"
    Write-Host "JWasm:         $env:SHARPOS_JWASM"
    Write-Host "Windows SDK:   $env:SHARPOS_XWIN_SPLAT"
    Write-Host "Log:           $LogFile"
    Write-Host "`n$Entry $($BuildArgs -join ' ')`n" -ForegroundColor Cyan
    & $Entry @BuildArgs 2>&1 | Tee-Object -FilePath $LogFile
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host "`n=== BUILD FAILED (exit $exitCode) ===" -ForegroundColor Red
        Write-Host "Recent FAILED targets:" -ForegroundColor Yellow
        Select-String -Path $LogFile -Pattern 'FAILED:' |
            Select-Object -First 10 |
            ForEach-Object { Write-Host "  $($_.Line.Trim())" }
        Write-Host "`nSee full log: $LogFile"
        exit $exitCode
    }

    Write-Host "`n=== BUILD SUCCEEDED ===" -ForegroundColor Green
    # libcmt в coreclr_static.lib не вливается: ядро передаёт libcmt.lib
    # компоновщику само (SharpOsNativeLink.props в SharpOS). Переупаковать её
    # средствами LLVM и нельзя — внутри есть объекты с машинным типом 0
    # (mbcat.obj и др.), llvm-lib отвергает их: "unknown machine: 0".
    $Outputs = @(
        @{ Path = Join-Path $ObjDir 'dlls/mscoree/coreclr/coreclr_static.lib'; Label = 'coreclr_static.lib (kernel input)' }
        @{ Path = Join-Path $ObjDir 'dlls/mscorrc/mscorrc.lib';                Label = 'mscorrc.lib (compiled-in resources)' }
        @{ Path = Join-Path $BinDir 'System.Private.CoreLib.dll';              Label = 'System.Private.CoreLib.dll' }
        @{ Path = Join-Path $BinDir 'coreclr.dll';                             Label = 'coreclr.dll (SHARED target)' }
    )
    foreach ($o in $Outputs) {
        if (Test-Path $o.Path) {
            $size = (Get-Item $o.Path).Length / 1MB
            Write-Host ("  {0,-50} {1,8:N1} MB" -f $o.Label, $size) -ForegroundColor Green
        } else {
            Write-Host ("  {0,-50} MISSING" -f $o.Label) -ForegroundColor Yellow
        }
    }
} finally {
    Pop-Location
    Exit-SharpOsToolchain $saved
}
