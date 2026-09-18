@echo off

powershell -ExecutionPolicy ByPass -NoProfile -Command "& { . '%~dp0eng\common\tools.ps1'; InitializeDotNetCli $true $true }"

if NOT [%ERRORLEVEL%] == [0] (
  echo Failed to install or invoke dotnet... 1>&2
  exit /b %ERRORLEVEL%
)

:: SharpOS: let PowerShell read sdk.txt and print the path. 'set /p' from a file
:: decodes bytes with the OEM code page while sdk.txt is written in ANSI, so a
:: non-ASCII SDK path (e.g. under a Cyrillic user profile, where mise puts it)
:: came out garbled. PowerShell's console output uses the same OEM page cmd reads.
for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "Get-Content -LiteralPath '%~dp0artifacts\toolset\sdk.txt'"`) do set "dotnetPath=%%p"

:: Clear the 'Platform' env variable for this session, as it's a per-project setting within the build, and
:: misleading value (such as 'MCD' in HP PCs) may lead to build breakage (issue: #69).
set Platform=

:: Don't resolve runtime, shared framework, or SDK from other locations to ensure build determinism
set DOTNET_MULTILEVEL_LOOKUP=0

:: Disable first run since we want to control all package sources
set DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

call "%dotnetPath%\dotnet.exe" %*
