@echo off
setlocal enableextensions
title Replace Parser - Launcher

rem ============================================================
rem  Replace Parser launcher
rem  - Checks for the .NET 8 Desktop Runtime (x64)
rem  - If present: starts the tool
rem  - If missing: opens the official Microsoft download page
rem ============================================================

set "EXE=%~dp0SSForensic.exe"

rem --- Check installed .NET runtimes for Microsoft.WindowsDesktop.App 8.x ---
set "HASNET="
for /f "delims=" %%R in ('dotnet --list-runtimes 2^>nul ^| findstr /i "Microsoft.WindowsDesktop.App 8."') do set "HASNET=1"

if not defined HASNET (
    echo.
    echo   The .NET 8 Desktop Runtime ^(x64^) is required and was not found.
    echo   Opening the download page in your browser...
    echo.
    start "" "https://dotnet.microsoft.com/en-us/download/dotnet/8.0/runtime?cid=getdotnetcore"
    echo   After installing it, run this launcher again.
    echo.
    pause
    exit /b 1
)

if not exist "%EXE%" (
    echo.
    echo   Could not find SSForensic.exe next to this launcher.
    echo   Keep this .bat in the same folder as the tool.
    echo.
    pause
    exit /b 1
)

rem --- Runtime present: start the tool ---
start "" "%EXE%"
exit /b 0
