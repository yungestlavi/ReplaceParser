@echo off
setlocal enableextensions
title Replace Parser - Launcher

rem ============================================================
rem  Replace Parser launcher
rem  - Checks for the .NET 8 Desktop Runtime (x64)
rem  - If present: starts the tool
rem  - If missing: opens the official Microsoft download page
rem ============================================================

set "EXE=%~dp0SSForensic\bin\Release\net8.0-windows\win-x64\publish\SSForensic.exe"

rem If you place this .bat next to SSForensic.exe instead, use this line:
if not exist "%EXE%" set "EXE=%~dp0SSForensic.exe"

rem --- Check the installed .NET runtimes for a Microsoft.WindowsDesktop.App 8.x ---
set "HASNET="
for /f "delims=" %%R in ('dotnet --list-runtimes 2^>nul ^| findstr /i "Microsoft.WindowsDesktop.App 8."') do set "HASNET=1"

if not defined HASNET (
    echo.
    echo   The .NET 8 Desktop Runtime ^(x64^) is required and was not found.
    echo   Opening the download page in your browser...
    echo.
    start "" "https://dotnet.microsoft.com/en-us/download/dotnet/8.0/runtime?cid=getdotnetcore"
    echo   After installing it, just run this launcher again.
    echo.
    pause
    exit /b 1
)

if not exist "%EXE%" (
    echo.
    echo   Could not find SSForensic.exe next to this launcher.
    echo   Make sure the launcher is in the same folder as the tool.
    echo.
    pause
    exit /b 1
)

rem --- Runtime present: start the tool (no console window left behind) ---
start "" "%EXE%"
exit /b 0
