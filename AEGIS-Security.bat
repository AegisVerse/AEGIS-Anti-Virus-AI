@echo off
title AEGIS AI Security Launcher
cd /d "%~dp0"
set "ELECTRON_RUN_AS_NODE="

set "PORTABLE_EXE=release\electron\AEGIS AI Security 0.1.0.exe"
set "UNPACKED_EXE=release\electron\win-unpacked\AEGIS AI Security.exe"

if exist "%UNPACKED_EXE%" (
    start "" "%UNPACKED_EXE%"
    exit /b 0
)

if exist "%PORTABLE_EXE%" (
    start "" "%PORTABLE_EXE%"
    exit /b 0
)

powershell.exe -ExecutionPolicy Bypass -File "scripts\open-ui.ps1"
