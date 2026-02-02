@echo off
title CLONADISCOS - Clonador de Discos
color 1F
echo.
echo   ╔═══════════════════════════════════════════════════════════════╗
echo   ║            CLONADISCOS - CLONADOR DE DISCOS                   ║
echo   ╚═══════════════════════════════════════════════════════════════╝
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   Solicitando permisos de administrador...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0CLONADISCOS.ps1"
