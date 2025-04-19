@echo off
setlocal enabledelayedexpansion

:: =============================================================
:: Anubis EDR Build and Installation Script
:: =============================================================
echo ===================================================
echo Anubis EDR Build and Installation
echo ==================================================


:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Administrator privileges required.
    echo Please run this script as administrator.
    pause
    exit /b 1
)