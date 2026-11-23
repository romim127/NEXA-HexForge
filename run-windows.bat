@echo off
REM NEXA-HexForge Local Console - Windows Launcher
REM Starts the FastAPI server and opens the web interface

setlocal enabledelayedexpansion

REM Configuration
set DEFAULT_PORT=8765
set DEFAULT_HOST=127.0.0.1
set PROJECT_ROOT=%~dp0
set VENV_DIR=%PROJECT_ROOT%.venv
set PYTHON=%VENV_DIR%\Scripts\python.exe
set UVICORN=%VENV_DIR%\Scripts\uvicorn.exe
set SERVER_MODULE=hexforge.server.main:app

REM Colors (using ANSI escape codes for Windows 10+)
for /f %%a in ('echo prompt $E ^| cmd') do set ESC=%%a
set RED=%ESC%[0;31m
set GREEN=%ESC%[0;32m
set YELLOW=%ESC%[1;33m
set BLUE=%ESC%[0;34m
set CYAN=%ESC%[0;36m
set NC=%ESC%[0m

REM Print banner
echo %CYAN%
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    NEXA-HexForge Local Console                ║
echo ║              Binary Intelligence · Forensic Analysis         ║
echo ╚══════════════════════════════════════════════════════════════╝
echo %NC%

REM Parse arguments
set PORT=%DEFAULT_PORT%
set HOST=%DEFAULT_HOST%
set OPEN_BROWSER=true

:parse_args
if "%~1"=="" goto :check_venv
set ARG=%~1
if "%ARG%"=="--no-browser" (
    set OPEN_BROWSER=false
) else if "%ARG:~0,7%"=="--port=" (
    set PORT=%ARG:~7%
) else if "%ARG:~0,6%"=="--host=" (
    set HOST=%ARG:~6%
) else if "%ARG%"=="--help" goto :show_help
if "%ARG:~0,1%"=="-" if not "%ARG%"=="--no-browser" (
    if not "%ARG:~0,7%"=="--port=" if not "%ARG:~0,7%"=="--host=" (
        echo Unknown option: %ARG%
        exit /b 1
    )
)
shift
goto :parse_args

:show_help
echo Usage: %~nx0 [PORT] [HOST] [OPTIONS]
echo.
echo Options:
echo   --port=PORT       Server port (default: %DEFAULT_PORT%)
echo   --host=HOST       Server host (default: %DEFAULT_HOST%)
echo   --no-browser      Don't open browser automatically
echo   --help            Show this help
exit /b 0

:check_venv
if not "%HOST%"=="127.0.0.1" if not "%HOST%"=="localhost" (
    echo Only loopback hosts are supported
    exit /b 1
)
REM Check if virtual environment exists
if not exist "%PYTHON%" (
    echo %YELLOW%Virtual environment not found. Creating...%NC%
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo %RED%Failed to create virtual environment. Is Python installed?%NC%
        pause
        exit /b 1
    )
    "%PYTHON%" -m pip install --upgrade pip
    "%PYTHON%" -m pip install -e "%PROJECT_ROOT%"
    "%PYTHON%" -m pip install fastapi uvicorn[standard] python-multipart
)

REM Find available port
:find_port
netstat -an | findstr /r /c:"^  TCP.*:%PORT% " >nul
if %ERRORLEVEL% equ 0 (
    echo %YELLOW%Port %PORT% in use, trying next...%NC%
    set /a PORT+=1
    goto :find_port
)

echo %GREEN%Starting server on %HOST%:%PORT%%NC%
echo %BLUE%Project root: %PROJECT_ROOT%%NC%
echo.

cd /d "%PROJECT_ROOT%"

REM Open browser after delay
if "%OPEN_BROWSER%"=="true" (
    start /b cmd /c "timeout /t 2 /nobreak >nul && start http://%HOST%:%PORT%"
)

REM Run uvicorn
"%UVICORN%" %SERVER_MODULE% --host %HOST% --port %PORT% --log-level warning --no-access-log

REM Pause on error
if %ERRORLEVEL% neq 0 (
    echo.
    echo %RED%Server exited with error code %ERRORLEVEL%%NC%
    pause
)