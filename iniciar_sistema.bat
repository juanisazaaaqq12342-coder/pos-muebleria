@echo off
setlocal EnableExtensions EnableDelayedExpansion
color 0F
title POS SYSTEM - Q'BAKANO
echo ==========================================
echo      INICIANDO SISTEMA POS Q'BAKANO
echo ==========================================
echo.
echo [INFO] Iniciando servidor...
echo [INFO] Por favor, NO cierre esta ventana negra.
echo.
echo -> Acceda en este PC: http://localhost:5001
echo.

cd /d "%~dp0"

echo [INFO] Cerrando instancias previas del POS en puerto 5001...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:":5001 .*LISTENING"') do (
    taskkill /PID %%P /F >nul 2>&1
)

echo [INFO] Limpiando procesos Python antiguos de este proyecto...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$root=(Get-Location).Path; $procs=Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -like '*app.py*' -and $_.CommandLine -like ('*' + $root + '*') }; foreach($p in $procs){ try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch {} }" >nul 2>&1
timeout /t 1 /nobreak >nul

:: Forzar ejecución estable sin hot reload para no perder formularios en POS.
set "POS_DEBUG=0"
set "POS_HOT_RELOAD=0"

set "PY_CMD="
set "PY_ARGS="

:: 1) Preferir entorno virtual local
if exist ".venv\Scripts\python.exe" (
    set "PY_CMD=.venv\Scripts\python.exe"
)

:: 2) Buscar python en PATH
if not defined PY_CMD (
    where python >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PY_CMD=python"
    )
)

:: 3) Buscar py launcher en PATH
if not defined PY_CMD (
    where py >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PY_CMD=py"
        set "PY_ARGS=-3"
    )
)

:: 4) Buscar instalaciones comunes de Python en Windows
if not defined PY_CMD (
    for %%P in (
        "%LocalAppData%\Programs\Python\Python314\python.exe"
        "%LocalAppData%\Programs\Python\Python313\python.exe"
        "%LocalAppData%\Programs\Python\Python312\python.exe"
        "%ProgramFiles%\Python314\python.exe"
        "%ProgramFiles%\Python313\python.exe"
        "%ProgramFiles%\Python312\python.exe"
    ) do (
        if exist %%~P (
            set "PY_CMD=%%~P"
            goto :python_found
        )
    )
)

:python_found
if not defined PY_CMD (
    color 0C
    echo [ERROR] No se encontro 'python' ni 'py' en el sistema.
    echo [ERROR] Instale Python 3.12+ y marque "Add Python to PATH".
    echo [TIP] Tambien puede usar: winget install Python.Python.3.12
    pause
    exit /b 1
)

echo [INFO] Usando Python: %PY_CMD% %PY_ARGS%

:: Crear entorno virtual local si no existe
if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Creando entorno virtual .venv...
    "%PY_CMD%" %PY_ARGS% -m venv .venv
    if !ERRORLEVEL! NEQ 0 (
        color 0C
        echo [ERROR] No fue posible crear el entorno virtual.
        echo [TIP] Verifique que Python incluya el modulo venv.
        pause
        exit /b 1
    )
)

set "PY_CMD=.venv\Scripts\python.exe"
set "PY_ARGS="
echo [INFO] Entorno Python activo: %PY_CMD%

:: Verificar dependencias criticas e instalar si faltan
"%PY_CMD%" -c "import flask, flask_sqlalchemy, sqlalchemy, fpdf" >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    echo [INFO] Instalando dependencias...
    "%PY_CMD%" -m pip install --upgrade pip
    if exist "requirements.txt" (
        "%PY_CMD%" -m pip install -r requirements.txt
    ) else (
        "%PY_CMD%" -m pip install Flask Flask-SQLAlchemy SQLAlchemy fpdf2 Werkzeug
    )
    if !ERRORLEVEL! NEQ 0 (
        color 0C
        echo [ERROR] No se pudieron instalar las dependencias.
        echo [TIP] Revise su conexion a internet o permisos de pip.
        pause
        exit /b 1
    )
)

"%PY_CMD%" "app.py"

if %ERRORLEVEL% NEQ 0 (
    color 0C
    echo.
    echo [ERROR] El sistema se detuvo con codigo %ERRORLEVEL%.
    echo [TIP] Si faltan librerias, instale dependencias y reinicie.
    pause
    exit /b %ERRORLEVEL%
)

endlocal
