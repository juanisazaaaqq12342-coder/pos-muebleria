@echo off
setlocal EnableExtensions EnableDelayedExpansion
color 0F
title Compilando para Windows 8

echo ==========================================
echo        COMPILANDO POS PARA WINDOWS 8
echo ==========================================
echo.

if not exist "python39\python.exe" (
    echo [ERROR] No se encontro Python 3.9 local
    exit /b 1
)

echo [INFO] Creando entorno virtual Python 3.9...
python39\python.exe -m venv .venv_win8

echo [INFO] Instalando dependencias en Windows 8 Env...
.venv_win8\Scripts\python.exe -m pip install --upgrade pip
.venv_win8\Scripts\pip.exe install -r requirements.txt
.venv_win8\Scripts\pip.exe install pyinstaller==5.13.2

echo [INFO] Limpiando...
if exist "dist_win8" rmdir /s /q "dist_win8"
if exist "build" rmdir /s /q "build"

echo [INFO] Ejecutando PyInstaller...
.venv_win8\Scripts\pyinstaller.exe --name "POS_QBakano_Win8" --onedir --noconfirm app.py --distpath "dist_win8"

echo [INFO] Copiando archivos...
xcopy "templates" "dist_win8\POS_QBakano_Win8\templates\" /E /I /Y /Q
xcopy "static" "dist_win8\POS_QBakano_Win8\static\" /E /I /Y /Q
copy "cloudflared.exe" "dist_win8\POS_QBakano_Win8\" /Y >nul
copy "token.txt" "dist_win8\POS_QBakano_Win8\" /Y >nul

echo [INFO] Adaptando menu...
powershell -Command "(Get-Content 'pos_cloudflare.bat') -replace 'iniciar_sistema\.bat', 'POS_QBakano_Win8.exe' | Set-Content 'dist_win8\POS_QBakano_Win8\iniciar_sistema.bat'"

echo [OK] Compilacion para Windows 8 Finalizada.
