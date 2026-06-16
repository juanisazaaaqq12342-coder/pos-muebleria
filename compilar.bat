@echo off
setlocal EnableExtensions EnableDelayedExpansion
color 0F
title Compilando Sistema POS

echo ==========================================
echo        COMPILANDO SISTEMA POS
echo ==========================================
echo.

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] No se encontro el entorno virtual .venv
    pause
    exit /b 1
)

echo [INFO] Activando entorno virtual...
call .venv\Scripts\activate.bat

echo [INFO] Instalando PyInstaller si no existe...
pip install pyinstaller

echo [INFO] Eliminando compilaciones anteriores...
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"
if exist "POS_QBakano.spec" del /q "POS_QBakano.spec"

echo [INFO] Ejecutando PyInstaller...
pyinstaller --name "POS_QBakano_Server" --onedir --noconfirm app.py

echo [INFO] Copiando archivos y carpetas necesarias a la carpeta compilada...
xcopy "templates" "dist\POS_QBakano_Server\templates\" /E /I /Y /Q
xcopy "static" "dist\POS_QBakano_Server\static\" /E /I /Y /Q
copy "cloudflared.exe" "dist\POS_QBakano_Server\" /Y >nul
copy "token.txt" "dist\POS_QBakano_Server\" /Y >nul

echo [INFO] Adaptando el menu para el sistema compilado...
powershell -Command "(Get-Content 'pos_cloudflare.bat') -replace 'iniciar_sistema\.bat', 'POS_QBakano_Server.exe' | Set-Content 'dist\POS_QBakano_Server\iniciar_sistema.bat'"

echo.
echo ==========================================
echo [OK] Compilacion completada con exito.
echo.
echo Encontraras tu sistema compilado en la carpeta:
echo.
echo   dist\POS_QBakano_Server
echo.
echo Esta es la carpeta que debes copiar y entregar a tu cliente.
echo Al ejecutar "iniciar_sistema.bat" en esa carpeta, vera el menu completo.
echo ==========================================
