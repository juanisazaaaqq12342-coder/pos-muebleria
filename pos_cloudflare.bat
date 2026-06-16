@echo off
setlocal EnableExtensions EnableDelayedExpansion
color 0F
title POS Cloudflare - Menu Principal

cd /d "%~dp0"
set "POS_HOST=127.0.0.1"
set "POS_PORT=5001"
set "POS_URL=http://%POS_HOST%:%POS_PORT%"
set "TOKEN_FILE=%~dp0token.txt"
set "MAX_WAIT=45"
set "MAX_RETRIES=12"
set "WAIT_SECONDS=8"

if "%~1"=="--temp-tunnel" goto :temp_tunnel
if "%~1"=="--domain-tunnel" goto :domain_tunnel

:menu
cls
color 0F
echo ==========================================
echo       POS + CLOUDFLARE - MENU UNICO
echo ==========================================
echo.
echo  1. Iniciar POS local
echo  2. Iniciar POS + tunel temporal variable
echo  3. Configurar token para dominio fijo
echo  4. Iniciar POS + dominio fijo
echo  5. Instalar tunel como servicio de Windows
echo  6. Verificar requisitos
echo  0. Salir
echo.
echo No pegues rutas aqui. Solo presiona una tecla del menu.
echo.
choice /c 1234560 /n /m "Selecciona una opcion: "
set "OPCION=%ERRORLEVEL%"

if "%OPCION%"=="1" goto :start_pos_only
if "%OPCION%"=="2" goto :start_temp
if "%OPCION%"=="3" goto :save_token
if "%OPCION%"=="4" goto :start_domain
if "%OPCION%"=="5" goto :install_service
if "%OPCION%"=="6" goto :check_requirements
if "%OPCION%"=="7" exit /b 0
goto :menu

:start_pos_only
if not exist "%~dp0iniciar_sistema.bat" (
    color 0C
    echo [ERROR] No se encontro iniciar_sistema.bat
    goto :pause_menu
)
start "POS Server" cmd /k ""%~dp0iniciar_sistema.bat""
echo.
echo [OK] POS iniciado en una ventana nueva.
echo Acceso local: %POS_URL%
goto :pause_menu

:start_temp
if not exist "%~dp0iniciar_sistema.bat" (
    color 0C
    echo [ERROR] No se encontro iniciar_sistema.bat
    goto :pause_menu
)
where cloudflared >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] No se encontro cloudflared.
    echo [TIP] Instalar:
    echo       winget install Cloudflare.cloudflared
    goto :pause_menu
)
set "NEXT_TUNNEL=temp"
goto :open_pos_and_wait

:start_domain
if not exist "%~dp0iniciar_sistema.bat" (
    color 0C
    echo [ERROR] No se encontro iniciar_sistema.bat
    goto :pause_menu
)
where cloudflared >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] No se encontro cloudflared.
    echo [TIP] Instalar:
    echo       winget install Cloudflare.cloudflared
    goto :pause_menu
)
if not exist "%TOKEN_FILE%" (
    color 0E
    echo [WARN] Falta configurar el token de dominio fijo.
    echo Ejecuta la opcion 3 de este menu.
    goto :pause_menu
)
set "NEXT_TUNNEL=domain"
goto :open_pos_and_wait

:save_token
where cloudflared >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] No se encontro cloudflared.
    echo [TIP] Instalar:
    echo       winget install Cloudflare.cloudflared
    goto :pause_menu
)
:: Se eliminó la creación de carpeta instance
echo.
echo Pega el token del tunel creado en Cloudflare.
echo Normalmente empieza por: eyJ
echo.
set /p CF_TUNNEL_TOKEN=Token: 
if "%CF_TUNNEL_TOKEN%"=="" (
    color 0C
    echo [ERROR] El token no puede estar vacio.
    goto :pause_menu
)
> "%TOKEN_FILE%" echo %CF_TUNNEL_TOKEN%
:: attrib +h "%TOKEN_FILE%" >nul 2>&1
echo.
echo [OK] Token guardado en:
echo      %TOKEN_FILE%
goto :pause_menu

:install_service
where cloudflared >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] No se encontro cloudflared.
    echo [TIP] Instalar:
    echo       winget install Cloudflare.cloudflared
    goto :pause_menu
)
if not exist "%TOKEN_FILE%" (
    color 0E
    echo [WARN] Falta configurar el token de dominio fijo.
    echo Ejecuta la opcion 3 de este menu.
    goto :pause_menu
)
for /f "usebackq delims=" %%T in ("%TOKEN_FILE%") do set "CF_TUNNEL_TOKEN=%%T"
echo.
echo IMPORTANTE: esta opcion debe ejecutarse como Administrador.
echo.
cloudflared service install %CF_TUNNEL_TOKEN%
if errorlevel 1 (
    color 0C
    echo.
    echo [ERROR] No se pudo instalar el servicio.
    echo [TIP] Abre CMD como Administrador y ejecuta este menu de nuevo.
    goto :pause_menu
)
echo.
echo [OK] Servicio instalado.
echo Verifica con: sc query cloudflared
goto :pause_menu

:check_requirements
echo.
if exist "%~dp0iniciar_sistema.bat" (
    echo [OK] iniciar_sistema.bat encontrado.
) else (
    echo [ERROR] No se encontro iniciar_sistema.bat
)
where cloudflared >nul 2>&1
if errorlevel 1 (
    echo [ERROR] No se encontro cloudflared.
    echo [TIP] winget install Cloudflare.cloudflared
) else (
    echo [OK] cloudflared disponible.
)
if exist "%TOKEN_FILE%" (
    echo [OK] Token de dominio fijo encontrado.
) else (
    echo [INFO] Token de dominio fijo no configurado.
)
echo [INFO] Servicio local esperado: %POS_URL%
goto :pause_menu

:open_pos_and_wait
start "POS Server" cmd /k ""%~dp0iniciar_sistema.bat""
echo [INFO] Esperando a que el POS responda en %POS_URL% ...
set /a WAITED=0
:wait_pos
powershell -NoProfile -ExecutionPolicy Bypass -Command "$c=New-Object Net.Sockets.TcpClient; try { $iar=$c.BeginConnect('%POS_HOST%',%POS_PORT%,$null,$null); if(-not $iar.AsyncWaitHandle.WaitOne(1000,$false)){ exit 1 }; $c.EndConnect($iar); exit 0 } catch { exit 1 } finally { $c.Close() }" >nul 2>&1
if errorlevel 1 (
    set /a WAITED+=1
    if !WAITED! GEQ %MAX_WAIT% (
        color 0C
        echo [ERROR] El POS no respondio despues de %MAX_WAIT% segundos.
        echo [TIP] Revisa la ventana "POS Server" para ver el error.
        goto :pause_menu
    )
    timeout /t 1 /nobreak >nul
    goto :wait_pos
)
echo [OK] POS activo en %POS_URL%
if "%NEXT_TUNNEL%"=="temp" (
    start "Cloudflare Tunnel Temporal" cmd /k ""%~f0" --temp-tunnel"
    echo.
    echo [OK] POS + tunel temporal iniciados.
    echo El link variable aparece en la ventana "Cloudflare Tunnel Temporal".
    goto :pause_menu
)
if "%NEXT_TUNNEL%"=="domain" (
    start "Cloudflare Tunnel Dominio" cmd /k ""%~f0" --domain-tunnel"
    echo.
    echo [OK] POS + tunel de dominio fijo iniciados.
    echo Abre el dominio configurado en Cloudflare.
    goto :pause_menu
)
goto :pause_menu

:temp_tunnel
where cloudflared >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] No se encontro cloudflared.
    echo [TIP] Instalar:
    echo       winget install Cloudflare.cloudflared
    pause
    exit /b 1
)
set /a ATTEMPT=0
:retry_temp
set /a ATTEMPT+=1
echo [INFO] Intento !ATTEMPT! de %MAX_RETRIES%...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$c=New-Object Net.Sockets.TcpClient; try { $iar=$c.BeginConnect('%POS_HOST%',%POS_PORT%,$null,$null); if(-not $iar.AsyncWaitHandle.WaitOne(1500,$false)){ exit 1 }; $c.EndConnect($iar); exit 0 } catch { exit 1 } finally { $c.Close() }" >nul 2>&1
if errorlevel 1 (
    color 0E
    echo [WARN] El POS aun no responde en %POS_URL%.
    if !ATTEMPT! LSS %MAX_RETRIES% (
        timeout /t %WAIT_SECONDS% /nobreak >nul
        color 0F
        goto :retry_temp
    )
    color 0C
    echo [ERROR] El servidor POS no esta activo.
    pause
    exit /b 1
)
cloudflared tunnel --url %POS_URL% --loglevel info --no-autoupdate
if errorlevel 1 (
    color 0E
    echo [WARN] Cloudflare no entrego el link temporal. Codigo %ERRORLEVEL%.
    if !ATTEMPT! LSS %MAX_RETRIES% (
        timeout /t %WAIT_SECONDS% /nobreak >nul
        color 0F
        goto :retry_temp
    )
    color 0C
    echo [ERROR] No fue posible crear el tunel temporal.
    pause
    exit /b 1
)
exit /b 0

:domain_tunnel
where cloudflared >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] No se encontro cloudflared.
    echo [TIP] Instalar:
    echo       winget install Cloudflare.cloudflared
    pause
    exit /b 1
)
if not exist "%TOKEN_FILE%" (
    color 0E
    echo [WARN] Falta configurar el token de dominio fijo.
    echo Ejecuta la opcion 3 de este menu.
    pause
    exit /b 1
)
for /f "usebackq delims=" %%T in ("%TOKEN_FILE%") do set "CF_TUNNEL_TOKEN=%%T"
if "%CF_TUNNEL_TOKEN%"=="" (
    color 0C
    echo [ERROR] El archivo de token esta vacio.
    pause
    exit /b 1
)
cloudflared tunnel --no-autoupdate --loglevel info run --token %CF_TUNNEL_TOKEN%
if errorlevel 1 (
    color 0C
    echo.
    echo [ERROR] El tunel se detuvo con codigo %ERRORLEVEL%.
    pause
    exit /b %ERRORLEVEL%
)
exit /b 0

:pause_menu
echo.
pause
goto :menu
