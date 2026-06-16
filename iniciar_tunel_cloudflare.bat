@echo off
cd /d "%~dp0"
call "%~dp0pos_cloudflare.bat" --temp-tunnel
