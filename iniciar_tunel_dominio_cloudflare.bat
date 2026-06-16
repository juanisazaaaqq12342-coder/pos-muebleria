@echo off
cd /d "%~dp0"
call "%~dp0pos_cloudflare.bat" --domain-tunnel
