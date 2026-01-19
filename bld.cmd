@echo off
set LOGFILE=%~1
if "%LOGFILE%"=="" set LOGFILE=log.txt
cargo build 1>"%LOGFILE%" 2>&1
