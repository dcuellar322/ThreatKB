@echo off
rem The content engine and worker require POSIX locking/process behavior.
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo Install WSL2 and Python 3.14/uv, then run sh install.sh inside WSL.
  exit /b 1
)
wsl.exe --exec sh ./install.sh
exit /b %errorlevel%
