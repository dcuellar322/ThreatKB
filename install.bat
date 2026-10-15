@echo off
py -3.14 -m venv .venv
if errorlevel 1 exit /b 1
.venv\Scripts\python -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
.venv\Scripts\flask --app app db upgrade
if errorlevel 1 exit /b 1
