@echo off
SETLOCAL

echo Starting AgriGuard...
cd /d %~dp0
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
) else (
    echo Virtual environment not found. Create one with install.bat first.
    pause
    exit /b 1
)

python app.py
