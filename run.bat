@echo off
title Attendance Management System
color 0A

echo ============================================
echo   Attendance Management System
echo ============================================
echo.

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo [1/3] Tao virtual environment...
    py -m venv venv
    if errorlevel 1 (
        echo Loi: Khong tim thay Python. Vui long cai Python 3.9+
        pause
        exit /b 1
    )
)

REM Activate and install deps
echo [2/3] Cai dat thu vien...
call venv\Scripts\activate.bat
pip install -r requirements.txt -q --disable-pip-version-check

echo [3/3] Khoi dong server...
echo.
echo ============================================
echo   Mo trinh duyet: http://localhost:5000
echo   Nhan Ctrl+C de dung
echo ============================================
echo.

python app.py
pause
