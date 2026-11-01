@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"
if exist "venv\Scripts\activate.bat" if not exist ".venv\Scripts\activate.bat" call "venv\Scripts\activate.bat"
python -m uvicorn backend.main:app --reload