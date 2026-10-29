@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Creating a local Python environment...
  py -3 -m venv .venv
  if errorlevel 1 python -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
  echo Could not create a virtual environment. Install Python 3.10+ and try again.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Check your internet connection and requirements.txt.
  pause
  exit /b 1
)
echo.
echo Trace Mind will open at http://127.0.0.1:8000
start "" http://127.0.0.1:8000
cd /d "%~dp0backend"
"..\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
