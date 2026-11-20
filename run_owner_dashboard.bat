@echo off
setlocal
cd /d "%~dp0"
if not defined OWNER_PORT set "OWNER_PORT=5050"
if not defined OWNER_INITIAL_PASSWORD (
  echo First run: set an owner password at least 12 characters long.
  set /p "OWNER_INITIAL_PASSWORD=Owner password: "
)
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" owner_app.py
) else (
  python owner_app.py
)
pause
endlocal
