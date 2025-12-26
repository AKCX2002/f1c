@echo off
setlocal
set "SCRIPT_DIR=%~dp0"

REM Launch GUI (no console) - prefer pythonw/pyw; fallback to python with hidden window via start.
where pythonw >nul 2>&1
if not errorlevel 1 (
  pythonw "%SCRIPT_DIR%f1c_gui.py" %*
  exit /b 0
)
where pyw >nul 2>&1
if not errorlevel 1 (
  pyw "%SCRIPT_DIR%f1c_gui.py" %*
  exit /b 0
)
where python >nul 2>&1
if not errorlevel 1 (
  start "" /b python "%SCRIPT_DIR%f1c_gui.py" %*
  exit /b 0
)
where py >nul 2>&1
if not errorlevel 1 (
  start "" /b py -3 "%SCRIPT_DIR%f1c_gui.py" %*
  exit /b 0
)
echo Python not found. Please install Python and add it to PATH.
pause
