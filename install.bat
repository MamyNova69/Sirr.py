@echo off
setlocal

echo Checking Python and pip availability...

:: Check for Python
where python >nul 2>&1
if errorlevel 1 (
    echo Python is not found in PATH. Please install Python first.
    pause
    exit /b 1
)

:: Check for pip
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo pip not found. Attempting to ensure pip is available...
    python -m ensurepip
)

echo Installing cryptography from local .whl file...

:: Install the .whl file from the current folder
python -m pip install cryptography-45.0.3-cp311-abi3-win_amd64.whl --no-index --find-links=.

if errorlevel 1 (
    echo Failed to install the package.
    pause
    exit /b 1
)

echo Installation completed successfully.
pause
endlocal