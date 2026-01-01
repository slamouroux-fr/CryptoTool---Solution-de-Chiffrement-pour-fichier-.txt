@echo off
echo Installing dependencies...
pip install -r requirements.txt
echo Building executable...
pyinstaller --noconfirm --onefile --windowed --collect-all customtkinter --name "SecureCryptPro" main.py
echo Build complete. Executable is in the 'dist' folder.
pause
