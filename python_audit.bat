@echo off
cd /d "%~dp0"
python3 -m pip install pip-audit
python3 -m pip_audit > python_output.txt
pause