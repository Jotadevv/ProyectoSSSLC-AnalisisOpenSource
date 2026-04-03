@echo off
cd /d "%~dp0"
echo Verificando npm...
npm --version >nul 2>&1
if errorlevel 1 (
    echo Error: npm no esta instalado
    echo Por favor instala Node.js y npm desde https://nodejs.org/
    pause
    exit /b 1
)

echo Ejecutando npm audit...
npm audit --json > npm_output.txt 2>&1

echo Auditoria completada
echo Resultados guardados en npm_output.txt
echo Ejecuta python npm_audit.py para procesar los resultados
pause
