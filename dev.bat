@echo off
rem Prueba el juego en tu PC: arranca MySQL de XAMPP y un servidor PHP en http://localhost:8000
cd /d "%~dp0"
tasklist /FI "IMAGENAME eq mysqld.exe" | find /I "mysqld.exe" >nul || (
  echo Arrancando MySQL de XAMPP...
  start "MySQL" /min C:\xampp\mysql\bin\mysqld.exe --defaults-file=C:\xampp\mysql\bin\my.ini --standalone
  timeout /t 4 /nobreak >nul
)
start "" http://localhost:8000
echo Juego en http://localhost:8000  (cierra esta ventana o pulsa Ctrl+C para pararlo)
C:\xampp\php\php.exe -S localhost:8000 -t . dev\router.php
