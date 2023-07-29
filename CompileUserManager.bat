@echo off
cls
echo Compiling User Manager ...
gcc UserManager.c -o UserManager -Llib -lcryptography
echo Done