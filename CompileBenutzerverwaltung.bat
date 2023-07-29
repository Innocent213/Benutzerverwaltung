@echo off
cls
echo Compiling benutzerverwaltung...
gcc Benutzerverwaltung.c -o Benutzerverwaltung -Llib -lcryptography
echo Done