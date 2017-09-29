Rem @echo off
Rem makeall.bat
Rem Remake all cryptographic programs
for %%i in (*.mak) do nmake /f %%i all
del *.obj
del *.map
del *.lrf
