@echo off
REM 1.0 Get the name of the directory containing the current project
for %%i in ("%cd%") do set name=%%~ni
echo %name%

REM Delete selected files under Project
cd .\Project

del /Q /S .\Objects\*
del /Q /S .\Listings\*
del /Q /S .\DebugConfig\*

del /Q /S *.uvguix.*
REM del /Q /S *.uvoptx
del /Q /S *.scvd

cd ..


REM pause