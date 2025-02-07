@echo off
setlocal enabledelayedexpansion

if not exist "bin\x86" mkdir "bin\x86"
if not exist "bin\x64" mkdir "bin\x64"

echo Building x64...
cl.exe /D "USE_CRT" /D "UNICODE" /D "_UNICODE" ^
    /nologo /O2 /W4  /MD /GS- /GR- /EHs-c- ^
    /Fo"bin\x64\\" /Fe"bin\x64\ForceBindIP64.exe" ^
    src\fbi.c /link /SUBSYSTEM:WINDOWS ^
    /MACHINE:X64 kernel32.lib user32.lib ws2_32.lib iphlpapi.lib

echo Building x86...
cl.exe /D "USE_CRT" /D "UNICODE" /D "_UNICODE" ^
    /nologo /O2 /W4  /MD /GS- /GR- /EHs-c- ^
    /Fo"bin\x86\\" /Fe"bin\x86\ForceBindIP32.exe" ^
    src\fbi.c /link /SUBSYSTEM:WINDOWS ^
    /MACHINE:X86 kernel32.lib user32.lib ws2_32.lib iphlpapi.lib

echo Building x64 DLL...
cl.exe /D "USE_CRT" /D "UNICODE" /D "_UNICODE" ^
    /nologo /O2 /W4  /MD /GS- /GR- /EHs-c- /LD ^
    /Fo"bin\x64\\" /Fe"bin\x64\BindIP64.dll" ^
    src\dll.c /link /SUBSYSTEM:WINDOWS ^
    /MACHINE:X64 kernel32.lib user32.lib ws2_32.lib

echo Building x86 DLL...
cl.exe /D "USE_CRT" /D "UNICODE" /D "_UNICODE" ^
    /nologo /O2 /W4  /MD /GS- /GR- /EHs-c- /LD ^
    /Fo"bin\x86\\" /Fe"bin\x86\BindIP32.dll" ^
    src\dll.c /link /SUBSYSTEM:WINDOWS ^
    /MACHINE:X86 kernel32.lib user32.lib ws2_32.lib

if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo Build completed successfully!