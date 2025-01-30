@echo off
setlocal enabledelayedexpansion

if "%1"=="x86" (
    set ARCH=x86
) else (
    set ARCH=x64
)

if not exist "bin\%ARCH%" mkdir "bin\%ARCH%"

set CFLAGS=/nologo /W4 /O2 /GS- /Gs999999 /DNDEBUG

set WFLAGS=/wd4005 /wd4100

set INCLUDES=/I"h"

cl %CFLAGS% %WFLAGS% %INCLUDES% /Fe"bin\%ARCH%\ForceBindIP.exe" c\ForceBindIP.c /link /SUBSYSTEM:WINDOWS user32.lib iphlpapi.lib ws2_32.lib

cl %CFLAGS% %WFLAGS% %INCLUDES% /Fe"bin\%ARCH%\BindIP.dll" /LD c\BindIPDLL.c /link ws2_32.lib user32.lib

del *.obj *.lib *.exp