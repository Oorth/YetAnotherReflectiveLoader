@REM @REM cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /DEBUG /MAP
@REM @REM cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /DEBUG /MAP /DEF:main.def
@REM @REM cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /VERBOSE /DEBUG /MAP
@REM @REM cl /c /EHsc /GS- /Oy /Zi /FAs .\injection.cpp

@echo off
setlocal enabledelayedexpansion

cls
del main.pdb main.map main.ilk injection.obj main.obj injection.asm main.lib main.exp main.exe vc140.pdb suicide.obj 2>nul
cls

@REM Compile asm code
ml64.exe /c /Fo suicide.obj .\suicide.asm
if errorlevel 1 (
    @REM echo Compilation failed.
    goto :eof
)

@REM Compile C++ code
cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp .\suicide.obj /link /OUT:main.exe /DEBUG /MAP /INCREMENTAL:NO
if errorlevel 1 (
    @REM echo Compilation failed.
    goto :eof
)

@REM Check if notepad.exe is running, start if not
tasklist /FI "IMAGENAME eq notepad.exe" 2>NUL | find /I /N "notepad.exe" >NUL
if errorlevel 1 (
    @REM echo Starting notepad.exe...
    start /min "" notepad.exe
    @REM Give notepad a moment to start up properly
    timeout /t 0 /nobreak >nul
) else (
    @REM echo notepad.exe is already running.
)

@REM Get notepad.exe PID
set "notepadPID="
for /f "tokens=2 delims=," %%i in ('tasklist /nh /fi "imagename eq notepad.exe" /fo csv') do @set "notepadPID=%%~i"

@REM Trim quotes from PID if present
if defined notepadPID (
    set "notepadPID=!notepadPID:"=!"
)

if defined notepadPID (
    @REM echo Notepad PID: !notepadPID!

    @REM echo Starting x64dbg for PID !notepadPID!...
    start /min "" "C:\tools\x32 & x64 dbg\release\x64\x64dbg.exe" -p !notepadPID!

    @REM echo Checking for DbgView64.exe...
    tasklist /FI "IMAGENAME eq dbgview64.exe" 2>NUL | find /I "dbgview64.exe" > NUL
    
    if !ERRORLEVEL! equ 0 (
        @REM echo DbgView64.exe is already running.
    ) else (
        @REM echo DbgView64.exe is NOT running. Starting it...
        if exist "C:\Users\Arth\Desktop\SysinternalsSuite\dbgview64.exe" (
            start "" "C:\Users\Arth\Desktop\SysinternalsSuite\dbgview64.exe"
        ) else (
            @REM echo Error: DbgView64.exe not found at the specified path: "C:\Users\Arth\Desktop\SysinternalsSuite\dbgview64.exe"
        )
    )
    @REM --- End of DbgView64.exe check ---

) else (
    @REM echo Error: Could not find notepad.exe's PID.
)

endlocal
goto :eof