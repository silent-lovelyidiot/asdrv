@echo off
@chcp 936
@cd /d %~dp0
@set ProjectDir=%CD%
@set LUA_DIR=%ProjectDir%\lua
@set LUA_SRC=%ProjectDir%\lua\src
@set GEN_DIR=%ProjectDir%\gen
@set TOOL_DIR=%ProjectDir%\tool
@set SRC=%ProjectDir%\source
@set OUT=%ProjectDir%\obj
@set PACKAGE=%ProjectDir%\package

@rmdir /s /q "%GEN_DIR%"
@rmdir /s /q "%OUT%"
@rmdir /s /q asdrv.package

@mkdir "%GEN_DIR%"
@mkdir asdrv.package

@"%TOOL_DIR%\lua-x64.exe" "%TOOL_DIR%\cc.lua" update_version true

@"C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe" vs_project\asdrv.sln /t:Rebuild /p:Configuration=Release,Platform=x64
@if NOT ERRORLEVEL 0 @goto end
@xcopy /y /e "%OUT%\Release\*" asdrv.package

@"C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe" vs_project\asdrv.sln /t:Rebuild /p:Configuration=Release,Platform=x86
@if NOT ERRORLEVEL 0 @goto end
@xcopy /y /e "%OUT%\Release\*" asdrv.package

@cd asdrv.package

@del /q lua*.exe
@del /q lua*.pdb

@mkdir pdb
@xcopy /y *.pdb pdb

@mkdir test
@xcopy /y asapp-*.exe test

@mkdir target
@xcopy /y aslauncher-*.exe target
@xcopy /y asdrv-*.sys target

@del /q *

:end
@pause
