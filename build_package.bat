@echo off
@cd /d %~dp0
@set ProjectDir=%CD%
@set LUA_DIR=%ProjectDir%\lua
@set LUA_SRC=%ProjectDir%\lua\src
@set GEN_DIR=%ProjectDir%\gen
@set TOOL_DIR=%ProjectDir%\tool
@set SRC=%ProjectDir%\source
@set OUT=%ProjectDir%\obj
@set PACKAGE=%ProjectDir%\package

@del /s /q "%GEN_DIR%\update_config_*.dat"
@rmdir /s /q "%GEN_DIR%"
@rmdir /s /q "%GEN_DIR%"
@mkdir "%GEN_DIR%"

@"%TOOL_DIR%\lua-x64.exe" "%TOOL_DIR%\cc.lua" update_version false

@"%TOOL_DIR%\lua-x64.exe" "%TOOL_DIR%\cc.lua" pre_compile "%TOOL_DIR%" "%SRC%" "%GEN_DIR%" x64 Package
@"%TOOL_DIR%\lua-x86.exe" "%TOOL_DIR%\cc.lua" pre_compile "%TOOL_DIR%" "%SRC%" "%GEN_DIR%" x86 Package

@set /p bn= < "%TOOL_DIR%\build_number"
@"%TOOL_DIR%\lua-x64.exe" "%TOOL_DIR%\cc.lua" gen_package "%GEN_DIR%\update_config_%bn%.dat"
:end
@pause
