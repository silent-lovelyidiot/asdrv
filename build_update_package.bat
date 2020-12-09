@echo off
@chcp 936
@pushd %CD%
@cd /d %~dp0
@set ProjectDir=%CD%
@set LUA_DIR=%ProjectDir%\lua
@set LUA_SRC=%ProjectDir%\lua\src
@set GEN_DIR=%ProjectDir%\gen
@set TOOL_DIR=%ProjectDir%\tool
@set SRC=%ProjectDir%\source
@set OUT=%ProjectDir%\obj
@set PACKAGE=%ProjectDir%\package

@popd

::@makecab asdrv-x64.sys
::@makecab asdrv-x86.sys
::@makecab aslauncher-x64.exe
::@makecab aslauncher-x86.exe


@"%TOOL_DIR%\lua-x64.exe" "%TOOL_DIR%\cc.lua" gen_update_package asdrv-x64.sys asdrv-x64.sys._patch
@"%TOOL_DIR%\lua-x64.exe" "%TOOL_DIR%\cc.lua" gen_update_package asdrv-x86.sys asdrv-x86.sys._patch
@"%TOOL_DIR%\lua-x64.exe" "%TOOL_DIR%\cc.lua" gen_update_package aslauncher-x64.exe aslauncher-x64.exe._patch
@"%TOOL_DIR%\lua-x64.exe" "%TOOL_DIR%\cc.lua" gen_update_package aslauncher-x86.exe aslauncher-x86.exe._patch

@pause
