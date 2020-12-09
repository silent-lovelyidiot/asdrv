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
@mkdir "%GEN_DIR%"
@cd vs_project
start asdrv.sln