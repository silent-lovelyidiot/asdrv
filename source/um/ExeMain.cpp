#include <Windows.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <Softpub.h>

#include "lua.hpp"
#include "constexpr.h"
#include "lua_ext_functions.h"

#include "macro.h"
#include "log.h"

#ifdef DBG
#define _SCRT_STARTUP_MAIN
#else
#define _SCRT_STARTUP_WINMAIN
#endif

int load_internal_lua_script(lua_State* L, int index);

int lua_panic(lua_State* L);

#if defined _SCRT_STARTUP_WINMAIN
int CALLBACK WinMain(
  _In_ HINSTANCE,
  _In_ HINSTANCE,
  _In_ LPSTR,
  _In_ int) {
#elif defined _SCRT_STARTUP_MAIN
int __cdecl main(int, char** ) {
#endif
  auto L = luaL_newstate();
  int n = 0;
  __try {
    lua_atpanic(L, lua_panic);
    luaL_openlibs(L);
    n = load_internal_lua_script(L, INTERNAL_LUA_SCRIPT_LAUNCHER);

    auto cmdline = GetCommandLineW();
    lua_pushlstring(L, (const char*)cmdline, wcslen(cmdline) * 2 + 2);
    Log("aslauncher running...");
    PVOID OldValue;
    BOOL bl = Wow64DisableWow64FsRedirection(&OldValue);
    Log("aslauncher disable wow64 %d", bl);
    LUA_CALL(L, n + 1, 1, 0);
    Log("aslauncher call end");
    if (bl) Wow64RevertWow64FsRedirection(OldValue);
    n = (int)lua_tointeger(L, -1);
    Log("aslauncher result %08x", n);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Log("aslauncher error");
  }
  Log("aslauncher finish");
  lua_close(L);
  return n;
}