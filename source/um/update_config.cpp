#include <Windows.h>

#include "macro.h"

#include "lua.hpp"
#include "constexpr.h"

#include "log.h"

#include "lua_ext_functions.h"

#include <crtdbg.h>

#include <setjmp.h>
EXTERN_C extern jmp_buf _jmp_buf;
EXTERN_C int lua_call_protect_env(lua_State* L, int n, int r , int f);

int lua_panic(lua_State* L) {
  L;
#ifdef DBG
  const char* err = lua_tostring(L, -1);
  if (err) {
    OutputDebugStringA("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    OutputDebugStringA(err);
    OutputDebugStringA("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  }
  _ASSERT(0);
#endif // DBG

  Log("RaiseException e0000001");
  // longjmp(_jmp_buf, 1);
  RaiseException(0xe0000001, 0, 0, nullptr);
  return 0;
}

int load_internal_lua_script(lua_State* L, int index);

ULONG UpdateConfigInternal(PVOID BaseAddress, ULONG Size) {
  Log("BaseAddress %p, Size %d", BaseAddress, Size);
  auto L = luaL_newstate();
  if (!L) return 0;
  __try {
    lua_atpanic(L, lua_panic);
    luaL_openlibs(L);
#ifdef DBG
    wchar_t Name[MAX_PATH];
    GetModuleFileNameW(nullptr, Name, MAX_PATH);
    Log("Current Process Name: %s", Name);
#endif // DBG
    int n = load_internal_lua_script(L, INTERNAL_LUA_SCRIPT_UPDATE);
    lua_pushlightuserdata(L, BaseAddress);
    lua_pushinteger(L, Size);

    Log("update config start");
    // LUA_CALL(L, n + 2, 1, 0);
    lua_call_protect_env(L, n + 2, 1, 0);
    Log("update config final");

    Size = (ULONG)lua_tointeger(L, -1);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Log("UpdateConfigInternal error");
    _ASSERT(0);
  }
  lua_close(L);
  Log("Size %d", Size);
  return Size;
}