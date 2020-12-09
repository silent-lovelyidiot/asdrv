#ifdef DBG
#include <Windows.h>

#include "../lua/src/lua.hpp"
#include "../source/constexpr.h"

#include "../source/log.h"

#include "lua_ext_functions.h"

#include "config.h"

#include <malloc.h>

#include <setjmp.h>
EXTERN_C extern jmp_buf _jmp_buf;
EXTERN_C int lua_call_protect_env(lua_State* L, int n, int r , int f);

int lua_test_script_panic(lua_State* L) {
  L;
#ifdef DBG
  const char* err = lua_tostring(L, -1);
  if (err) {
    OutputDebugStringA(__FUNCTION__);
    OutputDebugStringA("\t");
    OutputDebugStringA(err);
    OutputDebugStringA("\n");
  }
#endif // DBG

  Log("RaiseException e0000001");
  // longjmp(_jmp_buf, 1);
  RaiseException(0xe0000001, 0, 0, nullptr);
  return 0;
}

int test_lua_script(const char* lua_script, int lua_test_function, LPVOID BaseAddress, ULONG Size) {
  auto L = luaL_newstate();
  luaL_openlibs(L);
#ifdef DBG
  extern int lua_log(lua_State* L);
  lua_register(L, "dbg_log", lua_log);
#endif // DBG
  lua_atpanic(L, lua_test_script_panic);
  Log("aslauncher --test initialize script");
  const char* load = "load";
  lua_getglobal(L, load);
  lua_pushstring(L, lua_script);
  lua_pushstring(L, "test_lua_script");
  LUA_CALL(L, 2, 2, 0);

  if (lua_isnil(L, -2)) {
    printf("load error: %s\n", lua_tostring(L, -1));
    return -1;
  } else {
    lua_remove(L, -1);
  }
   __try {
    lua_pushinteger(L, lua_test_function);
    LUA_CALL(L, 1, 1, 0);

    Log("aslauncher --test initialize ext api");
    lua_initialize_ext(L, InternalApi, ARRAYSIZE(InternalApi), 0);
    lua_pushstring(L, GetCommandLineA());
    lua_pushlightuserdata(L, BaseAddress);
    lua_pushinteger(L, Size);

    Log("aslauncher --test running...");
    PVOID OldValue;
    BOOL bl = Wow64DisableWow64FsRedirection(&OldValue);
    //LUA_CALL(L, 4, 1, 0);
    lua_call_protect_env(L, 4, 1, 0);
    if (bl) Wow64RevertWow64FsRedirection(OldValue);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Log("test_lua_script error");
  }
  int n = (int)lua_tointeger(L, -1);
  Log("aslauncher --test result %08x", n);

  char* buffer = (char*)_alloca(Size);
  if (0 <= n && (ULONG)n < Size) {
    memcpy(buffer, BaseAddress, n);
  }
  memset(BaseAddress, 0, Size);
  n = DeserialzeConfig((PCONFIG_TABLE)buffer, TRUE);
  Log("DeserialzeConfig result %08x", n);
  lua_close(L);

  return 0;
}

#include <malloc.h>

// exe --test file n
ULONG TestScriptInternal(LPVOID BaseAddress, ULONG Size) {
  const wchar_t** argv = (const wchar_t**)BaseAddress;
  FILE* lua_script_file;

  char* buffer = nullptr;
  if (_wfopen_s(&lua_script_file, argv[2], L"rb") == 0) {
    fseek(lua_script_file, 0, SEEK_END);
    long len = ftell(lua_script_file);
    fseek(lua_script_file, 0, SEEK_SET);

    buffer = (char*)malloc(len + 1);
    fread(buffer, 1, len, lua_script_file);
    buffer[len] = 0;

    fclose(lua_script_file);
  }

  if (buffer) {
    test_lua_script(buffer, argv[3][0] - '0', BaseAddress, Size);
    free(buffer);
  }
  return 0;
}
#endif // DBG
