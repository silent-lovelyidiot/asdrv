#include <Windows.h>

#include <crtdbg.h>
#include <malloc.h>

#include "lua.hpp"

int lua_create_file(lua_State* L) {
  const wchar_t* filename = (const wchar_t*)lua_tostring(L, 1);
  DWORD access = luaL_optinteger(L, 2, GENERIC_READ) & 0xffffffff;
  DWORD share = luaL_optinteger(L, 3, FILE_SHARE_READ) & 0xffffffff;
  PSECURITY_ATTRIBUTES sa = (PSECURITY_ATTRIBUTES)lua_touserdata(L, 4);
  DWORD disposition = luaL_optinteger(L, 5, OPEN_EXISTING) & 0xffffffff;
  DWORD attributes = luaL_optinteger(L, 6, FILE_ATTRIBUTE_NORMAL) & 0xffffffff;
  HANDLE temp = lua_touserdata(L, 7);

  HANDLE hf = CreateFileW(filename, access, share, sa, disposition, attributes, temp);
  if (hf != INVALID_HANDLE_VALUE) {
    lua_pushlightuserdata(L, hf);
    return 1;
  }
  _ASSERT(0);
  return 0;
}

int lua_close_file(lua_State* L) {
  HANDLE hf = lua_touserdata(L, 1);
  if (hf) {
    BOOL bl = CloseHandle(hf);
    bl;
    _ASSERT(bl);
  } else {
    _ASSERT(0);
  }
  return 0;
}

int lua_to_userdata(lua_State* L) {
  lua_Integer pseudo = lua_tointeger(L, 1);
  if (pseudo) {
    lua_pushlightuserdata(L, (void*)pseudo);
    return 1;
  }
  _ASSERT(0);
  return 0;
}

int lua_mem_malloc(lua_State* L) {
  ULONG size = lua_tointeger(L, 1) & 0xffffffff;
  auto mem = malloc(size);
  if (mem) {
    lua_pushlightuserdata(L, mem);
    lua_pushinteger(L, size);
    return 2;
  }
  _ASSERT(0);
  return 0;
}

int lua_mem_free(lua_State* L) {
  auto mem = lua_touserdata(L, 1);
  if (mem) {
    _ASSERT((SIZE_T)lua_tointeger(L, 2) == _msize(mem));
    free(mem);
  } else {
    _ASSERT(0);
  }

  return 0;
}

int lua_mem_copy(lua_State* L) {
  auto mem = lua_touserdata(L, 1);
  size_t len = 0;
  auto str = lua_tolstring(L, 2, &len);
  _ASSERT(mem && len && str && len <= _msize(mem));
  if (mem && len && str && len <= _msize(mem)) {
    memcpy(mem, str, len);
    lua_pushboolean(L, TRUE);
  } else {
    lua_pushboolean(L, FALSE);
  }
  return 1;
}
