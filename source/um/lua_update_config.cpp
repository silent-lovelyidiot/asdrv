#include <ntdef.h>

#include "../source/config.h"

#include "../lua/src/lua.hpp"

#include <malloc.h>

static_assert(sizeof(lua_Integer) == sizeof(ULONGLONG), "");

int lua_cfg_new_item (lua_State *L) {
  //PCONFIG_ITEM* lua_user_item = (PCONFIG_ITEM*)lua_newuserdata(L, sizeof(PCONFIG_ITEM*));
  lua_Integer hash = lua_tointeger(L, 1);
  lua_Integer count = lua_tointeger(L, 2);
  lua_assert(count <= 0xff);
  PCONFIG_ITEM item = GenConfigItem(hash, count & 0xff);

  if (!item) return 0;
  lua_pushlightuserdata(L, item);
  return 1;
}

int lua_cfg_del_item (lua_State *L) {
  PCONFIG_ITEM lua_user_item = (PCONFIG_ITEM)lua_touserdata(L, 1);
  ReleaseConfigItem(lua_user_item);
  return 0;
}

int lua_cfg_set_item (lua_State *L) {
  PCONFIG_ITEM item = (PCONFIG_ITEM)lua_touserdata(L, 1);

  lua_Integer index = lua_tointeger(L, 2);
  const void* value = (const void*)lua_tostring(L, 3);// lua_tointeger(L, 3);
  lua_Integer length = lua_tointeger(L, 4);

  lua_assert(length <= 0xffff);
  BOOLEAN bl = SetConfigItemEntry(item, index,
    (PVOID)value, length & 0xffff);

  lua_pushboolean(L, bl);
  return 1;
}

int lua_cfg_serialze (lua_State *L) {
  void* memory = lua_touserdata(L, 1);
  ULONG size = (ULONG)lua_tointeger(L, 2);

  lua_len(L, 3);
  lua_Integer len = lua_tointeger(L, -1);

  PCONFIG_ITEM* items = (PCONFIG_ITEM*)alloca(sizeof(PCONFIG_ITEM)*(size_t)len);

  for (int i = 0; i < len; i++) {
    lua_geti(L, 3, i + 1);
    void* item = lua_touserdata(L, -1);
    items[i] = (PCONFIG_ITEM)item;
  }
  lua_assert(len <= 0xffff);
  ULONG n = SerialzeConfig(items, len & 0xffff, memory, size);
  lua_pushinteger(L, n);
  return 1;
}