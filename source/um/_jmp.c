
#include "lua.h"
#include <setjmp.h>

#ifdef DBG
#define LUA_CALL(L, n, r, f)  lua_call(L, n, r)
#else
#define LUA_CALL(L, n, r, f)  lua_pcall(L, n, r, f)
#endif // DBG

jmp_buf _jmp_buf = {0};

int lua_call_protect_env(lua_State* L, int n, int r, int f) {
  int jmp = 1;
  f;
  if (!setjmp(_jmp_buf)) {
    LUA_CALL(L, n, r, f);
    jmp = 0;
  }
  return jmp;
}

