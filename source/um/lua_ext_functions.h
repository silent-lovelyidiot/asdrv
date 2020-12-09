#ifndef __LUA_EXT_FUNCTIONS_H__
#define __LUA_EXT_FUNCTIONS_H__

#include "log.h"
#include <crtdbg.h>

#ifdef DBG
#define LUA_CALL(L, n, r, f)  lua_call(L, n, r)
#else
#define LUA_CALL(L, n, r, f)  lua_pcall(L, n, r, f)
#endif // DBG

template<lua_CFunction api>
int TryLuaExtApi(lua_State* L) {
  int n = 0;
  __try {
    n = api(L);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    _ASSERT(0);
    Log("try %p", api);
  }
  return n;
}

#define DEF_LUA_CFUNCTION(name)     int name(lua_State* L)

int lua_initialize_ext(lua_State* L, const lua_CFunction* cf, int Count, int nrec);

int lua_initialize_script(lua_State* L, lua_CFunction decrypt, const char* script, int length);

EXTERN_C DEF_LUA_CFUNCTION(lua_mpq_hash);
DEF_LUA_CFUNCTION(lua_sys_hash);

EXTERN_C DEF_LUA_CFUNCTION(lua_crypt_encrypt);
EXTERN_C DEF_LUA_CFUNCTION(lua_crypt_decrypt);
EXTERN_C DEF_LUA_CFUNCTION(lua_crypt_hash);
EXTERN_C DEF_LUA_CFUNCTION(lua_crypt_verify_sign);

DEF_LUA_CFUNCTION(lua_is_os_bit64);
DEF_LUA_CFUNCTION(lua_is_admin);
DEF_LUA_CFUNCTION(lua_verify);

DEF_LUA_CFUNCTION(lua_convert_to_wide_char);
DEF_LUA_CFUNCTION(lua_convert_to_asni_char);

DEF_LUA_CFUNCTION(lua_current_process_info);

EXTERN_C DEF_LUA_CFUNCTION(lua_file_wopen);
DEF_LUA_CFUNCTION(lua_execute);
DEF_LUA_CFUNCTION(lua_file_wremove);

DEF_LUA_CFUNCTION(lua_compute_def_hash);

DEF_LUA_CFUNCTION(lua_load_driver);
DEF_LUA_CFUNCTION(lua_unload_driver);

DEF_LUA_CFUNCTION(lua_cfg_new_item);
DEF_LUA_CFUNCTION(lua_cfg_del_item);
DEF_LUA_CFUNCTION(lua_cfg_set_item);
DEF_LUA_CFUNCTION(lua_cfg_serialze);

DEF_LUA_CFUNCTION(lua_reg_key_create);
DEF_LUA_CFUNCTION(lua_reg_key_close);
DEF_LUA_CFUNCTION(lua_reg_key_enum);
DEF_LUA_CFUNCTION(lua_reg_value_enum);
DEF_LUA_CFUNCTION(lua_reg_value_query);
DEF_LUA_CFUNCTION(lua_reg_value_write);
DEF_LUA_CFUNCTION(lua_reg_key_delete);
DEF_LUA_CFUNCTION(lua_reg_value_delete);
DEF_LUA_CFUNCTION(lua_reg_key_flush);

DEF_LUA_CFUNCTION(lua_http_create_session);
DEF_LUA_CFUNCTION(lua_http_create_connect);
DEF_LUA_CFUNCTION(lua_http_create_request);
DEF_LUA_CFUNCTION(lua_http_close_handle);
DEF_LUA_CFUNCTION(lua_http_send_request);
DEF_LUA_CFUNCTION(lua_http_recv_response);
DEF_LUA_CFUNCTION(lua_http_query_data_length);
DEF_LUA_CFUNCTION(lua_http_query_header);
DEF_LUA_CFUNCTION(lua_http_read_data);
DEF_LUA_CFUNCTION(lua_http_set_header);

DEF_LUA_CFUNCTION(lua_file_exist);
DEF_LUA_CFUNCTION(lua_mkdir);

DEF_LUA_CFUNCTION(lua_enum_files);

DEF_LUA_CFUNCTION(lua_mem_malloc); // 60
DEF_LUA_CFUNCTION(lua_mem_free);
DEF_LUA_CFUNCTION(lua_mem_copy);
DEF_LUA_CFUNCTION(lua_to_userdata); // 63

DEF_LUA_CFUNCTION(lua_create_file); // 65
DEF_LUA_CFUNCTION(lua_close_file); // 66

#define DEF_TRY_LUA_EXT_API(api)  TryLuaExtApi<api>
constexpr const lua_CFunction InternalApi[] = {
  DEF_TRY_LUA_EXT_API(lua_mpq_hash), // 1
  DEF_TRY_LUA_EXT_API(lua_sys_hash),

  DEF_TRY_LUA_EXT_API(lua_crypt_encrypt), // 3
  DEF_TRY_LUA_EXT_API(lua_crypt_decrypt),
  DEF_TRY_LUA_EXT_API(lua_crypt_hash),
  DEF_TRY_LUA_EXT_API(lua_crypt_verify_sign),

  DEF_TRY_LUA_EXT_API(lua_is_os_bit64), // 7
  DEF_TRY_LUA_EXT_API(lua_is_admin),
  DEF_TRY_LUA_EXT_API(lua_verify),

  DEF_TRY_LUA_EXT_API(lua_convert_to_wide_char), // 10
  DEF_TRY_LUA_EXT_API(lua_convert_to_asni_char),

  DEF_TRY_LUA_EXT_API(lua_current_process_info), // 12

  DEF_TRY_LUA_EXT_API(lua_file_wopen), // 13
  DEF_TRY_LUA_EXT_API(lua_execute),
  DEF_TRY_LUA_EXT_API(lua_file_wremove),

  DEF_TRY_LUA_EXT_API(lua_compute_def_hash), // 16

  DEF_TRY_LUA_EXT_API(lua_load_driver), // 17
  DEF_TRY_LUA_EXT_API(lua_unload_driver),

  DEF_TRY_LUA_EXT_API(lua_cfg_new_item), // 19
  DEF_TRY_LUA_EXT_API(lua_cfg_del_item),
  DEF_TRY_LUA_EXT_API(lua_cfg_set_item),
  DEF_TRY_LUA_EXT_API(lua_cfg_serialze),

  DEF_TRY_LUA_EXT_API(lua_reg_key_create), // 23
  DEF_TRY_LUA_EXT_API(lua_reg_key_close),
  DEF_TRY_LUA_EXT_API(lua_reg_key_enum),
  DEF_TRY_LUA_EXT_API(lua_reg_value_enum),
  DEF_TRY_LUA_EXT_API(lua_reg_value_query),
  DEF_TRY_LUA_EXT_API(lua_reg_value_write),
  DEF_TRY_LUA_EXT_API(lua_reg_key_delete),
  DEF_TRY_LUA_EXT_API(lua_reg_value_delete),

  DEF_TRY_LUA_EXT_API(lua_http_create_session), // 31
  DEF_TRY_LUA_EXT_API(lua_http_create_connect),
  DEF_TRY_LUA_EXT_API(lua_http_create_request),
  DEF_TRY_LUA_EXT_API(lua_http_close_handle),
  DEF_TRY_LUA_EXT_API(lua_http_send_request),
  DEF_TRY_LUA_EXT_API(lua_http_recv_response),
  DEF_TRY_LUA_EXT_API(lua_http_query_data_length),
  DEF_TRY_LUA_EXT_API(lua_http_query_header),
  DEF_TRY_LUA_EXT_API(lua_http_read_data),
  DEF_TRY_LUA_EXT_API(lua_http_set_header),

  DEF_TRY_LUA_EXT_API(lua_file_exist), // 41
  DEF_TRY_LUA_EXT_API(lua_mkdir),

  DEF_TRY_LUA_EXT_API(lua_reg_key_flush), // 43

  DEF_TRY_LUA_EXT_API(lua_enum_files), // 44
  nullptr, // 45
  nullptr, // 46
  nullptr, // 47
  nullptr, // 48
  nullptr, // 49
  nullptr, // 50
  nullptr, // 51
  nullptr, // 52
  nullptr, // 53
  nullptr, // 54
  nullptr, // 55
  nullptr, // 56
  nullptr, // 57
  nullptr, // 58
  nullptr, // 59
  DEF_TRY_LUA_EXT_API(lua_mem_malloc), // 60
  DEF_TRY_LUA_EXT_API(lua_mem_free),
  DEF_TRY_LUA_EXT_API(lua_mem_copy),
  DEF_TRY_LUA_EXT_API(lua_to_userdata), // 63
  nullptr,
  DEF_TRY_LUA_EXT_API(lua_create_file), // 65
  DEF_TRY_LUA_EXT_API(lua_close_file), // 66
};

static_assert(sizeof(InternalApi) / sizeof(InternalApi[0]) == 66, "");
#endif // !__LUA_EXT_FUNCTIONS_H__
