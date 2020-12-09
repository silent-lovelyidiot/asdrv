#include <Windows.h>
#include <Sddl.h>
#include <malloc.h>

#include <crtdbg.h>

#include "lua.hpp"
#include "lua_ext_functions.h"
#include "constexpr.h"
#include "log.h"

#ifdef DBG
int lua_log(lua_State* L) {
  const char* str = lua_tostring(L, 1);
  OutputDebugStringA(str);
  return 0;
}

#endif // DBG

int lua_initialize_ext(lua_State* L, const lua_CFunction* cf, int Count, int nrec) {
  lua_createtable(L, Count, nrec);

  for (int i = 0; i < Count; i++) {
    lua_pushinteger(L, i + 1);
    lua_pushcfunction(L, cf[i]);
    lua_settable(L, -3);
  }

  return 1;
}

int lua_initialize_script(lua_State* L, lua_CFunction decrypt, const char* script, int length) {
#ifdef DBG
  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
  lua_register(L, "dbg_log", lua_log);
#endif // DBG
  auto n = lua_getglobal(L, "dbg_load");
  n;
  int load[] = {RA('load'), 0};
  // load(decrypt(data))();
  lua_getglobal(L, (char*)load);

  if (decrypt) lua_pushcfunction(L, decrypt);
  lua_pushlstring(L, script, length);
  // decrypt(script)
  // push plaintext script
  if (decrypt) LUA_CALL(L, 1, 1, 0);

  // load(script)
  // return function
  LUA_CALL(L, 1, 1, 0);

  return 1;
}

int lua_is_os_bit64(lua_State* L) {
  BOOL bl = sizeof(size_t) == 8;

  if (!bl) {
    IsWow64Process((HANDLE)-1, &bl);
  }

  lua_pushboolean(L, bl);
  return 1;
}

int lua_convert_to_asni_char(lua_State* L) {
  size_t len;
  const wchar_t* str = (const wchar_t*)lua_tolstring(L, 1, &len);
  len = len / 2;
  UINT cp = (UINT)lua_tointeger(L, 2);

  int rlen = WideCharToMultiByte(cp, 0, str, len & 0xffffffff, nullptr, 0, nullptr, nullptr);
  if (rlen) {
    luaL_Buffer b;
    char* buff = (char*)luaL_buffinitsize(L, &b, rlen);

    rlen = WideCharToMultiByte(cp, 0, str, len & 0xffffffff, buff, rlen, nullptr, nullptr);

    luaL_pushresultsize(&b, rlen);
    return 1;
  }
  _ASSERT(0);
  lua_pushstring(L, "");
  return 1;
}

int lua_convert_to_wide_char(lua_State* L) {
  size_t len;
  const char* str = lua_tolstring(L, 1, &len);

  UINT cp = (UINT)lua_tointeger(L, 2);

  int rlen = MultiByteToWideChar(cp, 0, str, len & 0xffffffff, nullptr, 0);

  if (rlen) {
    luaL_Buffer b;
    wchar_t* buff = (wchar_t*)luaL_buffinitsize(L, &b, rlen * 2);

    len = MultiByteToWideChar(cp, 0, str, len & 0xffffffff, buff, rlen & 0xffffffff);

    luaL_pushresultsize(&b, len * 2);
    return 1;
  }
  _ASSERT(0);
  lua_pushstring(L, "");
  return 1;
}

int lua_file_wremove(lua_State* L) {
  const wchar_t* path = (const wchar_t*)lua_tostring(L, 1);

  auto bl = DeleteFileW(path);
  lua_pushboolean(L, bl);
  Log("%s, %d, %d", path, bl, GetLastError());
  _ASSERT(bl || GetLastError() == 0 || GetLastError() == 3 || GetLastError() == 2 || GetLastError() == 5);
  return 1;
}

int lua_compute_def_hash(lua_State* L) {
  extern void CalculateSingleUserChoiceHash(const wchar_t* InHashString, wchar_t OutHashString[16]);

  const char* str = lua_tostring(L, 1);

  wchar_t buff[16];
  buff[0] = 0;

  CalculateSingleUserChoiceHash((const wchar_t*)str, buff);
  lua_pushlstring(L, (const char*)buff, wcslen(buff) * 2);

  return 1;
}

DEF_LUA_CFUNCTION(lua_is_admin) {
  constexpr BYTE Buffer[] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00};
  PSID AdminGroupSid = (PSID)Buffer;

  BOOL bl = FALSE;
  CheckTokenMembership(nullptr, AdminGroupSid, &bl);

  lua_pushboolean(L, bl);
  return 1;
}

DEF_LUA_CFUNCTION(lua_execute) {
  size_t appname_len = 0, cmdline_len = 0, dirname_len = 0;
  const char* appname = lua_tolstring(L, 1, &appname_len);
  const char* cmdline = lua_tolstring(L, 2, &cmdline_len);
  auto show = lua_tointeger(L, 3);
  auto timeout = lua_tointeger(L, 4);

  const char* dirname = lua_tolstring(L, 5, &dirname_len);

  const wchar_t* APP = (const wchar_t*)appname;
  wchar_t* CMD = nullptr;

  if (cmdline_len) {
    CMD = _wcsdup((const wchar_t*)cmdline);
  }

  if (!APP && !CMD) return 0;

  STARTUPINFOW info = {sizeof(STARTUPINFOA)};
  info.dwFlags = STARTF_USESHOWWINDOW;
  info.wShowWindow = (WORD)show;

  DWORD ExitCode = 0xc0000000 | STILL_ACTIVE;
  PROCESS_INFORMATION pi;
  if (CreateProcessW(APP, CMD, nullptr, nullptr, FALSE, 0, nullptr, (wchar_t*)dirname,
    &info, &pi)) {
    WaitForSingleObject(pi.hProcess, (DWORD)timeout);
    GetExitCodeProcess(pi.hProcess, &ExitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  } else {
    _ASSERT(0);
  }
  lua_pushinteger(L, ExitCode);
  if (CMD) free(CMD);
  return 1;
}

ULONG TimeStampOfImageFile(CONST VOID* Data, ULONG Length) {
  ULONG T = ~0UL;
  __try {
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Data;

    if (!Dos || Dos->e_magic != IMAGE_DOS_SIGNATURE
      || (ULONG)Dos->e_lfanew >= Length - sizeof(ULONG_PTR))
      __leave;

    PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((CHAR*)Data + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE)
      __leave;

    T = Nt->FileHeader.TimeDateStamp;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    _ASSERT(0);
    Log("PE File Error!");
  }
  return T;
}

DEF_LUA_CFUNCTION(lua_verify) {
  size_t len;
  const char* str = lua_tolstring(L, 1, &len);

  if (!str || len < 512) {
    _ASSERT(0);
    return 0;
  }

  //if (VerifyEmbeddedSignature(str, 0xffffffff & len) != 0) {
  //  return 0;
  //}

  ULONG TimeStamp = TimeStampOfImageFile(str, len & 0xffffffff);
  if (TimeStamp == ~0UL) {
    return 0;
  }

  lua_pushinteger(L, TimeStamp);
  return 1;
}

DEF_LUA_CFUNCTION(lua_current_process_info) {
  wchar_t Buffer[MAX_PATH];
  Buffer[0] = 0;
  GetModuleFileNameW(nullptr, Buffer, MAX_PATH);
  lua_pushlstring(L, (char*)Buffer, wcslen(Buffer) * 2);

  Buffer[0] = 0;
  GetCurrentDirectoryW(MAX_PATH, Buffer);
  lua_pushlstring(L, (char*)Buffer, wcslen(Buffer) * 2);

  return 2;
}

#pragma region lua_key_routine
// lua registry key routines
int lua_reg_key_create(lua_State* L) {
  HKEY hKey = (HKEY)lua_touserdata(L, 1);
  if (hKey == nullptr) hKey = (HKEY)lua_tointeger(L, 1);
  if (hKey == nullptr) return _ASSERT(0), 0;

  DWORD sam = luaL_optinteger(L, 3, KEY_READ) & 0xffffffff;
  auto name = (const wchar_t*)lua_tostring(L, 2);

  HKEY h = nullptr;
  auto open = luaL_optinteger(L, 4, 0);
  LSTATUS r = 0;
  if (open) {
    r = RegOpenKeyExW(hKey, name, 0, sam, &h);
  } else {
    r = RegCreateKeyExW(hKey, name, 0, nullptr, 0, sam, nullptr, &h, nullptr);
  }

  if (h) {
    lua_pushlightuserdata(L, h);
    return 1;
  }
  Log("Create Key %s Error %08x, %d %d!", name, sam, r, open);
  return 0;
}

int lua_reg_key_close(lua_State* L) {
  HKEY hKey = (HKEY)lua_touserdata(L, 1);
  if (hKey == nullptr) return _ASSERT(0), 0;

  RegCloseKey(hKey);
  return 0;
}

int lua_reg_value_enum(lua_State* L) {
  HKEY hKey = (HKEY)lua_touserdata(L, 1);
  if (hKey == nullptr) return _ASSERT(0), 0;

  lua_createtable(L, 0, 0);

  for (int i = 0; ; i++) {
    WCHAR Value[MAX_PATH];
    DWORD ValueLength = ARRAYSIZE(Value);
    BYTE Data[1024];
    DWORD DataSize = sizeof(Data);
    DWORD Type;

    auto r = RegEnumValueW(hKey, i, Value, &ValueLength,
      nullptr, &Type, Data, &DataSize);

    if (r == ERROR_NO_MORE_ITEMS)
      break;

    if (r == ERROR_SUCCESS) {
      lua_pushlstring(L, (char*)Value, ValueLength * 2);
      if (Type == REG_DWORD || Type == REG_QWORD) {
        lua_pushinteger(L, DataSize == sizeof(DWORD) ? *(PULONG)Data : *(PULONGLONG)Data);
      } else {
        lua_pushlstring(L, (char*)Data, DataSize);
      }
      lua_settable(L, -3);
    }
  }
  return 1;
}

int lua_reg_key_enum(lua_State* L) {
  HKEY hKey = (HKEY)lua_touserdata(L, 1);
  if (hKey == nullptr) return _ASSERT(0), 0;

  lua_createtable(L, 0, 0);

  for (int i = 0; ; i++) {
    WCHAR buffer[MAX_PATH];
    DWORD size = ARRAYSIZE(buffer);
    auto r = RegEnumKeyExW(hKey, i, buffer, &size, nullptr, nullptr, nullptr, nullptr);
    if (r == ERROR_NO_MORE_ITEMS)
      break;

    if (r == ERROR_SUCCESS) {
      lua_pushlstring(L, (char*)buffer, size * 2);
      lua_pushinteger(L, i);
      lua_settable(L, -3);
    }
  }

  return 1;
}

int lua_reg_key_delete(lua_State* L) {
  HKEY hKey = (HKEY)lua_touserdata(L, 1);
  if (hKey == nullptr) return _ASSERT(0), 0;

  RegDeleteKeyExW(hKey, (wchar_t*)lua_tostring(L, 2), KEY_WOW64_64KEY, 0);

  return 0;
}

int lua_reg_value_delete(lua_State* L) {
  HKEY hKey = (HKEY)lua_touserdata(L, 1);
  if (hKey == nullptr) return _ASSERT(0), 0;

  RegDeleteKeyValueW(hKey, (wchar_t*)lua_tostring(L, 2), (wchar_t*)lua_tostring(L, 3));

  return 0;
}

int lua_reg_key_flush(lua_State* L) {
  HKEY hKey = (HKEY)lua_touserdata(L, 1);
  if (hKey == nullptr) return _ASSERT(0), 0;

  RegFlushKey(hKey);

  return 0;
}

int lua_reg_value_write(lua_State* L) {
  HKEY hKey = (HKEY)lua_touserdata(L, 1);
  if (hKey == nullptr) return _ASSERT(0), 0;

  DWORD Type = lua_tointeger(L, 3) & 0xffffffff;

  LONG r;
  if (Type == REG_QWORD || Type == REG_DWORD) {
    auto val = lua_tointeger(L, 4);
    r = RegSetValueExW(hKey, (wchar_t*)lua_tostring(L, 2), 0, Type,
      (BYTE*)&val, (Type == REG_DWORD) ? 4 : 8);
  } else {
    size_t len = 0;
    const char* val = lua_tolstring(L, 4, &len);
    r = RegSetValueExW(hKey, (wchar_t*)lua_tostring(L, 2), 0, Type,
      (BYTE*)val, len & 0xffffffff);
    Log("Write Value Type %d, Name %s, Value %16s", Type, (wchar_t*)lua_tostring(L, 2), val);
  }
  lua_pushinteger(L, r);
  return 1;
}

int lua_reg_value_query(lua_State* L) {
  HKEY hKey = (HKEY)lua_touserdata(L, 1);
  if (hKey == nullptr) return _ASSERT(0), 0;

  BYTE Data[1024];
  DWORD DataSize = sizeof(Data);
  DWORD Type;
  auto name = (const wchar_t*)lua_tostring(L, 2);
  auto r = RegQueryValueExW(hKey, name, nullptr, &Type, Data, &DataSize);
  if (r == ERROR_SUCCESS) {
    lua_pushinteger(L, Type);
    if (Type == REG_DWORD || Type == REG_QWORD) {
      lua_pushinteger(L, DataSize == sizeof(DWORD) ? *(PULONG)Data : *(PULONGLONG)Data);
    } else {
      lua_pushlstring(L, (char*)Data, DataSize);
    }
  } else if (r == ERROR_MORE_DATA) {
    luaL_Buffer b;
    char* buff = luaL_buffinitsize(L, &b, DataSize);
    r = RegQueryValueExW(hKey, name, nullptr, &Type, (BYTE*)buff, &DataSize);
    if (r == ERROR_SUCCESS) {
      luaL_pushresultsize(&b, DataSize);

      lua_pushinteger(L, Type);
      lua_insert(L, -2);
    }
  }

  if (r != ERROR_SUCCESS) {
    lua_pushnil(L);
    lua_pushnil(L);
  }

  return 2;
}
// lua registry key routines finish
#pragma endregion 注册表相关扩展

#pragma region lua_http_routine
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
// http
int lua_http_create_session(lua_State* L) {
  const wchar_t* user_agent = (const wchar_t*)lua_tostring(L, 1);
  auto hSession = WinHttpOpen(user_agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (hSession) {
    ULONG timeout = luaL_optinteger(L, 2, 3000) & 0xffffffff;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    lua_pushlightuserdata(L, hSession);
    return 1;
  }
  _ASSERT(0);
  return 0;
}

int lua_http_create_connect(lua_State* L) {
  HINTERNET hSession = (HINTERNET)lua_touserdata(L, 1);
  _ASSERT(hSession);
  const wchar_t* host = (const wchar_t*)lua_tostring(L, 2);
  auto hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTP_PORT, 0);
  if (hConnect) {
    lua_pushlightuserdata(L, hConnect);
    return 1;
  }

  return 0;
}

int lua_http_create_request(lua_State* L) {
  HINTERNET hConnect = (HINTERNET)lua_touserdata(L, 1);
  const wchar_t* verb = (const wchar_t*)lua_tostring(L, 2);
  const wchar_t* file = (const wchar_t*)lua_tostring(L, 3);

  LPCWSTR AcceptTypes[] = {L"application/octet-stream", nullptr};
  auto hRequest = WinHttpOpenRequest(hConnect, verb, file, nullptr, nullptr,
        AcceptTypes, 0);
  _ASSERT(hRequest);
  if (hRequest) {
    lua_pushlightuserdata(L, hRequest);
    return 1;
  }
  return 0;
}

int lua_http_send_request(lua_State* L) {
  HINTERNET hRequest = (HINTERNET)lua_touserdata(L, 1);
  _ASSERT(hRequest);

  BOOL bl = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
  lua_pushboolean(L, bl);
  return 1;
}

int lua_http_recv_response(lua_State* L) {
  HINTERNET hRequest = (HINTERNET)lua_touserdata(L, 1);
  _ASSERT(hRequest);

  BOOL bl = WinHttpReceiveResponse(hRequest, nullptr);
  lua_pushboolean(L, bl);

  return 1;
}

int lua_http_query_data_length(lua_State* L) {
  HINTERNET hRequest = (HINTERNET)lua_touserdata(L, 1);
  _ASSERT(hRequest);

  DWORD AllData = 0;
  
  BOOL bl = WinHttpQueryDataAvailable(hRequest, &AllData);
  lua_pushboolean(L, bl);
  if (bl)
    lua_pushinteger(L, AllData);
  else
    lua_pushnil(L);
  return 2;
}

int lua_http_query_header(lua_State* L) {
  HINTERNET hRequest = (HINTERNET)lua_touserdata(L, 1);
  _ASSERT(hRequest);

  DWORD dwInfoLevel = (DWORD)lua_tointeger(L, 2);

  wchar_t str[256];
  DWORD len = sizeof(str);

  BOOL bl = WinHttpQueryHeaders(hRequest, dwInfoLevel,
    WINHTTP_HEADER_NAME_BY_INDEX, str, &len, WINHTTP_NO_HEADER_INDEX);
  lua_pushboolean(L, bl);
  if (bl)
    lua_pushlstring(L, (const char*)str, len);
  else
    lua_pushnil(L);
  return 2;
}

int lua_http_read_data(lua_State* L) {
  HINTERNET hRequest = (HINTERNET)lua_touserdata(L, 1);
  _ASSERT(hRequest);

  int len = lua_tointeger(L, 2) & 0xffffffff;

  DWORD read = 0;

  luaL_Buffer b;
  char* buff = luaL_buffinitsize(L, &b, len);
  BOOL bl = WinHttpReadData(hRequest, buff, len, &read);
  luaL_pushresultsize(&b, read);

  lua_pushboolean(L, bl);
  lua_insert(L, -2);

  return 2;
}

int lua_http_set_header(lua_State* L) {
  HINTERNET hRequest = (HINTERNET)lua_touserdata(L, 1);
  _ASSERT(hRequest);

  LPCWSTR pwszHeaders = (LPCWSTR)lua_tostring(L, 2);
  DWORD dwModifiers = lua_tointeger(L, 3) & 0xffffffff;

  BOOL bl = WinHttpAddRequestHeaders(hRequest, pwszHeaders, (DWORD)-1, dwModifiers);
  lua_pushboolean(L, bl);
  return 0;
}

int lua_http_close_handle(lua_State* L) {
  auto hRequest = (HINTERNET)lua_touserdata(L, 1);
  _ASSERT(hRequest);

  WinHttpCloseHandle(hRequest);
  return 0;
}

#pragma endregion HTTP相关API

#include <direct.h>
#include <io.h>
int lua_file_exist(lua_State* L) {
  const wchar_t* path = (const wchar_t*)lua_tostring(L, 1);
  int mode = luaL_optinteger(L, 2, 0) & 0xffffffff;

  int r = _waccess_s(path, mode);
  lua_pushinteger(L, r);
  return 1;
}

int lua_mkdir(lua_State* L) {
  const wchar_t* path = (const wchar_t*)lua_tostring(L, 1);
  int r = _wmkdir(path);
  lua_pushinteger(L, r);
  return 1;
}

int lua_enum_files(lua_State* L) {
  const wchar_t* path = (const wchar_t*)lua_tostring(L, 1);
  WIN32_FIND_DATAW ffd = {0};
  HANDLE handle = FindFirstFileW(path, &ffd);
  if (handle == INVALID_HANDLE_VALUE) return 0;

  lua_createtable(L, 10, 0);
  int i = 1;
  do {
    lua_pushinteger(L, i++);
    lua_pushlstring(L, (char*)ffd.cFileName, wcslen(ffd.cFileName) * sizeof(wchar_t));
    lua_settable(L, -3);
  } while(FindNextFileW(handle, &ffd));

  FindClose(handle);
  return 1;
}

#include "NtApi.h"

int lua_sys_hash(lua_State* L) {
  size_t len = 0;
  const char* str = lua_tolstring(L, 1, &len);
  _ASSERT(str);
  auto CaseInSensitive = luaL_optinteger(L, 2, TRUE);
  auto HashAlgorithm = luaL_optinteger(L, 3, HASH_STRING_ALGORITHM_X65599);

  if (str) {
    UNICODE_STRING STR = {
      len & 0xffff,
      len & 0xffff,
      (PWCHAR)str
    };
    ULONG Value;
    if (0 == RtlHashUnicodeString(&STR, 1 & CaseInSensitive, (ULONG)HashAlgorithm,
      &Value)) {
      lua_pushinteger(L, Value);
      return 1;
    }
  }

  return 0;
}

void RaiseLoadDriverAndDebugPrivilege(DWORD Attributes) {
  HANDLE hToken;
  HANDLE hProcess = GetCurrentProcess();

  if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    TOKEN_PRIVILEGES tkp = {0};
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = Attributes;

    LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    Log("LookupPrivilegeValue SE_DEBUG_NAME Last Error %d", GetLastError());

    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, nullptr, nullptr);
    Log("AdjustTokenPrivileges Last Error %d", GetLastError());

    LookupPrivilegeValue(nullptr, SE_LOAD_DRIVER_NAME, &tkp.Privileges[0].Luid);
    Log("LookupPrivilegeValue SE_LOAD_DRIVER_NAME Last Error %d", GetLastError());

    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, nullptr, nullptr);
    Log("AdjustTokenPrivileges Last Error %d", GetLastError());
    CloseHandle(hToken);
  } else {
    _ASSERT(0);
  }
}

int lua_load_driver(lua_State* L) {
  size_t len;
  wchar_t* drv = (wchar_t*)lua_tolstring(L, 1, &len);

  UNICODE_STRING DrvName = {
    (wcslen(drv) * 2) & 0xffff, len & 0xffff,
    drv
  };
  Log("Load Driver Registry Key Name %d, %d, %s", DrvName.Length & 0xffff, DrvName.MaximumLength & 0xffff, drv);
  RaiseLoadDriverAndDebugPrivilege(SE_PRIVILEGE_ENABLED);
  NTSTATUS st = NtLoadDriver(&DrvName);
  Log("NtLoadDriver result %08x", st);
  //RaiseLoadDriverAndDebugPrivilege(SE_PRIVILEGE_REMOVED);
  lua_pushinteger(L, st);
  return 1;
}

int lua_unload_driver(lua_State* L) {
  size_t len;
  wchar_t* drv = (wchar_t*)lua_tolstring(L, 1, &len);

  UNICODE_STRING DrvName = {
    (wcslen(drv) * 2) & 0xffff, len & 0xffff,
    drv
  };
  RaiseLoadDriverAndDebugPrivilege(SE_PRIVILEGE_ENABLED);
  NTSTATUS st = NtUnloadDriver(&DrvName);
  Log("NtUnloadDriver result %08x", st);
  //RaiseLoadDriverAndDebugPrivilege(SE_PRIVILEGE_REMOVED);
  lua_pushinteger(L, st);
  return 1;
}

