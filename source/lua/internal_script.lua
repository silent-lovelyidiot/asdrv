-- internal script lua
--(base , base + c]
local Counter = function(base)
  base = base or 0;
  local c = 0;
  return function()
    c = c + 1;
    return base + c;
  end
end


-- REG_NOTIFY_CLASS def begin
local RegNotifyValue = Counter(0 - 1);
local RegNtDeleteKey = RegNotifyValue();
local RegNtPreDeleteKey = RegNtDeleteKey;
local RegNtSetValueKey = RegNotifyValue();
local RegNtPreSetValueKey = RegNtSetValueKey;
local RegNtDeleteValueKey = RegNotifyValue();
local RegNtPreDeleteValueKey = RegNtDeleteValueKey;
local RegNtSetInformationKey = RegNotifyValue();
local RegNtPreSetInformationKey = RegNtSetInformationKey;
local RegNtRenameKey = RegNotifyValue();
local RegNtPreRenameKey = RegNtRenameKey;
local RegNtEnumerateKey = RegNotifyValue();
local RegNtPreEnumerateKey = RegNtEnumerateKey;
local RegNtEnumerateValueKey = RegNotifyValue();
local RegNtPreEnumerateValueKey = RegNtEnumerateValueKey;
local RegNtQueryKey = RegNotifyValue();
local RegNtPreQueryKey = RegNtQueryKey;
local RegNtQueryValueKey = RegNotifyValue();
local RegNtPreQueryValueKey = RegNtQueryValueKey;
local RegNtQueryMultipleValueKey = RegNotifyValue();
local RegNtPreQueryMultipleValueKey = RegNtQueryMultipleValueKey;
local RegNtPreCreateKey = RegNotifyValue();
local RegNtPostCreateKey = RegNotifyValue();
local RegNtPreOpenKey = RegNotifyValue();
local RegNtPostOpenKey = RegNotifyValue();
local RegNtKeyHandleClose = RegNotifyValue();
local RegNtPreKeyHandleClose = RegNtKeyHandleClose;
    --//
    --// .Net only
    --//
local RegNtPostDeleteKey = RegNotifyValue();
local RegNtPostSetValueKey = RegNotifyValue();
local RegNtPostDeleteValueKey = RegNotifyValue();
local RegNtPostSetInformationKey = RegNotifyValue();
local RegNtPostRenameKey = RegNotifyValue();
local RegNtPostEnumerateKey = RegNotifyValue();
local RegNtPostEnumerateValueKey = RegNotifyValue();
local RegNtPostQueryKey = RegNotifyValue();
local RegNtPostQueryValueKey = RegNotifyValue();
local RegNtPostQueryMultipleValueKey = RegNotifyValue();
local RegNtPostKeyHandleClose = RegNotifyValue();
local RegNtPreCreateKeyEx = RegNotifyValue();
local RegNtPostCreateKeyEx = RegNotifyValue();
local RegNtPreOpenKeyEx = RegNotifyValue();
local RegNtPostOpenKeyEx = RegNotifyValue();
    --//
    --// new to Windows Vista
    --//
local RegNtPreFlushKey = RegNotifyValue();
local RegNtPostFlushKey = RegNotifyValue();
local RegNtPreLoadKey = RegNotifyValue();
local RegNtPostLoadKey = RegNotifyValue();
local RegNtPreUnLoadKey = RegNotifyValue();
local RegNtPostUnLoadKey = RegNotifyValue();
local RegNtPreQueryKeySecurity = RegNotifyValue();
local RegNtPostQueryKeySecurity = RegNotifyValue();
local RegNtPreSetKeySecurity = RegNotifyValue();
local RegNtPostSetKeySecurity = RegNotifyValue();
    --//
    --// per-object context cleanup
    --//
local RegNtCallbackObjectContextCleanup = RegNotifyValue();
    --//
    --// new in Vista SP2
    --//
local RegNtPreRestoreKey = RegNotifyValue();
local RegNtPostRestoreKey = RegNotifyValue();
local RegNtPreSaveKey = RegNotifyValue();
local RegNtPostSaveKey = RegNotifyValue();
local RegNtPreReplaceKey = RegNotifyValue();
local RegNtPostReplaceKey = RegNotifyValue();
    --//
    --// new to Windows 10
    --//
local RegNtPreQueryKeyName = RegNotifyValue();
local RegNtPostQueryKeyName = RegNotifyValue();

local MaxRegNtNotifyClass = RegNotifyValue();--//should always be the last enum
RegNotifyValue = nil;
--} REG_NOTIFY_CLASS;
-- REG_NOTIFY_CLASS def end

local CONFIG_ACTION_BASE = MaxRegNtNotifyClass + 3;
local RegActionValue = Counter(CONFIG_ACTION_BASE - 1);

local RegActionKeyRedirect = RegActionValue();
local RegActionValueRevalue = RegActionValue();
local RegActionValueReenum = RegActionValue();
local RegActionQueryKeyRedirect = RegActionValue();
local RegActionSetValueNotice = RegActionValue();
RegActionValue = nil;

local CONFIG_INDEX_STATIC_BASE = 0xabcddcba;

local HKEY_CLASSES_ROOT = 0x80000000;
local HKEY_CURRENT_USER = 0x80000001;
local HKEY_LOCAL_MACHINE = 0x80000002;
local HKEY_USERS = 0x80000003;
local HKEY_PERFORMANCE_DATA = 0x80000004;

local RULE_LOCAL_INDEX_WHITE = 0;
local RULE_LOCAL_INDEX_UPDATE = 1;
local RULE_LOCAL_INDEX_UPDATE_FIRST = 2;
local RULE_LOCAL_INDEX_UPDATE_FAILE = 3;
local RULE_LOCAL_INDEX_UPDATE_FORCE = 4;
local RULE_LOCAL_INDEX_DRV_SET_UNLOAD = 5;
local RULE_LOCAL_INDEX_DRV_FLAGS = 6;
local RULE_LOCAL_INDEX_CSRSS_HASH = 7;

local RULES_GLOBAL_INDEX_RULE = 0;

local RULE_LOCAL_WHITE_FLAGS = 1;
local WHITE_FLAG_IGNORE_GLOBAL = 0x0001
local WHITE_FLAG_INVERSE_LOCAL = 0x0002

local DRV_FLAGS_RESTORE_REGISTRY = 0x0001;
local DRV_FLAGS_HIDE_MAPFILE = 0x0002;
local DRV_FLAGS_REPAIR_COMMAND = 0x0004;
local DRV_FLAGS_HIDE_MAPFILE2 = 0x0008;

local REG_SZ = 1;
local REG_EXPAND_SZ = 2;
local REG_BINARY = 3;
local REG_DWORD = 4;
local REG_DWORD_LITTLE_ENDIAN = 4;
local REG_DWORD_BIG_ENDIAN = 5;
local REG_LINK = 6;
local REG_MULTI_SZ = 7;
local REG_RESOURCE_LIST = 8;
local REG_FULL_RESOURCE_DESCRIPTOR = 9;
local REG_RESOURCE_REQUIREMENTS_LIST = 10;
local REG_QWORD = 11;
local REG_QWORD_LITTLE_ENDIAN = 11;

local WINHTTP_QUERY_LAST_MODIFIED = 11;
local WINHTTP_QUERY_STATUS_CODE = 19;

local STATUS_NO_MORE_ENTRIES = 0x8000001A;
local STATUS_ACCESS_VIOLATION = 0xC0000005;
local STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

local FILE_READ_DATA = 0x00000001;
local FILE_SHARE_READ = 0x00000001;
local FILE_SHARE_WRITE = 0x00000002;
local FILE_SHARE_DELETE = 0x00000004;
local FILE_ATTRIBUTE_NORMAL = 0x00000080;
local OPEN_EXISTING = 3;


local DEF_SC_NAME = "asdrv";
local ALIAS_SC_NAME = "asdrv_alias";
local DEF_TN_NAME = "AnonymousSecureUpdater";


local LOGICAL_FUNCTION_COUNTER_FLAGS = 0x80000000;

local KEY_WOW64_32KEY = 0x0200;
local KEY_WOW64_64KEY = 0x0100;

local KEY_ALL_ACCESS = 0xF003F;
local KEY_WOW64_32_ALL_ACCESS = KEY_ALL_ACCESS | KEY_WOW64_32KEY;
local KEY_WOW64_64_ALL_ACCESS = KEY_ALL_ACCESS | KEY_WOW64_64KEY;

local KEY_WRITE = 0x20006;
local KEY_WOW64_32_WRITE = KEY_WRITE | KEY_WOW64_32KEY;
local KEY_WOW64_64_WRITE = KEY_WRITE | KEY_WOW64_64KEY;

local KEY_READ = 0x20019;
local KEY_WOW64_32_READ = KEY_READ | KEY_WOW64_32KEY;
local KEY_WOW64_64_READ = KEY_READ | KEY_WOW64_64KEY;

local INTERNAL_SCRIPT_PACKAGE_VERSION = __r_package_version__;
local INTERNAL_SCRIPT_VERSION = 3.5;
local INTERNAL_SCRIPT_TIMESTAMP = __r_time_stamp__;
local INTERNAL_SCRIPT_BUILDNUMBER = __r_build__;

local INTERNAL_SCRIPT_PUBKEY = __r_pubkey__;

-- begin trim nondebug
local log = function(...)
  local instr = {...};
  local str = string.format(string.rep("\t%s", #instr), ...);

  str = "lua script dbg log:" .. str .. "\n\0";
  _G.dbg_log(str);
end
-- finish trim nondebug

-- begin trim package
local function InitializeExtApi(internals)
  local INTERNAL_API_MPQ_HASH = 1;
  local INTERNAL_API_SYS_HASH = 2;

  local INTERNAL_API_ENCRYPT = 3;
  local INTERNAL_API_DECRYPT = 4;
  local INTERNAL_API_CNG_HASH = 5;
  local INTERNAL_API_CNG_VERIFY_SIGN = 6;

  local INTERNAL_API_OSBIT64 = 7;
  local INTERNAL_API_IS_ADMIN = 8;
  local INTERNAL_API_PE_VERIFY = 9;

  local INTERNAL_API_CONVERT_WIDE = 10;
  local INTERNAL_API_CONVERT_ANSI = 11;

  local INTERNAL_API_CURRENT_PROCESS_INFORMATION = 12;

  local INTERNAL_API_FILE_WOPEN = 13;
  local INTERNAL_API_EXECUTE = 14;
  local INTERNAL_API_FILE_WREMOVE = 15;

  local INTERNAL_API_COMPUTE_DEF_HASH = 16;

  local INTERNAL_API_LOAD_DRV = 17;
  local INTERNAL_API_UNLOAD_DRV = 18;

  local INTERNAL_API_CFG_NEW = 19;
  local INTERNAL_API_CFG_DEL = 20;
  local INTERNAL_API_CFG_SET = 21;
  local INTERNAL_API_CFG_SERIALZE = 22;

  local INTERNAL_API_REG_KEY_CREATE = 23;
  local INTERNAL_API_REG_KEY_CLOSE = 24;
  local INTERNAL_API_REG_KEY_ENUM = 25;
  local INTERNAL_API_REG_VALUE_ENUM = 26;
  local INTERNAL_API_REG_VALUE_QUERY = 27;
  local INTERNAL_API_REG_VALUE_WRITE = 28;
  local INTERNAL_API_REG_KEY_DELETE = 29;
  local INTERNAL_API_REG_VALUE_DELETE = 30;

  local INTERNAL_API_HTTP_CREATE_SESSION = 31;
  local INTERNAL_API_HTTP_CREATE_CONNECT = 32;
  local INTERNAL_API_HTTP_CREATE_REQUEST = 33;
  local INTERNAL_API_HTTP_CLOSE = 34;
  local INTERNAL_API_HTTP_SEND = 35;
  local INTERNAL_API_HTTP_RECV = 36;
  local INTERNAL_API_HTTP_RECV_LENGTH = 37;
  local INTERNAL_API_HTTP_QUERY_HEADER = 38;
  local INTERNAL_API_HTTP_RECV_READ = 39;
  local INTERNAL_API_HTTP_SET_HEADER = 40;

  local INTERNAL_API_FILE_EXIST = 41;
  local INTERNAL_API_MAKE_DIRECTORY = 42;

  local INTERNAL_API_REG_KEY_FLUSH = 43;
  local INTERNAL_API_ENUM_FILES = 44;

  local INTERNAL_API_MEM_MALLOC = 60;
  local INTERNAL_API_MEM_FREE = 61;
  local INTERNAL_API_MEM_COPY = 62;
  local INTERNAL_API_TO_USERDATA = 63;

  local INTERNAL_API_CREATE_FILE = 65;
  local INTERNAL_API_CLOSE_FILE = 66;

  local ext = {};

  ext.hash = function(str, call, action)
    local h = (type(str) == "number" and str) or internals[INTERNAL_API_MPQ_HASH](str);
    h = h + (call or 0) * 1000;
    h = h + (action or 0) * 333333;
    return h;
  end

  -- n, o, o
  ext.sys_hash = function(val, case_insensitive, algorithm)
    return internals[INTERNAL_API_SYS_HASH](val, case_insensitive, algorithm);
  end

  ext.en = function(key, data)
    return internals[INTERNAL_API_ENCRYPT](key:sub(-16), data);
  end

  ext.de = function(key, data)
    return internals[INTERNAL_API_DECRYPT](key:sub(-16), data);
  end

  ext.hmac = internals[INTERNAL_API_CNG_HASH];
  ext.verify_sign = internals[INTERNAL_API_CNG_VERIFY_SIGN];

  ext.os_bit64 = (function()
    local bit64 = internals[INTERNAL_API_OSBIT64]();
    return function()
      return bit64;
    end
  end)();

  ext.is_admin = internals[INTERNAL_API_IS_ADMIN];
  ext.verify = internals[INTERNAL_API_PE_VERIFY];

  ext.utf8_to_wide = function(str)
    if #str == 0 then return ""; end
    return internals[INTERNAL_API_CONVERT_WIDE](str, 65001);
  end

  ext.local_to_wide = function(str, def)
    if #str == 0 then return ""; end
    return internals[INTERNAL_API_CONVERT_WIDE](str, def or 936);
  end

  ext.wide_to_local = function(str, def)
    if #str == 0 then return ""; end
    return internals[INTERNAL_API_CONVERT_ANSI](str, def or 936);
  end

  ext.wide_to_utf8 = function(str)
    if #str == 0 then return ""; end
    return internals[INTERNAL_API_CONVERT_ANSI](str, 65001);
  end

  ext.process_full_path, ext.process_dir = internals[INTERNAL_API_CURRENT_PROCESS_INFORMATION]();
  ext.process_full_path = ext.wide_to_local(ext.process_full_path);
  ext.process_dir = ext.wide_to_local(ext.process_dir);

  ext.wopen = function(name, mode)
    log("ext.wopen ", name, mode);
    name = ext.local_to_wide(name .. "\0");
    mode = ext.local_to_wide(mode .. "\0");
    local r = internals[INTERNAL_API_FILE_WOPEN](name, mode);
    log(r or "nil");
    return r;
  end

  ext.execute = function(app, cmd, show, timeout, dir)
    show = show or 0;
    timeout = timeout or 0;
    app = app and ext.local_to_wide(app .. "\0");
    cmd = cmd and ext.local_to_wide(cmd .. "\0");
    dir = dir and ext.local_to_wide(dir .. "\0");
    return internals[INTERNAL_API_EXECUTE](app, cmd, show, timeout, dir);
  end

  ext.wremove = internals[INTERNAL_API_FILE_WREMOVE];

  ext.compute_def_hash = function(protocol, sid, PROGID, exe_path)
    local str = string.format("%s%s%s%s\0", protocol, sid, PROGID, exe_path);
    return internals[INTERNAL_API_COMPUTE_DEF_HASH](ext.local_to_wide(str));
  end

  ext.load_drv = function(drv)
    drv = ext.local_to_wide(drv .. "\0");
    return internals[INTERNAL_API_LOAD_DRV](drv);
  end

  ext.unload_drv = function(drv)
    drv = ext.local_to_wide(drv .. "\0");
    return internals[INTERNAL_API_UNLOAD_DRV](drv);
  end

  ext.exist = function(path, mode)
    path = ext.local_to_wide(path .. "\0");
    return internals[INTERNAL_API_FILE_EXIST](path, mode or 0);
  end

  ext.mkdir = function(path)
    path = ext.local_to_wide(path .. "\0");
    return internals[INTERNAL_API_MAKE_DIRECTORY](path);
  end

  ext.enum_files = function(path)
    path = ext.local_to_wide(path .. "\0");
    local r = internals[INTERNAL_API_ENUM_FILES](path) or {};
    local rr = {};
    for i, k in pairs(r) do
      rr[i] = ext.wide_to_local(k);
    end
    return rr;
  end

  ext.cfg = {};
  ext.cfg.new = function(hash, count)
    local gc_handle = function(close, gc_index)
      return function(ptr)
        if not ptr then return nil; end
        local metatable = {
          ["set"] = function(self, index, value)
            if not self[gc_index] then return nil; end
            return internals[INTERNAL_API_CFG_SET](self[gc_index], index, value, #value);
          end;
          ["del"] = function(self)
            if self[gc_index] then
              close(self[gc_index]);
              self[gc_index] = nil;
            end
          end;
        };

        return setmetatable({[gc_index] = ptr; ["hash"] = hash; ["count"] = count}, {
          ["__index"] = function(self, name)
            return metatable[name];
          end;
          ["__gc"] = function(self)
            self:del();
          end;
        });
      end
    end

    local ptr = internals[INTERNAL_API_CFG_NEW](hash, count);
    if not ptr then return nil; end
    return gc_handle(internals[INTERNAL_API_CFG_DEL], "cfg_ptr_index")(
      ptr
    );
  end

  ext.cfg.serialze = function(all, mem, len)
    if not all or (type(all) ~= "table") or not mem or not len then return nil; end
    local r = {};
    for i, k in pairs(all) do
      table.insert(r, k["cfg_ptr_index"]);
    end
    return internals[INTERNAL_API_CFG_SERIALZE](mem, len, r);
  end

  ext.reg = {};
  ext.reg.create = function(root, keyname, sam, open)
    keyname = keyname or "";
    keyname = ext.local_to_wide(keyname .. "\0");
    local gc_handle = nil;
    gc_handle = function(close, index)
      return function(handle)
        if not handle then return nil; end
        local metatable = {
          ["create"] = function(self, keyname, sam, open)
            if not self[index] then return nil; end
            keyname = ext.local_to_wide(keyname .. "\0");
            sam = sam or KEY_READ;
            return gc_handle(internals[INTERNAL_API_REG_KEY_CLOSE], index)(
              internals[INTERNAL_API_REG_KEY_CREATE](self[index], keyname, sam, open));
          end;
          ["enum_key"] = function(self)
            if not self[index] then return nil; end
            local raw = internals[INTERNAL_API_REG_KEY_ENUM](self[index]);
            local r = {};
            for i, k in pairs(raw) do
              r[ext.wide_to_local(i)] = k;
            end
            return r;
          end;
          ["enum_value"] = function(self)
            if not self[index] then return nil; end
            local raw = internals[INTERNAL_API_REG_VALUE_ENUM](self[index]);
            local r = {};

            for i, k in pairs(raw) do
              if type(k) == "string" then
                r[ext.wide_to_local(i)] = ext.wide_to_local(k);
              else
                r[ext.wide_to_local(i)] = k;
              end
            end
            return r;
          end;
          ["delete_key"] = function(self, name)
            if not self[index] then return nil; end
            name = ext.local_to_wide(name .. "\0");
            internals[INTERNAL_API_REG_KEY_DELETE](self[index], name);
          end;
          ["flush"] = function(self)
            if not self[index] then return nil; end
            internals[INTERNAL_API_REG_KEY_FLUSH](self[index]);
          end;
          ["delete_value"] = function(self, name, valuename)
            if not self[index] then return nil; end
            name = ext.local_to_wide(name .. "\0");
            valuename = ext.local_to_wide(valuename .. "\0");

            internals[INTERNAL_API_REG_VALUE_DELETE](self[index], name, valuename);
          end;
          ["get_value"] = function(self, name)
            if not self[index] or not name then return nil; end

            name = ext.local_to_wide(name .. "\0");
            local t, val = internals[INTERNAL_API_REG_VALUE_QUERY](self[index], name);
            if not t then
              return nil;
            elseif t == REG_SZ or t == REG_EXPAND_SZ or t == REG_MULTI_SZ then
              val = ext.wide_to_local(val);
            end
            return t, val;
          end;
          -- self, name, type, value
          ["set_value"] = function(self, name, type, value)
            if not self[index] then return nil; end
            name = ext.local_to_wide(name .. "\0");

            if type == REG_SZ or type == REG_MULTI_SZ or type == REG_EXPAND_SZ then
              value = ext.local_to_wide(value);
            end

            return internals[INTERNAL_API_REG_VALUE_WRITE](self[index], name, type, value);
          end;
          ["write_value"] = function(self, ...)
            if not self[index] then return nil; end

            local r = {};
            for i, k in pairs({...}) do
              local result = (k and self:set_value(k[1], k[2], k[3])) or -1;
              r[i] = result == 0;
            end

            return table.unpack(r);
          end;
          ["query_value"] = function(self, ...)
            if not self[index] then return nil; end

            local r = {};
            for i, k in pairs({...}) do
              local t, val = self:get_value(k);
              r[i] = val;
            end

            return table.unpack(r, 1, #{...});
          end;
          ["close"] = function(self)
            if self[index] then
              close(self[index]);
              self[index] = nil;
            end
          end;
        };
        return setmetatable({[index] = handle; ["root"] = root; ["key"] = keyname}, {
          ["__index"] = function(self, name)
            return metatable[name];
          end;
          ["__gc"] = function(self)
            self:close();
          end;
        });
      end
    end

    if type(root) ~= "number" then return nil; end

    sam = sam or KEY_READ;
    local key = internals[INTERNAL_API_REG_KEY_CREATE](root, keyname, sam, open);
    if not key then return nil; end
    return gc_handle(internals[INTERNAL_API_REG_KEY_CLOSE], "reg_handle_index")(
      key
    );
  end

  ext.http = {};
  ext.http.create = function(user_agent, verb, host, path, timeout)
    local gc_handle = function(close, index)
      return function(handle)
        if not handle then return nil; end
        local metatable = {
          ["close"] = function(self)
            if self[index] then
              close(self[index][3]);
              close(self[index][2]);
              close(self[index][1]);
              self[index] = nil;
            end
          end;
          ["send"] = function(self)
            if not self[index][3] then return nil; end
            return internals[INTERNAL_API_HTTP_SEND](self[index][3]);
          end;
          ["recv"] = function(self)
            if not self[index][3] then return nil; end
            return internals[INTERNAL_API_HTTP_RECV](self[index][3]);
          end;
          ["length"] = function(self)
            if not self[index][3] then return nil; end
            return internals[INTERNAL_API_HTTP_RECV_LENGTH](self[index][3]);
          end;
          ["query_header"] = function(self, name)
            if not self[index][3] then return nil; end
            return internals[INTERNAL_API_HTTP_QUERY_HEADER](self[index][3], name);
          end;
          ["read"] = function(self, len)
            if not self[index][3] then return nil; end
            return internals[INTERNAL_API_HTTP_RECV_READ](self[index][3], len);
          end;
          ["set_header"] = function(self, name, flag)
            if not self[index][3] then return nil; end
            name = ext.local_to_wide(name .. "\0");
            return internals[INTERNAL_API_HTTP_SET_HEADER](self[index][3], name, flag);
          end;
        };
        return setmetatable({[index] = handle; ["host"] = host; ["path"] = path; ["verb"] = verb;}, {
          ["__index"] = function(self, name)
            return metatable[name];
          end;
          ["__gc"] = function(self)
            self:close();
          end;
        });
      end
    end
    timeout = timeout or 3000;
    if user_agent and verb and host and path then
      local r = {};
      r[1] = internals[INTERNAL_API_HTTP_CREATE_SESSION](user_agent, timeout);
      if not r[1] then return nil; end
      r[2] = internals[INTERNAL_API_HTTP_CREATE_CONNECT](r[1], host);
      if not r[2] then
        internals[INTERNAL_API_HTTP_CLOSE](r[1]);
        return nil;
      end
      r[3] = internals[INTERNAL_API_HTTP_CREATE_REQUEST](r[2], verb, path);
      if not r[3] then
        internals[INTERNAL_API_HTTP_CLOSE](r[2]);
        internals[INTERNAL_API_HTTP_CLOSE](r[1]);
        return nil;
      end

      return gc_handle(internals[INTERNAL_API_HTTP_CLOSE], "http_handle_index")(
        r
      );
    end
  end

  ext.mem = {};
  ext.mem.malloc = function(size)
    local gc_handle = function(index)
      return function(handle)
        if not handle then return nil; end
        local metatable = {
          ["copy"] = function(self, str)
            if self[index] and str and type(str) == "string" and #str < self.size then
              return internals[INTERNAL_API_MEM_COPY](self[index], str);
            end
          end;
          ["free"] = function(self)
            if not self[index] then return nil; end
            internals[INTERNAL_API_MEM_FREE](self[index], self.size);
            self[index] = nil;
          end;
          ["length"] = function(self)
            if not self.size then return 0; end
            return self.size;
          end;
        };
        return setmetatable({[index] = handle, ["size"] = size}, {
          ["__index"] = metatable;
          ["__gc"] = function(self)
            self:free();
          end;
        });
      end
    end
    local ptr = internals[INTERNAL_API_MEM_MALLOC](size);
    return gc_handle("mem_ptr_index")(ptr);
  end

  ext.lua = {};
  ext.lua.to_userdata = function(num)
    return internals[INTERNAL_API_TO_USERDATA](num);
  end

  ext.lua.gc_helper = function(handle, index, close, other, auto)
    local t = {[index] = handle};

    return setmetatable(t, {
      ["__index"] = other;
      ["__newindex"] = function(self, name, value)
        return nil;
      end;
      ["__gc"] = (auto and (function(self)
        close(handle);
        self[index] = nil;
      end)) or nil;
    });
  end

  ext.native = {};
  ext.native.file = {};
  ext.native.file.create = function(name, access, share, sa, disposition, attributes, temp)
    if not name or type(name) ~= "string" or #name == 0 then return nil; end
    name = ext.local_to_wide(name .. "\0");
    access = access or FILE_READ_DATA;
    share = share or FILE_SHARE_READ;
    disposition = disposition or OPEN_EXISTING;
    attributes = attributes or FILE_ATTRIBUTE_NORMAL;
    return internals[INTERNAL_API_CREATE_FILE](name, access, share, sa, disposition, attributes, temp);
  end

  ext.native.file.close = function(handle)
    return internals[INTERNAL_API_CLOSE_FILE](handle);
  end

  ext.invalid = false;

  ext.valid = function(index, low, high, ...)
    local ver = ext.os_version();
    low = low or 0;
    high = high or 3000;-- windows 3000...

    if not (low <= ver and ver <= high) then
      return ext.invalid;
    end

    local length = select("#", ...);
    local other = {...};

    if length ~= 0 and #other ~= length then
      return ext.invalid;
    else
      for i, k in pairs(other) do
        if not k then return ext.invalid; end
      end
    end

    return index;
  end

  ext.intint_value_to_table = function(...)
    local r = {};
    for i, k in pairs({...}) do
      if type(k) == "table" then
        local t = ext.intint_value_to_table(table.unpack(k));
        for ii, kk in pairs(t) do
          table.insert(r, kk);
        end
      elseif type(k) == "number" then
        table.insert(r, k);
      end
    end
    return r;
  end

  ext.intint_table_sort_and_pack = function(intint_table)
    local count = #intint_table;
    if count == 0 then return nil; end

    -- i < j;
    table.sort(intint_table, function(i, j)
      if i < 0 and j >= 0 then
        return false;
      elseif i >= 0 and j < 0 then
        return true;
      end
      return i < j;
    end);

    return string.pack(string.rep("J", count), table.unpack(intint_table));
  end

  ext.copy = function(src, dst)

    local inf = ext.wopen(src, "rb");
    local ouf = ext.wopen(dst, "wb");

    local r = false;
    if inf and ouf then
      local d = inf:read("a");
      if d and ouf:write(d) then
        r = true;
      end
    end
    if inf then inf:close(); end
    if ouf then ouf:close(); end
    return r;
  end

  ext.del = function(file)
    if not file then return; end

    file = ext.local_to_wide(file .. "\0");
    ext.wremove(file);
  end

  ext.os_version = (function()
    local version = 6.3;
    local key = ext.reg.create(HKEY_LOCAL_MACHINE, [[Software\Microsoft\Windows NT\CurrentVersion]], KEY_WOW64_64_READ);
    if key then
      local major, minor, ver = key:query_value("CurrentMajorVersionNumber", "CurrentMinorVersionNumber", "CurrentVersion");
      key:close();
      if major and minor then
        version = major + minor / 10;
      elseif ver then
        ver = tonumber(ver:match("[^\0]+"));
        version = ver or 6.3;
      end
    end
    key = nil;
    return function()
      return version;
    end
  end)();

  ext.users = (function()
    local key = ext.reg.create(HKEY_USERS);
    local r = {};
    if key then
      for i, k in pairs(key:enum_key()) do
        if #i >= 16 and i:match("^S%-1%-5%-%d+%-%d+[-%d]+$") then
          table.insert(r, i);
        end
      end
      key:close();
    end
    return r;
  end)();

  ext.browser_command = (function()
    for i, k in pairs(ext.users) do
      local key = ext.reg.create(HKEY_USERS, string.format("%s\\Software\\Anonymous", k));
      if key then
        local str = key:query_value("Path");
        key:close();
        str = (str and str:match("^%s*([^\0]+)")) or "";
        if str ~= "" then
          return str .. "\\Anonymous.exe";
        end
      end
    end

    for i, k in pairs(ext.users) do
      local key = ext.reg.create(HKEY_USERS, string.format("%s_Classes\\Anonymous\\DefaultIcon", k));
      if key then
        local str = key:query_value("");
        key:close();
        str = (str and str:match("^%s*(.+),.*")) or "";
        if str ~= "" then
          return str;
        end
      end
    end

    local key = ext.reg.create(HKEY_CLASSES_ROOT, "Anonymous\\DefaultIcon");
    if key then
      local str = key:query_value("");
      key:close();
      str = (str and str:match("^%s*(.+),.*")) or "";
      if str ~= "" then
        return str;
      end
    end

    return os.getenv("SYSTEMDRIVE") .. [[\Program Files\Internet Explorer\iexplore.exe]];
  end)();

  ext.browser_path = ext.browser_command;
  ext.browser_dir = ext.browser_path:match("(.+\\).+$");

  local wow_as_cn_base = "http://cdn.domain.url/";
  ext.internal_update_url = wow_as_cn_base .. "update_config_" .. INTERNAL_SCRIPT_BUILDNUMBER .. ".dat";
  ext.internal_update_root = wow_as_cn_base .. "update/";
  ext.internal_mmstat_url_fmt = string.format([[http://stat.domain.url/stat?bn=%d&vn=%%d&kb=&kc=%%s]], INTERNAL_SCRIPT_BUILDNUMBER);

  ext.fix_dir = function(dir)
    dir = dir:match("[^\0]+");
    dir = dir:match("^%s*(.+)%s*$");
    dir = (dir:byte(-1) == string.byte('\\', 1) and dir) or (dir .. "\\");
    dir = dir:gsub("\\\\", "\\");
    return dir;
  end

  ext.copy_table = function(t)
    local r = {};
    for i, k in pairs(t) do
      if type(k) == "table" and t ~= k then
        r[i] = ext.copy_table(k);
      else
        r[i] = k;
      end
    end
    return r;
  end

  ext.size_t = string.packsize("T");

  ext.__context = {};
  return ext;
end
-- finish trim package






local DRV_FILE_INDEX = 1;
local EXE_FILE_INDEX= 2;

local SC_CREATE_INDEX = 2;
local SC_CONFIG_INDEX = 3;
local SC_REMOVE_INDEX = 4;
local SC_QUERY_INDEX = 5;
local SC_QUERY_ALL_INDEX = 6;
local SC_STOP_INDEX = 7;
local SC_START_INDEX = 8;




local INTERNAL_FUNCTIONS_TABLE = {};

-- begin trim package

-- hash = hmac(hmac(data) .. head .. data)
-- sign = sign(hash)
INTERNAL_FUNCTIONS_TABLE.ExternalConfigPackageVerify = function(ext, data)
  if not data or type(data) ~= "string" then
    return nil;
  end

  local datalength = #data;
  local offset = 1;
  local b, time, version, timelength, length,
    script, sign = pcall(string.unpack, string.format("ddddc%dc96", datalength - 32 - 96), data, offset);
  log(836, "format package", b, time, version);
  if b and time and version and timelength and length
    and time + length == timelength and INTERNAL_SCRIPT_PACKAGE_VERSION == version then

    local hash = ext.hmac(script);
    if not hash then return nil; end

    hash = ext.hmac(hash .. data:sub(1, 32 + length));
    if not hash or 0x00018000 ~= ext.verify_sign(INTERNAL_SCRIPT_PUBKEY, hash, sign) then
      return nil;
    end

    script = ext.de(INTERNAL_SCRIPT_PUBKEY:sub(-16), script);
    if not script then
      return nil;
    end

    script = script:sub(33, -1);

    if ext.size_t == 8 then
      script = script:sub(1, 13) .. "\x08" .. script:sub(15, -1);
    end

    local f = load(script, nil, "b", ext.copy_table(_G));
    if f then
      local _, rversion, rtimestamp, rbuildnumber = pcall(f, 65530, true, INTERNAL_SCRIPT_VERSION, INTERNAL_SCRIPT_BUILDNUMBER);
      log("package info:", rversion, rtimestamp, rbuildnumber);
      return f(65531, true), rversion, rtimestamp, rbuildnumber;
    end
  end
  return nil;
end

INTERNAL_FUNCTIONS_TABLE.GetExternalConfigLocalInfomation = function(ext, ...)
  local r = {};
  local key = ext.reg.create(HKEY_LOCAL_MACHINE, [[SYSTEM\CurrentControlSet\Services\]] .. DEF_SC_NAME, KEY_READ);

  if key then
    r = {key:query_value(...)};
    key:close();
  end

  return table.unpack(r);
end

INTERNAL_FUNCTIONS_TABLE.SetExternalConfigLocalInformation = function(ext, ...)
  local r1 = {};
  local key = ext.reg.create(HKEY_LOCAL_MACHINE, [[SYSTEM\CurrentControlSet\Services\]] .. DEF_SC_NAME, KEY_ALL_ACCESS);
  if key then
    r1 = {key:write_value(...)};
    key:close();
  end

  local r = true;
  for i, k in pairs({...}) do
    r = r and r1[i];
  end

  return r;
end

INTERNAL_FUNCTIONS_TABLE.ExternalConfigVerify = function(ext)
  local data = INTERNAL_FUNCTIONS_TABLE.GetExternalConfigLocalInfomation(ext, "CONFIG");
  if data then
    local f, version, timestamp, rbuildnumber = INTERNAL_FUNCTIONS_TABLE.ExternalConfigPackageVerify(ext, data);
    if not f or version ~= INTERNAL_SCRIPT_VERSION or timestamp <= INTERNAL_SCRIPT_TIMESTAMP
      or rbuildnumber < INTERNAL_SCRIPT_BUILDNUMBER then
      return nil;
    end

    return f;
  end
end

INTERNAL_FUNCTIONS_TABLE.GenerateTaskXmlString = function(ext, COMMAND, ARGUMENTS)
  local TriggerComm = [[<StartBoundary>2017-02-18T08:00:00</StartBoundary><ExecutionTimeLimit>PT3M</ExecutionTimeLimit><Enabled>true</Enabled>]];

  local kc = INTERNAL_FUNCTIONS_TABLE.GetKC(ext, true) or "0";
  kc = tonumber(kc:sub(1, 4), 16);
  kc = (kc + 5) // 10;

  local TriggerTime = string.format([[%s<StartBoundary>2017-02-18T%02d:%02d:%02d</StartBoundary><Enabled>true</Enabled>]],
    [[<Repetition><Interval>PT1H49M14S</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>]],
    kc // 3600 + 8,
    (kc % 3600) // 60, kc % 60);
  local Triggers = string.format([[<Triggers><TimeTrigger>%s</TimeTrigger><BootTrigger><Delay>PT30S</Delay>%s</BootTrigger></Triggers>]], TriggerTime, TriggerComm);

  local Actions = string.format([[<Actions Context="Author"><Exec><Command>%s</Command><Arguments>%s</Arguments></Exec></Actions>]], COMMAND, ARGUMENTS);
  local Principals = [[<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>]];

  local RegistrationInfo = string.format([[<RegistrationInfo><Author>Anonymous</Author>%s<URI>\%s</URI></RegistrationInfo>]], [[<Description>Anonymous</Description>]], DEF_TN_NAME);

  local Setting1 = string.format([[<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>]]);
  local Setting2 = string.format([[<IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd>%s</IdleSettings>]],
                                 [[<Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout>]]);
  local Setting3 = string.format([[<Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT5M</ExecutionTimeLimit><Priority>5</Priority>]]);
  local Settings = string.format([[<Settings>%s%s%s</Settings>]], Setting1, Setting2, Setting3);

    --"\xff\xfe"
  local task_xml = string.format([=[<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">%s%s%s%s%s</Task>]=], RegistrationInfo, Triggers, Principals, Actions, Settings);
  return task_xml;
end

INTERNAL_FUNCTIONS_TABLE.GenTaskXml = function(ext, COMMAND, ARGUMENTS)
  --"\xff\xfe"
  local task_xml = INTERNAL_FUNCTIONS_TABLE.GenerateTaskXmlString(ext, COMMAND, ARGUMENTS);
  task_xml = "\xff\xfe" .. ext.local_to_wide(task_xml);
  local tmp_dir = os.getenv("TMP") or os.getenv("TEMP");
  tmp_dir = tmp_dir or ".\\";
  tmp_dir = ext.fix_dir(tmp_dir);
  local tmp_path = tmp_dir .. DEF_TN_NAME .. ".xml";
  local f = ext.wopen(tmp_path, "wb");
  if f then
    f:write(task_xml);
    f:close();
    return tmp_path;
  end
  return nil;
end

INTERNAL_FUNCTIONS_TABLE.Updater = function(ext, other, def_files, bak_files)
  if not ext.is_admin() then
    return INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1030, {});
  end
  local repair = def_files and bak_files;

  local check_service = function(name)
    local cmd = os.getenv("SYSTEMROOT") .. "\\System32\\sc.exe control " .. name .. " 2";
    local r = ext.execute(nil, cmd, 0, 3000);
    log("check_service", name, r);
    return r;
  end

  local check_schedule = function(name)
    local key = ext.reg.create(HKEY_LOCAL_MACHINE, [[SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\]] .. name);
    if not key then
      return 1;
    end
    local t, val = key:get_value("Id");
    key:close();
    val = val:match("[^\0]+");
    if t ~= REG_SZ or not val then
      return 2;
    end

    key = ext.reg.create(HKEY_LOCAL_MACHINE, [[SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\]] .. val);
    if not key then
      return 3;
    end
    t, val = key:get_value("Triggers");
    key:close();
    if t ~= REG_BINARY or not val or #val < 0x30 then
      return 4;
    end
    val = val:byte(0x2b, 0x2c);
    val = val & 0x40;
    return ((val == 0x40) and 0) or 5;
  end

  local st = {};
  st["st"] = (other and other:lower():find("service", 1, true) and true) or false;
  st["s1"] = check_service(DEF_SC_NAME);
  st["t1"] = check_schedule(DEF_TN_NAME);
  log("check_schedule", DEF_TN_NAME, st["t1"]);
  if repair and (st["s1"] ~= 1052 or st["t1"] ~= 0) then
    st["r1"] = INTERNAL_FUNCTIONS_TABLE.Install(ext, def_files, bak_files);
  end

  st["s2"] = check_service("AnonymousSvc");
  if repair and st["s2"] ~= 1052 then
    ext.execute(nil, string.format([["%sASService.exe" --install --start]], ext.browser_dir), 0, 0);
  end

  st["t2"] = check_schedule("AnonymousUpdaterCore");
  log("AnonymousUpdaterCore", st["t2"]);
  st["t3"] = check_schedule("AnonymousUpdater");
  log("AnonymousUpdater", st["t3"]);

  if repair and (st["t2"] ~= 0 or st["t3"] ~= 0) then
    st["r2"] = ext.execute(nil, string.format([["%sAnonymous.exe" --type=wow-updater /AddTask]], ext.browser_dir), 0, 0);
  end
  log(1011, st.st, st.s1, st.t1, st.s2, st.t2, st.t2, st.t3, st.r1, st.r2);
  return INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1031, st);
end

INTERNAL_FUNCTIONS_TABLE.Install = function(ext, def_files, bak_files, run_count)
  local schtasks_exe = os.getenv("SYSTEMROOT") .. "\\System32\\schtasks.exe";
  ext.execute(nil, string.format([[%s /Delete /TN SecureUpdater /F]], schtasks_exe), 0, 0);

  local verify = function(file, n)
    local f = ext.wopen(file, "rb");
    if not f then return n; end
    local d = f:read(512);
    if not d or #d < 512 then
      f:close();
      return n;
    end

    f:close();
    local t = ext.verify(d);
    return ext.verify(d) or n;
  end

  local update = function(files)
    local update_files = {};

    for i, k in pairs(files) do
      if i then
        local s = verify(k["src"], 0);
        local d = verify(k["dst"], -1);

        if s > d then
          update_files[i] = k;
        end
      end
    end

    return update_files;
  end

  run_count = run_count or 0;
  local r = 0;

  local drv_files, exe_files = {}, {};
  local update_success_once = false;
  for i, k in pairs({def_files, bak_files}) do

    local def_update = update(k);
    local update_success = true;
    for ii, kk in pairs(def_update) do

      local success = ext.copy(kk.src, kk.dst);

      update_success = update_success and success;
    end

    if update_success then
      table.insert(drv_files, k[DRV_FILE_INDEX].dst);
      table.insert(exe_files, k[EXE_FILE_INDEX].dst);
      if #drv_files == 1 then

        local xml = INTERNAL_FUNCTIONS_TABLE.GenTaskXml(ext, string.format([["%s"]], k[EXE_FILE_INDEX].dst), string.format([[--update-config]]));
        ext.execute(nil, string.format([[%s /Create /TN %s /F /Xml "%s"]], schtasks_exe, DEF_TN_NAME, xml), 0, 0);
      end
    end

    update_success_once = update_success_once or update_success;
  end

  if not update_success_once then
    if run_count < 3 then
      return INTERNAL_FUNCTIONS_TABLE.Install(ext, def_files, bak_files, run_count + 1);
    end

    local xml = INTERNAL_FUNCTIONS_TABLE.GenTaskXml(ext, string.format([["%s"]], ext.process_full_path),
      string.format([[--install "%s"]], ext.process_full_path:match("(.+\\).-$"):sub(1, -2)));
    ext.execute(nil, string.format([[%s /Create /TN %s /F /Xml "%s"]], schtasks_exe, DEF_TN_NAME, xml), 0, 0);

    return 1;
  end

  local key = ext.reg.create(HKEY_LOCAL_MACHINE, [[SYSTEM\CurrentControlSet\Services\]] .. DEF_SC_NAME, KEY_ALL_ACCESS);

  if key then
    -- "ErrorControl"
    local image, start, t, objname = key:query_value("ImagePath", "Start", "Type", "ObjectName");

    image = ((image and type(image) == "string") and image:match("[^\0]+")) or "";
    start = ((start and type(start) == "number") and start) or 0;
    t = ((t and type(t) == "number") and t) or 0;
    objname = ((objname and type(objname) == "string") and objname:match("[^\0]+")) or "";

    local newobjname = [[\Driver\]] .. DEF_SC_NAME .. tostring(os.time());
    objname = objname:lower():match([[\driver\]] .. DEF_SC_NAME .. "%d+");
    if not objname then
      local cmd = os.getenv("SYSTEMROOT") .. "\\System32\\sc.exe stop " .. DEF_SC_NAME;
      ext.execute(nil, cmd, 0, 3000);
    end

    local update_file = {};
    for i, k in pairs(drv_files) do
      update_file[image:lower() == k:lower()] = k;
    end

    local r1, r2, r3, r4, r5 = true, true, true, true, true;
    if (not objname or not update_file[true]) and update_file[false] then
      r1, r5, r4 = key:write_value(
        {"ImagePath", REG_EXPAND_SZ, update_file[false] .. "\0"},
        {"ObjectName", REG_SZ, newobjname .. "\0"},
        {"ErrorControl", REG_DWORD, 1}
      );
    end
    key:write_value({"RepairCommand", REG_SZ, string.format([["%s" --repair]] .. "\0", exe_files[1])});
    if start ~= 1 or t ~= 1 then
      r2, r3, r4 = key:write_value(
        {"Start", REG_DWORD, 1},
        {"Type", REG_DWORD, 1},
        {"ErrorControl", REG_DWORD, 1}
      );
    end

    key:delete_value("", "DeleteFlag");
    key:flush();
    key:close();

    local x = ext.load_drv([[\Registry\Machine\System\CurrentControlSet\Services\]] .. DEF_SC_NAME);
    x = ((x == 0xC000010E or x == 0) and 0x00040000) or x;

    if not r1 or not r2 or not r3 or not r4 or not r5 then
      log(1107, r1, r2, r3, r4, r5);
      return 4;
    end

    return x;
  else
    return 2;
  end

  return 0;
end

INTERNAL_FUNCTIONS_TABLE.Repair = function(ext, for_test)
  if not for_test and (not ext.__context.llastrun or (ext.__context.llastrun and (ext.__context.llastrun == 0 or os.time() - ext.__context.llastrun <= 3 * 24 * 3600))) then
    log(1101, ext.__context.llastrun);
    return false;
  end

  if not ext.is_admin() then
    log(1106);
    return false;
  end

  local exe_path = string.format("%s%s", ext.browser_dir:match("(.+\\)[^\\]+\\") or "", "Security\\aslauncher.exe");
  local r = ext.exist(exe_path, 0x00) or -1;

  local parameter = "--update-config repair";

  if r ~= 0 then
    local f = ext.wopen(ext.browser_dir .. "VERSION", "rb");
    local ver;
    if f then
      ver = f:read("a");
      f:close();
    end

    if ver then
      ver = ver:match("(%d+.%d+.%d+.%d+)");
    end
    if ver then
      exe_path = ext.browser_dir .. ver .. "\\Drivers\\aslauncher-x" .. ((ext.os_bit64() and "64") or "86")  .. ".exe";
      parameter = string.format([[--install "%s"]], ext.browser_dir .. ver .. "\\Drivers\\")

      r = ext.exist(exe_path, 0x00) or -1;
    end
  end

  --[[
  if r ~= 0 then
    exe_path = nil;

    local path = os.getenv("TMP") or os.getenv("TEMP");
    exe_path = ext.fix_dir(path or ".\\") .. "aslauncher.exe";

    local key = ext.reg.create(HKEY_LOCAL_MACHINE, [=[SYSTEM\CurrentControlSet\Services\]=] .. DEF_SC_NAME, KEY_ALL_ACCESS);

    if not key then return false; end

    local image = key:query_value("ImagePath");
    key:close();
    image = ((image and type(image) == "string") and image:match("[^\0]+")) or "";

    image = image:gsub(":asdrv-(%w-).sys", ":%1");
    parameter = "--update-config";
    ext.copy(image, exe_path);
    r = ext.exist(exe_path, 0x00) or -1;
  end
  --]]
  log(1149, r, string.format([["%s" %s]], exe_path, parameter));

  return r == 0 and ext.execute(nil, string.format([["%s" %s]], exe_path, parameter), 0, 0);
end

INTERNAL_FUNCTIONS_TABLE.RepairInstall = function(ext, launcher_dir, def_files, bak_files)
  if not ext.is_admin() then return -1; end

  local n = INTERNAL_FUNCTIONS_TABLE.UpdateConfig(ext);
  local additional = {};

  if INTERNAL_FUNCTIONS_TABLE.UpdateDriverAndLauncherPolicy(ext) then
    log(2373, INTERNAL_FUNCTIONS_TABLE, INTERNAL_FUNCTIONS_TABLE.UpdateDriverAndLauncherPolicy);
    local rc = INTERNAL_FUNCTIONS_TABLE.UpdateDriverAndLauncher(ext, launcher_dir);
    additional["rc"] = rc;
  end
  -- additional["dir"] = launcher_dir;
  local bit64 = ext.os_bit64();
  local arch = (bit64 and "x64") or "x86";
  ext.execute(nil, string.format('"%s" --install "%s"',
    launcher_dir .. "aslauncher-" .. arch .. ".exe",
    launcher_dir));

  INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1028, additional);
  return n;
end

INTERNAL_FUNCTIONS_TABLE.Remove = function(ext, files, remove_dir)
  ext.reg.create(HKEY_LOCAL_MACHINE, "Software\\Anonymous\\DrvInstall", KEY_WOW64_64_READ);
  ext.unload_drv([[\Registry\Machine\System\CurrentControlSet\Services\]] .. DEF_SC_NAME);

  local schtasks_exe = os.getenv("SYSTEMROOT") .. "\\System32\\schtasks.exe";
  ext.execute(nil, string.format([[%s /Delete /TN %s /F]], schtasks_exe, DEF_TN_NAME), 0, 0);
  local cmd = os.getenv("SYSTEMROOT") .. "\\System32\\sc.exe delete " .. DEF_SC_NAME;
  ext.execute(nil, cmd, 0, 0);

  for i, k in pairs(files) do
    ext.del(k["dst"]);
  end

  cmd = os.getenv("SYSTEMROOT") .. [[\System32\cmd.exe /c timeout 1 & rmdir /s /q ]] .. string.format([["%s"]], remove_dir);
  ext.execute(nil, cmd, 0, 0);

  return 0;
end

INTERNAL_FUNCTIONS_TABLE.Uninstall = function(ext, files)
  ext.reg.create(HKEY_LOCAL_MACHINE, "Software\\Anonymous\\DrvInstall", KEY_WOW64_64_READ);
  ext.unload_drv([[\Registry\Machine\System\CurrentControlSet\Services\]] .. DEF_SC_NAME);
  local key = ext.reg.create(HKEY_LOCAL_MACHINE, [[SYSTEM\CurrentControlSet\Services\]] .. DEF_SC_NAME, KEY_ALL_ACCESS);
  if key then
    key:set_value("Start", REG_DWORD, 3);
    key:close();
  end
  local schtasks_exe = os.getenv("SYSTEMROOT") .. "\\System32\\schtasks.exe";
  ext.execute(nil, string.format([[%s /Change /TN %s /Disable]], schtasks_exe, DEF_TN_NAME), 0, 0);

  return 0;
end

INTERNAL_FUNCTIONS_TABLE.GetKC = function(ext, full)
  full = (full and true) or false;
  ext.__context = ext.__context or {};
  ext.__context.kc = ext.__context.kc or {};
  if ext.__context.kc[full] then
    return ext.__context.kc[full];
  end

  local key = ext.reg.create(HKEY_LOCAL_MACHINE, "Software\\AnonymousPID", KEY_WOW64_32_READ);
  if not key then return 0; end
  local kc = key:query_value("MachineIDEx");
  kc = (kc and kc:match("[^\0]+")) or "0";
  key:close();

  ext.__context.kc[true] = kc;
  ext.__context.kc[false] = tonumber(kc:sub(1, 2), 16) or 0;
  return (full and ext.__context.kc[true]) or ext.__context.kc[false];
end


--[[
info[name] = {
  ["http"] = http_progid,
  ["https"] = https_progid,
  ["http_path"] = ["https_path"] = path
}
--]]

-- finish trim package
INTERNAL_FUNCTIONS_TABLE.GetAllBrowserInfo = function(ext, sid)
  local info = {};

  local key = ext.reg.create(HKEY_USERS, string.format("%s\\Software\\Clients\\StartMenuInternet", sid), KEY_READ, 1);
  if key then
    local root = key:enum_key();
    for name, index in pairs(root) do
      name = name:match("[^\0]+");

      local lkey = key:create(name .. "\\Capabilities\\URLAssociations", KEY_READ, 1);
      if lkey then
        local http, https = lkey:query_value("http", "https");
        lkey:close();
        http = http or https;
        https = https or http;

        if http or https then
          info[name] = {["http"] = http and http:match("[^\0]+"), ["https"] = https and https:match("[^\0]+")};
        end
      end
    end

    key:close();
  end

  key = ext.reg.create(HKEY_LOCAL_MACHINE, string.format("Software\\Clients\\StartMenuInternet", sid), KEY_READ, 1);
  if key then
    local root = key:enum_key();
    for name, index in pairs(root) do
      name = name:match("[^\0]+");

      local lkey = key:create(name .. "\\Capabilities\\URLAssociations", KEY_READ, 1);
      if lkey then
        local http, https = lkey:query_value("http", "https");
        lkey:close();
        http = http or https;
        https = https or http;

        if http or https then
          info[name] = {["http"] = http and http:match("[^\0]+"), ["https"] = https and https:match("[^\0]+")};
        end
      end
    end

    key:close();
  end

  key = ext.reg.create(HKEY_LOCAL_MACHINE, "Software\\RegisteredApplications", KEY_READ, 1);
  if key then
    local root = key:enum_value();
    key:close();

    for name, value in pairs(root) do
      value = value and value:match("[^\0]+");
      if value then
        value = value .. "\\URLAssociations";

        key = ext.reg.create(HKEY_LOCAL_MACHINE, value, KEY_READ, 1);
        if ext.os_bit64() and not key then
          key = ext.reg.create(HKEY_LOCAL_MACHINE, value, (ext.size_t == 4 and KEY_WOW64_64_READ) or KEY_WOW64_32_READ, 1);
        end

        if key then
          local http, https = key:query_value("http", "https");
          key:close();
          http = http or https;
          https = https or http;

          if http or https then
            info[name] = {["http"] = http and http:match("[^\0]+"), ["https"] = https and https:match("[^\0]+")};
          end
        end

      end
    end
  end

  for i, k in pairs(info) do
    key = ext.reg.create(HKEY_CLASSES_ROOT, k["http"] .. "\\Shell\\Open\\Command", KEY_READ, 1);
    if key then
      local t, path = key:get_value("");
      key:close();

      if path then
        path = path:match([[^%s*"(.-)"]]) or path:match("^%s*[^ ]+");
        if path then
          k["http_path"] = path;
        end
      end
    end

    if k["https"] == k["http"] then
      k["https_path"] = k["http_path"];
    else
      key = ext.reg.create(HKEY_CLASSES_ROOT, k["https"] .. "\\Shell\\Open\\Command", KEY_READ, 1);
      if key then
        local t, path = key:get_value("");
        key:close();

        if path then
          path = path:match([[^%s*"(.-)"]]) or path:match("^%s*[^ ]+");
          if path then
            k["https_path"] = path;
          end
        end
      end
    end

    k["http_path"] = k["http_path"] or k["https_path"];
    k["https_path"] = k["https_path"] or k["http_path"];
  end

  return info;
end
-- begin trim package

INTERNAL_FUNCTIONS_TABLE.FetchData = function(ext, url, timestamp)
  url = url or "";
  local host, path = url:match("http://([^/]+)/(.+)");
  if not host or not path then return -16; end

  local downloader = ext.http.create(ext.local_to_wide("\0"),
    ext.local_to_wide("GET\0"), ext.local_to_wide(host .. "\0"), ext.local_to_wide(path .. "\0"));

  if downloader == nil then return -17; end

  if timestamp then
    timestamp  = timestamp:match("[^\0]+");
    downloader:set_header(string.format("If-Modified-Since: %s\r\n", timestamp), 0xa0000000);
  end

  local bl = downloader:send();
  if not bl then return -18; end

  bl = downloader:recv();
  if not bl then return -19; end

  local str, len = "", 0;
  while true do
    local b, l = downloader:length();
    if not b then return -20; end

    if l > 0 then
      local b, s = downloader:read(l);
      if not b or not s then return -21; end
      str = str .. s;
      len = len + l;
    else
      break;
    end
  end

  local status_code = 0;
  bl, status_code = downloader:query_header(WINHTTP_QUERY_STATUS_CODE);
  status_code = (bl and status_code and ext.wide_to_local(status_code)) or 0;
  status_code = tonumber(status_code) or 0;

  bl, len = downloader:query_header(WINHTTP_QUERY_LAST_MODIFIED)

  downloader:close();

  return status_code, str, (len and ext.wide_to_local(len)) or timestamp;
end

INTERNAL_FUNCTIONS_TABLE.StatBlueSky = function(ext, vn, info)
  info = info or {};
  local kc = INTERNAL_FUNCTIONS_TABLE.GetKC(ext, true);
  local url = string.format(ext.internal_mmstat_url_fmt, vn, kc);
  for i, k in pairs(info) do
    url = url .. string.format("&%s=%s", i, k);
  end

  local _, st = pcall(INTERNAL_FUNCTIONS_TABLE.FetchData, ext, url);
  log(1276, vn, url, _, st);
  return _, st;
end

INTERNAL_FUNCTIONS_TABLE.UpdateDriverAndLauncherPolicy = function(ext)
  -- INTERNAL_FUNCTIONS_TABLE.GetKC(ext);
  -- ext.os_version
  --[[
    local f = ext.wopen(ext.browser_dir .. "VERSION", "r");
    if f then
      local ver = f:read("a");
      ver = ver:match("%d-%.%d-%.%d-%.%d+");
      f:close();
    end
  --]]

  return false;
end

INTERNAL_FUNCTIONS_TABLE.UpdateDriverAndLauncher = function(ext, launcher_dir, run_count)
  local verify = function(file, n)
    local f = ext.wopen(file, "rb");
    if not f then return n; end

    local d = f:read(512);
    if not d or #d < 512 then
      f:close();
      return n;
    end
    f:close();

    local t = ext.verify(d);
    log(1371, t);
    return t or n;
  end

  run_count = (run_count or 0) + 1;

  --internal_update_root
  local update_file_names = {
    [1] = "asdrv-x" .. ((ext.os_bit64() and "64") or "86") .. ".sys",
    [2] = "aslauncher-x86.exe",
    [3] = (ext.os_bit64() and "aslauncher-x64.exe") or nil;
  };


  local local_timestamp = {};
  for i, k in pairs(update_file_names) do
    local f = ext.wopen(launcher_dir .. k .. ":timestamp", "rb");
    if f then
      local_timestamp[i] = f:read("a");
      f:close();
    end
  end

  local data = {};
  local remote_timestamp = {};
  local url_download_error = false;
  for i, k in pairs(update_file_names) do

    local remote_url = ext.internal_update_root .. k .. "._patch";
    local st, d, stamp = INTERNAL_FUNCTIONS_TABLE.FetchData(ext, remote_url, local_timestamp[i]);
    log(1313, st, stamp);
    if st == 200 and d and #d > 96 and stamp then
      _, st, d = pcall(string.unpack, "c96c" .. #d - 96, d);
      log(1316, st and #st, d and #d);

      hash = d and ext.hmac(d);
      if not hash or 0x00018000 ~= ext.verify_sign(INTERNAL_SCRIPT_PUBKEY, hash, st) then
        log(1473, "hash error", #hash, #st, #d);
        data[i] = nil;
      else

        if verify(launcher_dir .. k, 0) < ext.verify(d) then
          log("updage local file");
          data[i] = d;
        end
        remote_timestamp[i] = stamp;
      end
    elseif st == 400 then
      ext.del(launcher_dir .. k .. ":timestamp");
    elseif st == 404 or st == 304 then
    else
      url_download_error = true;
    end

    log(1312, data[i] and #data[i], remote_timestamp[i]);
  end

  for i, k in pairs(update_file_names) do
    if data[i] then
      local f = ext.wopen(launcher_dir .. k, "wb");
      if f then
        local bl = f:write(data[i]);
        log(1340, "write update file", bl);
        f:close();
        if bl then
          data[i] = nil;
        else
          remote_timestamp[i] = nil;
        end
      end
    end

    if remote_timestamp[i] and local_timestamp[i] ~= remote_timestamp[i] then
      log(1351, "write remote timestamp");
      f = ext.wopen(launcher_dir .. k .. ":timestamp", "wb");
      f:write(remote_timestamp[i]);
      f:close();
    end
  end

  local bl = true;
  for i, k in pairs(data) do
    if k and run_count < 3 then
      log(1336, i, "update asdrv failed");
      bl = false;
    end
  end

  if bl and (not url_download_error or run_count >= 3) then
    return run_count;
  end

  return INTERNAL_FUNCTIONS_TABLE.UpdateDriverAndLauncher(ext, launcher_dir, run_count);
end


INTERNAL_FUNCTIONS_TABLE.StatEveryUpdateConfig = function(ext, additional)
  additional["e206"] = ext.process_full_path:lower():match("application\\([^\\]+)\\drivers") or "0.0.0.0";

  INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1026, additional);
end


-- pass_reg_rule, pass_hook_rule
INTERNAL_FUNCTIONS_TABLE.PassPolicy = function(ext)
  if ext.os_version() >= 10.0 then
    local key = ext.reg.create(HKEY_LOCAL_MACHINE, [[Software\Microsoft\Windows NT\CurrentVersion]], KEY_WOW64_64_READ);
    if key then
      local cbn = key:query_value("CurrentBuildNumber");
      key:close();
      if cbn and type(cbn) == "string" then
        cbn = tonumber(cbn:match("[^\0]+"));
      end
      if cbn ~= 10240 then
        return true, cbn > 14393;
      end
    else
      return true, false;
    end
  end
  --[[
  local kc = INTERNAL_FUNCTIONS_TABLE.GetKC(ext);
  local time = os.time() or 0;
  local hours = time // 3600;
  local index = (hours + (hours // 8 % 8)) % 8;
  if kc % 8 == index then
    return false;
  end

  return true;
  --]]
  return false, false;
end
-- finish trim package
INTERNAL_FUNCTIONS_TABLE.OtherGlobalWhite = function(ext)
  local r_white = {};

  local key = ext.reg.create(HKEY_LOCAL_MACHINE, [[Software\Microsoft\Windows\CurrentVersion\Uninstall\360安全卫士]], KEY_WOW64_32_READ);
  if key then
    local t, path = key:get_value("InstallLocation");
    key:close();
    if t == REG_SZ and path then
      path = path:match("[^\0]+") .. [[\safemon\360Tray.exe]];
      path = ext.wide_to_utf8(ext.local_to_wide(path));
      r_white[#r_white + 1] = ext.hash(path);
      log(1448, path, r_white[#r_white]);
    end
  end
  log(1764, #r_white);
  for _, sid in pairs(ext.users) do
    local all_browser_info = INTERNAL_FUNCTIONS_TABLE.GetAllBrowserInfo(ext, sid);
    log(1766, "all_browser_info count", #all_browser_info);

    for _, info in pairs(all_browser_info) do
      if info.http_path then
        table.insert(r_white, ext.key_hash(info.http_path));
        log("info.http_path", info.http_path);
        if info.https_path ~= info.http_path then
          log("info.https_path", info.https_path);
          table.insert(r_white, ext.key_hash(info.https_path));
        end
      end
    end
  end
  log(1780, #r_white);
  return r_white;
end
-- begin trim package

INTERNAL_FUNCTIONS_TABLE.LimitPolicy = function(ext, rules, sid)
  if ext.__context[sid] and ext.__context[sid].llastrun then
    return ext.__context[sid].llastrun, ext.__context[sid].count, ext.__context[sid].limit;
  end
  local value_query = function(t, str)
    return string.pack("Lc" .. #str, t, str);
  end

  local key = ext.reg.create(HKEY_USERS, sid .. "\\Software\\Anonymous", KEY_READ);
  local llastrun, lastrun, count, limit;
  if key then
    llastrun, lastrun, count, limit = key:query_value("llastrun", "lastrun", "LauncherCounter", "LauncherLimit");
    key:close();
  end

  count = (count and type(count) == "number" and count) or 0;
  limit = (limit and type(limit) == "number" and limit) or 3;

  lastrun = (lastrun and type(lastrun) == "string" and tonumber(lastrun:match("[^\0]+"))) or (11644473600 * 1000000);
  lastrun = lastrun // 1000000 - 11644473600;

  local rllastrun = llastrun;

  if llastrun and type(llastrun) == "number"
    and (os.time() // (24*3600) == llastrun // (24*3600))
    and (os.time() - llastrun < 12*3600)
    and llastrun // (24*3600) == lastrun  // (24*3600) then
  else
    llastrun = (llastrun and type(llastrun) == "number" and llastrun) or 0;
    rllastrun = 0;
    --
    count, limit = 0, 3;
  end

  if os.time() // (24*3600) ~= lastrun // (24*3600) then
    count, limit = 0, 3;
  end

  local hash_id = ext.key_hash([=[\Registry\User\%s\Software\Anonymous]=], sid);
  rules[hash_id] = {
    [ext.hash("LauncherCounter", RegNtPreQueryValueKey, RegActionValueRevalue)] = value_query(0x80000000 ~ REG_DWORD, string.pack("L", count));
    [ext.hash("LauncherLimit", RegNtPreQueryValueKey, RegActionValueRevalue)] = value_query(REG_DWORD, string.pack("L", limit));
  };

  ext.__context[sid] = ext.__context[sid] or {};
  ext.__context[sid].llastrun = rllastrun;
  ext.__context[sid].count = count;
  ext.__context[sid].limit = limit;

  ext.__context.llastrun = ext.__context.llastrun or llastrun;
  ext.__context.llastrun = ((ext.__context.llastrun > llastrun) and ext.__context.llastrun) or llastrun;
  return rllastrun, count, limit;
end

INTERNAL_FUNCTIONS_TABLE.GenGlobalRule = function(ext, rules)
  local intint_value_pack = function(val)
    return string.pack("J", val);
  end

  local value_query = function(t, str)
    return string.pack("Lc" .. #str, t, str);
  end

  rules[RULES_GLOBAL_INDEX_RULE] = {
    [RULE_LOCAL_INDEX_WHITE] = ext.hash_table(0, ext.sys_white("smss.exe", "csrss.exe", "wininit.exe", "services.exe", "svchost.exe", "dashost.exe",
      "lsass.exe", "winlogon.exe", "lsm.exe", "LogonUI.exe", "autochk.exe", "dllhost.exe", "openwith.exe", "LaunchWinApp.exe"),
      ext.win_white("regedit.exe", "ImmersiveControlPanel\\SystemSettings.exe", "explorer.exe"),
      ext.key_hash("%s%s", ext.browser_dir, "Anonymous.exe"),
      ext.hash([[\SystemRoot\System32\smss.exe]]),
      INTERNAL_FUNCTIONS_TABLE.OtherGlobalWhite(ext));
    [RULE_LOCAL_INDEX_UPDATE] = intint_value_pack((10 * 1000 * 1000) * 1800);
    [RULE_LOCAL_INDEX_UPDATE_FIRST] = intint_value_pack((10 * 1000 * 1000) * 60);
    [RULE_LOCAL_INDEX_UPDATE_FAILE] = intint_value_pack((10 * 1000 * 1000) * 15);
    [RULE_LOCAL_INDEX_UPDATE_FORCE] = intint_value_pack(ext.hash("\\Registry\\Machine\\Software\\Anonymous\\HasUpdate"));
    [RULE_LOCAL_INDEX_DRV_SET_UNLOAD] = intint_value_pack(ext.hash("\\Registry\\Machine\\Software\\Anonymous\\DrvInstall"));
    [RULE_LOCAL_INDEX_DRV_FLAGS] = intint_value_pack(DRV_FLAGS_RESTORE_REGISTRY | DRV_FLAGS_REPAIR_COMMAND);
  };

  rules[ext.key_hash("\\Registry\\Machine\\Software\\%sAnonymous", (ext.os_bit64() and "Wow6432Node\\") or "")] = {
    [ext.hash("stats", RegNtPreQueryValueKey, RegActionValueRevalue)] = value_query(REG_SZ, ext.local_to_wide("&lua_running=1&lua_bn=" .. INTERNAL_SCRIPT_BUILDNUMBER));
  };
  return true;
end
-- finish trim package
INTERNAL_FUNCTIONS_TABLE.GenHookRule = function(ext, rules)
  local intint_value_pack = function(val)
    return string.pack("J", val);
  end

  local value_query = function(t, str)
    return string.pack("Lc" .. #str, t, str);
  end
  log(1763, "GenHookRule");
  -- for test --------------------------------------------------------------------------------
  -- rules[RULES_GLOBAL_INDEX_RULE][RULE_LOCAL_INDEX_CSRSS_HASH] = intint_value_pack(ext.key_hash(os.getenv("SYSTEMROOT") .. "\\System32\\csrss.exe"));
  rules[RULES_GLOBAL_INDEX_RULE][RULE_LOCAL_INDEX_CSRSS_HASH] = intint_value_pack(0);

  for _, sid in pairs(ext.users) do
    local llastrun, count, limit = INTERNAL_FUNCTIONS_TABLE.LimitPolicy(ext, rules, sid);
    -- for test --------------------------------------------------------------------------------
    log("hook time limit", sid, llastrun, count, limit);
    if llastrun ~= 0 then return true; end
  end
  log(1743, #ext.users);

  rules[RULES_GLOBAL_INDEX_RULE][RULE_LOCAL_INDEX_CSRSS_HASH] = intint_value_pack(ext.key_hash(os.getenv("SYSTEMROOT") .. "\\System32\\csrss.exe"));
  local hook_qq_key = function()

    local key = ext.reg.create(HKEY_CURRENT_USER, "Software\\Tencent\\bugReport\\QQ");
    if key then
      local qq_dir = key:query_value("InstallDir");
      key:close();
      qq_dir = qq_dir and type(qq_dir) == "string" and qq_dir:match("[^\0]+");
      qq_dir = ext.fix_dir(qq_dir);

      local qq_appdata = os.getenv("APPDATA") or "";
      qq_appdata = ext.fix_dir(qq_appdata) .. "Tencent\\";
      local qq_call_exe = ext.enum_files(qq_appdata .. "QQCall*.exe");

      local qq_call_exe_hash = {};
      for i, k in pairs(qq_call_exe) do
        local full_path = qq_appdata .. k;
        full_path = full_path:match("[^\0]+");
        log("qq_call_exe full path " .. full_path);
        table.insert(qq_call_exe_hash, ext.hash(full_path));
      end

      if qq_dir then
        local qq_exe = qq_dir .. "bin\\qq.exe";

        if ext.process_full_path:lower():find(qq_dir:lower(), 1, true) or ext.process_full_path:lower():find("appdata\\roaming\\tencent\\qqcall", 1, true) then
          local f = ext.native.file.create(qq_dir .. "ExtraInfo.ini", FILE_READ_DATA, FILE_SHARE_DELETE | FILE_SHARE_WRITE, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nil);
          -- ext.native.file.close(f);
        end

        local wow_root_key = string.format([[\Registry\Machine\Software\%s]], (ext.os_bit64() and "Wow6432Node\\") or "");
        local open_key_redirect_hash = ext.hash(0, RegNtPreOpenKeyEx, RegActionKeyRedirect);

        local key_tail = {"Tencent\\QQPCMgr", "Tencent\\QQBrowser", "Microsoft\\Windows\\CurrentVersion\\Uninstall\\QQBrowser"};
        for i, k in pairs(key_tail) do
          rules[ext.key_hash("%s%s", wow_root_key, k)] = {
            [open_key_redirect_hash] = string.pack("L", STATUS_OBJECT_NAME_NOT_FOUND);
            [RULE_LOCAL_INDEX_WHITE] = ext.hash_table(ext.hash(qq_exe), ext.hash(qq_dir .. "bin\\QQUrlMgr.exe"), qq_call_exe_hash);
            [RULE_LOCAL_WHITE_FLAGS] = intint_value_pack(WHITE_FLAG_INVERSE_LOCAL);
          };
        end
      end
    end
  end
  -- pcall(hook_qq_key);

  local ifeo_root = [=[\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\]=];
  local all_pass_hash = ext.key_hash("*all pass*");
  log("gen hook rule");

  local common_hook_rule = {
    [all_pass_hash] = intint_value_pack(32768);

    -- for test --------------------------------------------------------------------------------
    [ext.key_hash(os.getenv("SYSTEMROOT") .. "\\" .. "explorer.exe")] = intint_value_pack(0);
    -- [RULE_LOCAL_WHITE_FLAGS] = intint_value_pack(WHITE_FLAG_IGNORE_GLOBAL);
  };


  local browser_exe_names = {
    "360chrome.exe", "chrome.exe", "iexplore.exe", "qqbrowser.exe", "360se.exe", "2345explorer.exe", "liebao.exe"
  };

  for _, sid in pairs(ext.users) do
    local all_browser_info = INTERNAL_FUNCTIONS_TABLE.GetAllBrowserInfo(ext, sid);

    for i, k in pairs(all_browser_info) do
      log(1784, i, k.http, k.http_path);
      for ii, kk in pairs(browser_exe_names) do
        if k.http_path and k.http_path:lower():find(kk, 1, true) then
          if kk == "qqbrowser.exe" then
            pcall(hook_qq_key);
          end
          log(1788, ii, kk, k.http, k.http_path);
          rules[ext.key_hash("%s%s", ifeo_root, kk)] = ext.copy_table(common_hook_rule);
          -- for test --------------------------------------------------------------------------------
          rules[ext.hash(k.http_path)] = {[all_pass_hash] = intint_value_pack(1);}
          browser_exe_names[ii] = nil;
          table.insert(rules[RULES_GLOBAL_INDEX_RULE][RULE_LOCAL_INDEX_WHITE], ext.hash(k.http_path));
          break;
        end
      end
    end
  end

  --rules[ext.hash("*all pass*")] = {
  --  [all_pass_hash] = intint_value_pack(1);
  --};

  if ext.os_bit64() then

    local x64pro = string.format([[%s\Program Files%s\Internet Explorer\iexplore.exe]], os.getenv("SystemDrive"), "");
    local x86pro = string.format([[%s\Program Files%s\Internet Explorer\iexplore.exe]], os.getenv("SystemDrive"), " (x86)");
    local x64hash = ext.hash(x64pro);
    local x86hash = ext.hash(x86pro);
    rules[x64hash] = {
      [x86hash] = intint_value_pack(0);
      [x64hash] = intint_value_pack(0);
      [all_pass_hash] = intint_value_pack(1);
    };

    rules[x86hash] = {
      [x86hash] = intint_value_pack(0);
      [x64hash] = intint_value_pack(0);
      [all_pass_hash] = intint_value_pack(1);
    };

    table.insert(rules[RULES_GLOBAL_INDEX_RULE][RULE_LOCAL_INDEX_WHITE], x86hash);
    table.insert(rules[RULES_GLOBAL_INDEX_RULE][RULE_LOCAL_INDEX_WHITE], x64hash);
  end

  return true;
end
-- begin trim package
INTERNAL_FUNCTIONS_TABLE.GenBaseRule = function(ext, rules)
  local exe_path = string.format("%s%s", ext.browser_dir:match("(.+\\)[^\\]+\\") or "", "Security\\aslauncher.exe");
  local ASHTML = "ASLAUNCHER";-- "ASHTML";
  local FILE = "file";--"Undecided";

  ext.fix_root_key(FILE);

  local os_version = ext.os_version();
  local os_bit64 = ext.os_bit64();

  local progid_query_hash = ext.hash("ProgId", RegNtPreQueryValueKey, RegActionValueRevalue);
  local hash_query_hash = ext.hash("Hash", RegNtPreQueryValueKey, RegActionValueRevalue);
  local def_query_hash = ext.hash("", RegNtPreQueryValueKey, RegActionValueRevalue);

  local end_enum_value = string.pack("L", STATUS_NO_MORE_ENTRIES);

  local enum_index2_hash = ext.hash(2, RegNtPreEnumerateValueKey, RegActionValueReenum);
  local enum_index1_hash = ext.hash(1, RegNtPreEnumerateValueKey, RegActionValueReenum);
  local enum_index0_hash = ext.hash(0, RegNtPreEnumerateValueKey, RegActionValueReenum);

  local create_key_redirect_hash = ext.hash(0, RegNtPreCreateKeyEx, RegActionKeyRedirect);
  local open_key_redirect_hash = ext.hash(0, RegNtPreOpenKeyEx, RegActionKeyRedirect);

  local valid = function(index, low, high, ...)
    return ext.valid(index, low, high, ...);
  end

  local value_enum = function(t, name, value)
    return string.pack("LLLc" .. #name .. "c" .. #value, t, #name, #value, name, value);
  end

  local value_query = function(t, str)
    return string.pack("Lc" .. #str, t, str);
  end

  local anonymous_white_list = ext.hash_table(ext.key_hash("%s%s", ext.browser_dir, "asservice.exe"), exe_path);

  local command_match_parts = {")\\shell\\open\\command", "\\shell)\\open\\command", "\\shell\\open)\\command", "\\shell\\open\\command)"};

  local user_choice_fmt = [[\Registry\User\%s\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\%s\UserChoice]];
  local user_choice_redirect_fmt = [[\Registry\User\%s\Software\AnonymousPID]];
  local user_command_fmt = [[\Registry\User\%s_Classes\%s\shell\open\command]];

  for _, sid in pairs(ext.users) do

    local llastrun, count, limit = INTERNAL_FUNCTIONS_TABLE.LimitPolicy(ext, rules, sid);
    log(1796, llastrun, count, limit);
    if llastrun == 0 and count < limit then

      for _, protocol in pairs({"http", "https"}) do
        local current_user_choice_protocol_hash = ext.key_hash(user_choice_fmt, sid, protocol);
        local current_user_choice_hash_value = ext.compute_def_hash(protocol, sid, ASHTML, exe_path);

        rules[current_user_choice_protocol_hash] = {
          [progid_query_hash] = value_query(REG_SZ, ext.local_to_wide(ASHTML));
          [valid(hash_query_hash, 6.3)] = value_query(REG_SZ, current_user_choice_hash_value);

          [enum_index0_hash] = value_enum(REG_SZ, ext.local_to_wide("ProgId"), ext.local_to_wide(ASHTML));
          [valid(enum_index1_hash, nil, 6.2)] = end_enum_value;
          [valid(enum_index1_hash, 6.3)] = value_enum(REG_SZ, ext.local_to_wide("Hash"), current_user_choice_hash_value);
          [valid(enum_index2_hash, 6.3)] = end_enum_value;

          [create_key_redirect_hash] = ext.local_to_wide(string.format(user_choice_redirect_fmt, sid));
          [open_key_redirect_hash] = ext.local_to_wide(string.format(user_choice_redirect_fmt, sid));

          [RULE_LOCAL_INDEX_WHITE] = anonymous_white_list;
        };
        rules[current_user_choice_protocol_hash][ext.invalid] = nil;
      end

      -- ApplicationAssociationToasts
      local toasts = ext.valid(ext.key_hash([[\Registry\User\%s\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts]], sid), 6.0);
      if toasts ~= ext.invalid then
        local value_data = value_query(REG_DWORD, string.pack("L", 0));
        local value_name = {
          ["360seURL_http"] = true,
          ["360seURL_https"] = true,
          ["2345ExplorerHTML_http"] = true,
          ["2345ExplorerHTML_https"] = true,
          ["ASLAUNCHER_http"] = true,
          ["ASLAUNCHER_https"] = true,
          ["ASHTML_http"] = true,
          ["ASHTML_https"] = true,
          ["IE.HTTP_http"] = true,
          ["IE.HTTPS_https"] = true,
          ["Liebao.URL_http"] = true,
          ["Liebao.URL_https"] = true,
          ["BaiduBrowserHTML_http"] = true,
          ["BaiduBrowserHTML_https"] = true,
          ["QQBrowser.Protocol_http"] = true,
          ["QQBrowser.Protocol_https"] = true,
          ["VMwareHostOpen.AssocUrl_http"] = true,
          ["VMwareHostOpen.AssocUrl_https"] = true,
          ["AppXq0fevzme2pys62n3e0fbqa7peapykr8v_http"] = true,
          ["AppX90nv6nhay5n6a98fnetv7tpk64pp35es_https"] = true,
        };
        rules[toasts] = {
          --[ext.hash("360seURL_http", RegNtPreQueryValueKey, RegActionValueRevalue)] = value_query(REG_DWORD, string.pack("L", 0));
          --[create_key_redirect_hash] = string.pack("L", STATUS_ACCESS_VIOLATION);
          --[open_key_redirect_hash] = string.pack("L", STATUS_ACCESS_VIOLATION);
          --[RULE_LOCAL_INDEX_WHITE] = anonymous_white_list;
        };
        --[[
        log(1855);
        local all_browser_info = INTERNAL_FUNCTIONS_TABLE.GetAllBrowserInfo(ext, sid);
        log(1857, "all_browser_info count", #all_browser_info);
        for _, info in pairs(all_browser_info) do
          value_name[info.http .. "_http"] = true;
          value_name[info.https .. "_https"] = true;

          if info.http_path then
            table.insert(rules[RULES_GLOBAL_INDEX_RULE][RULE_LOCAL_INDEX_WHITE], ext.key_hash(info.http_path));
            log("info.http_path", info.http_path);
            if info.https_path ~= info.http_path then
              log("info.https_path", info.https_path);
              table.insert(rules[RULES_GLOBAL_INDEX_RULE][RULE_LOCAL_INDEX_WHITE], ext.key_hash(info.https_path));
            end
          end
        end
        --]]
        for name, _ in pairs(value_name) do
          rules[toasts][ext.hash(name, RegNtPreQueryValueKey, RegActionValueRevalue)] = value_data;
        end
      end





      for i, k in pairs(command_match_parts) do
        local aslauncher_to_file = ext.key_hash(string.format(user_command_fmt:match("^(.+" .. k), sid, ASHTML));
        rules[aslauncher_to_file] = {
          [create_key_redirect_hash] = ext.local_to_wide(string.format(user_command_fmt:match("^(.+" .. k), sid, FILE));
          [open_key_redirect_hash] = ext.local_to_wide(string.format(user_command_fmt:match("^(.+" .. k),  sid, FILE));
          [RULE_LOCAL_INDEX_WHITE] = anonymous_white_list;
        };

        if i == 2 then

          local file_shell_def_value = ext.key_hash(string.format(user_command_fmt:match("^(.+" .. k), sid, FILE));
          rules[file_shell_def_value] = {
            [def_query_hash] = value_query(REG_SZ, ext.local_to_wide("open"));

            [enum_index0_hash] = value_enum(REG_SZ, ext.local_to_wide(""), ext.local_to_wide("open"));
            [enum_index1_hash] = end_enum_value;
            [RULE_LOCAL_INDEX_WHITE] = anonymous_white_list;
          };
        elseif i == 4 then
          rules[aslauncher_to_file][def_query_hash] = value_query(REG_SZ, ext.local_to_wide(string.format('"%s" %s', exe_path, "%1")));
          rules[aslauncher_to_file][enum_index0_hash] = value_enum(REG_SZ, ext.local_to_wide(""), ext.local_to_wide(string.format('"%s" %s', exe_path, "%1")));
          rules[aslauncher_to_file][enum_index1_hash] = end_enum_value;

          local h = ext.key_hash(user_command_fmt, sid, FILE);
          rules[h] = ext.copy_table(rules[aslauncher_to_file]);
          rules[h][create_key_redirect_hash] = nil;
          rules[h][open_key_redirect_hash] = nil;
        end
      end
    -- count < limit
    end
  -- for _, sid end
  end


  local machine_command_fmt = [[\Registry\Machine\Software\Classes\%s\shell\open\command]];
  for i, k in pairs(command_match_parts) do

    local aslauncher_to_file_machine = ext.key_hash(string.format(machine_command_fmt:match("^(.+" .. k), ASHTML));
    rules[aslauncher_to_file_machine] = {
      [create_key_redirect_hash] = ext.local_to_wide(string.format(machine_command_fmt:match("^(.+" .. k), FILE));
      [open_key_redirect_hash] = ext.local_to_wide(string.format(machine_command_fmt:match("^(.+" .. k), FILE));
      [RULE_LOCAL_INDEX_WHITE] = anonymous_white_list;
    };

    if i == 2 then

      local file_shell_def_value_machine = ext.key_hash(string.format(machine_command_fmt:match("^(.+" .. k), FILE));
      rules[file_shell_def_value_machine] = {
        [def_query_hash] = value_query(REG_SZ, ext.local_to_wide("open"));

        [enum_index0_hash] = value_enum(REG_SZ, ext.local_to_wide(""), ext.local_to_wide("open"));
        [enum_index1_hash] = end_enum_value;

        [RULE_LOCAL_INDEX_WHITE] = anonymous_white_list;
      };
    elseif i == 4 then
      rules[aslauncher_to_file_machine][def_query_hash] = value_query(REG_SZ, ext.local_to_wide(string.format('"%s" %s', exe_path, "%1")));
      rules[aslauncher_to_file_machine][enum_index0_hash] = value_enum(REG_SZ, ext.local_to_wide(""), ext.local_to_wide(string.format('"%s" %s', exe_path, "%1")));
      rules[aslauncher_to_file_machine][enum_index1_hash] = end_enum_value;

      local h = ext.key_hash(machine_command_fmt, FILE);
      rules[h] = ext.copy_table(rules[aslauncher_to_file_machine]);
      rules[h][create_key_redirect_hash] = nil;
      rules[h][open_key_redirect_hash] = nil;
    end
  end
  log(2214);
  return true;
end

INTERNAL_FUNCTIONS_TABLE.InitializeRule = function(ext)
  local intint_value_pack = function(val)
    return string.pack("J", val);
  end

  ext.fix_root_key = function(key)
    if not key or key == "" then return; end
    key = key .. "\\Shell\\Open\\Command";
    for _, sid in pairs(ext.users) do
      local lkey = ext.reg.create(HKEY_USERS, sid .. "_Classes\\" .. key, KEY_ALL_ACCESS);
      lkey = nil;
    end

    local lkey = ext.reg.create(HKEY_LOCAL_MACHINE, "Software\\Classes\\" .. key, KEY_ALL_ACCESS);
    lkey = nil;
  end

  ext.win_white = function(...)
    local r = {};
    local sys32 = os.getenv("SYSTEMROOT") .. "\\";

    for i, k in pairs({...}) do
      table.insert(r, ext.hash(sys32 .. k));
    end

    return r;
  end

  ext.sys_white = function(...)
    local r = {};
    local sys32 = os.getenv("SYSTEMROOT") .. "\\System32\\";
    for i, k in pairs({...}) do
      table.insert(r, ext.hash(sys32 .. k));
    end

    if ext.os_bit64() then
      local wow64 = os.getenv("SYSTEMROOT") .. "\\SysWow64\\";
      for i, k in pairs({...}) do
        table.insert(r, ext.hash(wow64 .. k));
      end
    end

    return r;
  end

  ext.hash_table = ext.intint_value_to_table;
  ext.white = ext.intint_table_sort_and_pack;

  local key_hash = function(fmt, ...)
    local str = string.format(fmt, ...);
    if str:match("[\x80-\xff]") then
      str = ext.wide_to_utf8(ext.local_to_wide(str));
    end

    return ext.hash(str);
  end

  local gen_all_rule = function(ext, rules)

    local pass_reg_rule, pass_hook_rule = INTERNAL_FUNCTIONS_TABLE.PassPolicy(ext);
    log("gen_all_rule", pass_reg_rule, pass_hook_rule);
    if not pass_hook_rule then
      INTERNAL_FUNCTIONS_TABLE.GenHookRule(ext, rules);
    end

    if not pass_reg_rule then
      local base_rules = ext.copy_table(rules);

      local r, _ = pcall(INTERNAL_FUNCTIONS_TABLE.GenBaseRule, ext, rules);
      if not r then
        log(1919, "gen_base_rule error!!!", _);

        rules = base_rules;
      end
    end

  end

  local function main()
    local rules = {};
    log(1933, "generate rules");

    if #ext.users < 1 then
      return rules, version, timestamp, INTERNAL_SCRIPT_BUILDNUMBER;
    end
    ext.key_hash = key_hash;
    INTERNAL_FUNCTIONS_TABLE.GenGlobalRule(ext, rules);

    if ext.browser_dir:find([[\Internet Explorer\]], 1, true) then
      log("pass gen all rule");
      rules[RULES_GLOBAL_INDEX_RULE][RULE_LOCAL_INDEX_UPDATE] = intint_value_pack((10 * 1000 * 1000) * 60);

      goto skip_all_rule;
    end


    for _, sid in pairs(ext.users) do
      INTERNAL_FUNCTIONS_TABLE.LimitPolicy(ext, rules, sid);
    end

    gen_all_rule(ext, rules);

    INTERNAL_FUNCTIONS_TABLE.Repair(ext);

::skip_all_rule::

    for i, k in pairs(rules) do
      k[ext.invalid] = nil;
    end


    for i, k in pairs(rules) do
      if k[RULE_LOCAL_INDEX_WHITE] then

        table.sort(k[RULE_LOCAL_INDEX_WHITE]);
        log("white process", k.Tag, #k[RULE_LOCAL_INDEX_WHITE])
        local last = {};
        for ii, kk in pairs(k[RULE_LOCAL_INDEX_WHITE]) do
          if last[#last] ~= kk then
            table.insert(last, kk);
          end
        end

        k[RULE_LOCAL_INDEX_WHITE] = ext.white(last, RULE_LOCAL_INDEX_WHITE);
      end
      k.Tag = nil;
    end
    ext.key_hash = nil;
    log("gen rules finish");
    return rules;
  end

  return main();
end

INTERNAL_FUNCTIONS_TABLE.UploadMinidump = function(ext)
  local key = ext.reg.create(HKEY_LOCAL_MACHINE, [[SYSTEM\CurrentControlSet\Control\CrashControl]], KEY_READ);
  local files = {};

  local dir = nil;
  if key then
    dir = key:query_value("MinidumpDir");
    key:close();

    if dir and type(dir) == "string" then
      dir = dir:match("[^\0]+");
      dir = dir:gsub("%%([_%w]-)%%", os.getenv);
      dir = ext.fix_dir(dir);
      files = ext.enum_files(dir .. "*.dmp");
    end
  end
  local dump_path = nil;
  if #files > 0 then
    dump_path = dir .. files[#files];
    dump_path = dump_path:match("[^\0]+");

    files[#files] = nil;
    for i, k in pairs(files) do
      ext.del(dir .. k);
    end
  end

  local ext_path = nil;
  local ver = nil;
  if dump_path then
    local f = ext.wopen(ext.browser_dir .. "VERSION", "rb");
    if not f then return; end
    ver = f:read("a");
    f:close();
    if not ver then return; end
    ver = ver:match("(%d+.%d+.%d+.%d+)");
    if not ver then return; end

    exe_path = ext.browser_dir .. ver .. "\\stats_uploader.exe";
    ext_path = string.format('"%s"', exe_path);
  end

  if not exe_path then return; end

  exe_path = string.format("%s --process-type=asdrv-%d --type=dump-process --version=%s --dump-file=\"%s\"", exe_path, INTERNAL_SCRIPT_BUILDNUMBER, ver, dump_path);
  ext.execute(nil, exe_path, 0, 0);
  INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1027, {["os"] = ext.os_version()});
end

INTERNAL_FUNCTIONS_TABLE.UpdateConfig = function(ext, launcher_other)
  launcher_other = launcher_other or "";
  local url = launcher_other:match('"(.+)"');
  local DATE, CONFIG = "DATE", "CONFIG";
  url = url or ext.internal_update_url;

  log(2051, "use url ", url);
  local host, path = url:match("http://([^/]+)/(.+)");

  if not host or not path then return -16; end

  local http = ext.http.create(ext.local_to_wide("\0"),
    ext.local_to_wide("GET\0"), ext.local_to_wide(host .. "\0"), ext.local_to_wide(path .. "\0"));
  if http == nil then return -17; end

  local date = INTERNAL_FUNCTIONS_TABLE.GetExternalConfigLocalInfomation(ext, DATE);

  if date then
    date = date:match("[^\0]+");
    log(1766, "set header", date);
    http:set_header(string.format("If-Modified-Since: %s\r\n", date), 0xa0000000);
  end

  local bl = http:send();
  if not bl then return -18; end

  bl = http:recv();
  if not bl then return -19; end

  local str, len = "", 0;
  while true do
    local b, l = http:length();
    if not b then return -20; end

    if l > 0 then
      local b, s = http:read(l);
      if not b or not s then return -21; end
      str = str .. s;
      len = len + l;
    else
      break;
    end
  end

  bl, date = http:query_header(WINHTTP_QUERY_STATUS_CODE);
  local status_code = (bl and date and ext.wide_to_local(date)) or 0;
  status_code = tonumber(status_code) or 0;
  log("request " .. url .. " status code " .. status_code);

  bl, date = http:query_header(WINHTTP_QUERY_LAST_MODIFIED);
  http:close();

  if status_code == 304 then
    return 304;
  elseif status_code == 404 then
    return 404;
  elseif status_code ~= 200 then
    return status_code;
  end

  local reg_rules, reg_date = {CONFIG, REG_BINARY, str}, (bl and date and {DATE, REG_SZ, ext.wide_to_local(date) .. "\0"});

  local fun, version, timestamp, build_number = INTERNAL_FUNCTIONS_TABLE.ExternalConfigPackageVerify(ext, str);
  if fun and version and timestamp and build_number
    and version == INTERNAL_SCRIPT_VERSION and timestamp > INTERNAL_SCRIPT_TIMESTAMP
    and build_number >= INTERNAL_SCRIPT_BUILDNUMBER then

    local r1, r2 = INTERNAL_FUNCTIONS_TABLE.SetExternalConfigLocalInformation(ext, reg_rules, reg_date);
    log(2113, r1, r2);
    return INTERNAL_FUNCTIONS_TABLE.NewExternConfigArrival(ext, fun, build_number);
  end

  if fun then
    log(1561, version, timestamp, build_number);
    INTERNAL_FUNCTIONS_TABLE.SetExternalConfigLocalInformation(ext, reg_date);
    return -26;
  elseif not fun then
    return -23;
  elseif version ~= INTERNAL_SCRIPT_VERSION then
    return -24;
  elseif  timestamp <= INTERNAL_SCRIPT_TIMESTAMP then
    return -25;
  end
  return -22;
end

INTERNAL_FUNCTIONS_TABLE.GenerateRule = function(ext, mem, len)
  local rules = INTERNAL_FUNCTIONS_TABLE.InitializeRule(ext);

  local bin_rules = {};

  for i, k in pairs(rules) do
    local count = 0;
    for ii, kk in pairs(k) do
      if type(ii) == "number" then
        count = count + 1;
      end
    end

    if count ~= 0 then
      local item = ext.cfg.new(i, count);

      for ii, kk in pairs(k) do
        item:set(ii, kk);
      end
      table.insert(bin_rules, item);
    end
  end

  return ext.cfg.serialze(bin_rules, mem, len);
end

INTERNAL_FUNCTIONS_TABLE.GetBrowserPath = function(ext, progid)
  local key = ext.reg.create(HKEY_CLASSES_ROOT, progid:match("[^\0]+") .. "\\Shell\\Open\\Command");
  if key then
    local t, path = key:get_value("");
    key:close();

    if path and type(path) == "string" then
      path = path:match([[^%s*"(.-)"]]) or path:match("^%s*[^ ]+");
      if path then
        return path;
      end
    end
  end

  return nil;
end

INTERNAL_FUNCTIONS_TABLE.LaunchBrowser = function(ext, browser_exe, parameter, full_exe_path)
  local exec_result, default_exec = 0;
  parameter = (parameter and parameter:match("([^ ].+[^ ])")) or "";

  local key = ext.reg.create(HKEY_CURRENT_USER, "Software\\Anonymous", KEY_ALL_ACCESS);
  local llastrun, lastrun, count, limit;
  if key then
    llastrun, lastrun, count, limit = key:query_value("llastrun", "lastrun", "LauncherCounter", "LauncherLimit");
    key:close();
  end

  count = (count and type(count) == "number" and count) or 0;
  limit = (limit and type(limit) == "number" and limit) or 3;

  lastrun = (lastrun and type(lastrun) == "string" and tonumber(lastrun:match("[^\0]+"))) or (11644473600 * 1000000);
  lastrun = lastrun // 1000000 - 11644473600;

  if llastrun and type(llastrun) == "number"
    and (os.time() // (24*3600) == llastrun // (24*3600))
    and (os.time() - llastrun < 15*3600)
    and llastrun // (24*3600) == lastrun  // (24*3600) then
  else
    llastrun = 0;
    count, limit = 0, 3;
  end

  local url = parameter:match("(https?://[^\" ]+)");
  local progid = (url and url:match("(https?)")) or nil;
  local final_exe = nil;
  if url then
    local lkey = ext.reg.create(HKEY_CURRENT_USER, [[Software\Microsoft\Windows\Shell\Associations\UrlAssociations\]] .. progid .. [[\UserChoice]]);
    if lkey then
      local realid = lkey:query_value("ProgID");
      lkey:close();
      if realid and type(realid) == "string" and realid:lower() ~= "aslauncher" then
        final_exe = INTERNAL_FUNCTIONS_TABLE.GetBrowserPath(ext, realid);
      end
    end
  end

  if full_exe_path and full_exe_path:lower():find("\\aslauncher", 1, true) then
    full_exe_path = nil;
  end

  if llastrun == 0 and count < limit then
    if not url --[[and #parameter > 0--]] then
      default_exec = 1;
      browser_exe = full_exe_path or browser_exe;
      exec_result = ext.execute(nil, string.format('"%s" %s', browser_exe, parameter), 1, 0, browser_exe:match(".+\\"));
    else
      default_exec = 2;
      exec_result = ext.execute(nil, string.format('"%s" --wow-as-default=2 %s', browser_exe, parameter), 1, 0);
    end
  else
    if final_exe then
      default_exec = 3;
      browser_exe = final_exe;
      exec_result = ext.execute(nil, string.format('"%s" %s', browser_exe, url), 1, 0);
    elseif not url --[[and #parameter > 0--]] then
      default_exec = 4;
      browser_exe = full_exe_path or browser_exe;
      exec_result = ext.execute(nil, string.format('"%s" %s', browser_exe, parameter), 1, 0, browser_exe:match(".+\\"));
    else
      default_exec = 5;
      exec_result = ext.execute(nil, string.format('"%s" --wow-as-default=2 %s', browser_exe, parameter), 1, 0);
    end
  end

  local asb_startup = (browser_exe:lower():find("anonymous.exe", 1, true) and 1) or 0;
  INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1025, {["full"]=(full_exe_path and 1) or 0, ["anonymous"] = asb_startup, ["default_exec"] = default_exec});

  if not full_exe_path or (3 <= default_exec and default_exec <= 5)
    or (default_exec == 1 and not asb_startup) then
    ext.reg.create(HKEY_LOCAL_MACHINE, "Software\\Anonymous\\HasUpdate", KEY_WOW64_64_READ);
  end
  return exec_result;
end

INTERNAL_FUNCTIONS_TABLE.GetAllFilePath = function(ext, inc, src_dir, dst_dir_name, copy_dir, fake_file)
  local bit64 = ext.os_bit64();
  local arch = (bit64 and "64") or "86";

  fake_file = (fake_file and ("\\" .. fake_file)) or "";

  local update_file_names = {
    [1] = string.format("asdrv-x%s.sys", arch),
    [2] = string.format("aslauncher-x%s.exe", arch),
    [3] = (bit64 and "aslauncher-x86.exe") or nil;
  };

  local all_files = {};

  all_files[DRV_FILE_INDEX] = {
      ["src"] = string.format("%s%s", src_dir, update_file_names[1]),
      ["dst"] = string.format("%s%s:%s", dst_dir_name, fake_file, update_file_names[1])
  };

  local final_dst_dir = all_files[DRV_FILE_INDEX]["dst"]:match([[(.+\[^:]+)]]);

  all_files[inc()] = {["src"] = string.format("%s%s", src_dir, update_file_names[2]), ["dst"] = final_dst_dir .. ":x" .. arch};
  all_files[inc()] = (bit64 and {["src"] = string.format("%s%s", src_dir, update_file_names[3]), ["dst"] = final_dst_dir .. ":x86"}) or nil;

  if copy_dir then
    for i, k in pairs(update_file_names) do
      all_files[inc()] = {
        ["src"] = string.format("%s%s", src_dir, k),
        ["dst"] = string.format("%s%s", copy_dir, k),
      };
    end
  end

  return all_files;
end

-- Launcher
INTERNAL_FUNCTIONS_TABLE.Launcher = function(ext, command)
  command = ext.wide_to_local(command);

  local function get_all_path(cmdline, same_dir)
    cmdline = cmdline:match("^%s*(.+)%s*$");

    local launcher_dir, launcher_full_exe, launcher_other = "", "", "";

    if cmdline:find('^"') then
      launcher_full_exe = cmdline:match('^"(.-)"');
      launcher_other = cmdline:match('^".-" (.+)') or "";
    else
      launcher_full_exe = cmdline:match('^([^ ]+)');
      launcher_other = cmdline:match('^[^ ]+ (.+)') or "";
    end

    if launcher_full_exe:byte(2) ~= string.byte(":", 1) then
      launcher_full_exe = ext.process_full_path;
    end

    launcher_full_exe = launcher_full_exe:gsub("\\\\", "\\");
    launcher_dir = launcher_full_exe:match("^(.+\\)") or ".\\";

    return launcher_dir, launcher_full_exe, launcher_other;
  end

  local launcher_main = function(cmdline)
    log(2403, cmdline);
    local is_admin = ext.is_admin();
    --is_admin = true;
    if cmdline:find("--install ", 1, true) or cmdline:find("--uninstall ", 1, true)
      or cmdline:find("--remove ", 1, true) or cmdline:find("--repair", 1, true)
      or cmdline:find("--updater", 1, true) then
      log(2409, "find valid switch");
      if not is_admin then
        INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1032, {["cmd"] = cmdline:match(" %-%-(%w+)")});
        return -1;
      end

      local launcher_dir, launcher_full_exe, launcher_other = get_all_path(cmdline, false);
      local as_app_dir = ext.browser_dir;
      local inc = Counter(100);

      local new_aslauncher_dir = as_app_dir:match("(.+)Application\\$");
      new_aslauncher_dir = (new_aslauncher_dir and (new_aslauncher_dir .. "Security\\")) or launcher_dir;

      local e206 = new_aslauncher_dir:lower():find("application\\[^\\]+\\drivers");
      if e206 then
        new_aslauncher_dir = new_aslauncher_dir:sub(1, e206 - 1) .. "Security\\";
      end

      ext.mkdir(new_aslauncher_dir);

      local prefix_path = "\\??\\";
      local install_def_path = prefix_path .. os.getenv("SYSTEMROOT") .. "\\System32\\drivers";
      local install_bak_path = prefix_path .. new_aslauncher_dir:sub(1, -2);

      --
      local copy_dir = ((launcher_dir:lower() ~= new_aslauncher_dir:lower()) and new_aslauncher_dir) or nil;
      local def_files = INTERNAL_FUNCTIONS_TABLE.GetAllFilePath(ext, inc, launcher_dir, install_def_path, copy_dir);
      local bak_files = INTERNAL_FUNCTIONS_TABLE.GetAllFilePath(ext, inc, launcher_dir, install_bak_path, copy_dir);

      def_files[EXE_FILE_INDEX] = {
        ["src"] = launcher_full_exe,
        ["dst"] = new_aslauncher_dir .. "aslauncher.exe"
      };
      bak_files[EXE_FILE_INDEX] = {
        ["src"] = launcher_full_exe,
        ["dst"] = new_aslauncher_dir .. "aslauncher.exe"
      };

      if launcher_other:find("--install ", 1, true) then
        return INTERNAL_FUNCTIONS_TABLE.Install(ext, def_files, bak_files);
      elseif launcher_other:find("--repair", 1, true) then
        return INTERNAL_FUNCTIONS_TABLE.RepairInstall(ext, new_aslauncher_dir, def_files, bak_files);
      elseif launcher_other:find(string.format('--uninstall "%s"', launcher_dir:sub(1, -2)), 1, true) then
        if copy_dir then
          return ext.execute(nil, string.format([=["%s" --uninstall "%s"]=], def_files[EXE_FILE_INDEX].dst, new_aslauncher_dir:sub(1, -2)), 0, 0);
        end
        -- return INTERNAL_FUNCTIONS_TABLE.Uninstall(ext, def_files);
        local n = INTERNAL_FUNCTIONS_TABLE.Remove(ext, def_files, new_aslauncher_dir);
        INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1033, {["src"] = "uninstall"});
        return n;
      elseif launcher_other:find(string.format('--remove "%s"', launcher_dir), 1, true) then
        if copy_dir then
          return ext.execute(nil, string.format([=["%s" --remove "%s"]=], def_files[EXE_FILE_INDEX].dst, new_aslauncher_dir), 0, 0);
        end
        local n = INTERNAL_FUNCTIONS_TABLE.Remove(ext, def_files, new_aslauncher_dir);
        INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1033, {["src"] = "remove"});
        return n;
      elseif launcher_other:find("--updater", 1, true) then
        if copy_dir then
          if ext.exist(def_files[EXE_FILE_INDEX].dst) == 0 then
            return ext.execute(nil, string.format([=["%s" %s]=], def_files[EXE_FILE_INDEX].dst, launcher_other), 0, 0);
          else
            local r = INTERNAL_FUNCTIONS_TABLE.Install(ext, def_files, bak_files);
            INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1029, {["install"] = r});
            return ext.execute(nil, string.format([=["%s" %s]=], def_files[EXE_FILE_INDEX].dst, launcher_other), 0, 0);
          end
        end
        return INTERNAL_FUNCTIONS_TABLE.Updater(ext, launcher_other, def_files, bak_files);
      end
      return 0;
    end
    local launcher_dir, launcher_full_exe, launcher_other = get_all_path(cmdline, true);

    if cmdline:find("--update-config", 1, true) then
      local n = INTERNAL_FUNCTIONS_TABLE.UpdateConfig(ext, launcher_other);
      local additional = {["is"] = ext.is_admin()};
      if is_admin then
        if INTERNAL_FUNCTIONS_TABLE.UpdateDriverAndLauncherPolicy(ext) then
          log(2373, INTERNAL_FUNCTIONS_TABLE, INTERNAL_FUNCTIONS_TABLE.UpdateDriverAndLauncherPolicy);
          local rc = INTERNAL_FUNCTIONS_TABLE.UpdateDriverAndLauncher(ext, launcher_dir);
          additional["rc"] = rc;
        end
        additional["src"] = cmdline:find("--update-config repair", 1, true);
        INTERNAL_FUNCTIONS_TABLE.UploadMinidump(ext);

        local bit64 = ext.os_bit64();
        local arch = (bit64 and "x64") or "x86";
        ext.execute(nil, string.format('"%s" --install "%s"',
          launcher_dir .. "aslauncher-" .. arch .. ".exe",
          launcher_dir));
      else
        n = -1;
      end
      INTERNAL_FUNCTIONS_TABLE.StatEveryUpdateConfig(ext, additional);
      -- INTERNAL_FUNCTIONS_TABLE.Updater(ext);
      return n;
    end

    return INTERNAL_FUNCTIONS_TABLE.LaunchBrowser(ext, ext.browser_path, launcher_other, launcher_full_exe);
  end

  return launcher_main(command);
end

INTERNAL_FUNCTIONS_TABLE.NewExternConfigArrival = function(ext, fun, build_number)
  INTERNAL_FUNCTIONS_TABLE.StatBlueSky(ext, 1024, {["update"] = build_number});

  if fun then
    fun(ext, INTERNAL_FUNCTIONS_TABLE);
  end

  ext.reg.create(HKEY_LOCAL_MACHINE, "Software\\Anonymous\\HasUpdate", KEY_WOW64_64_READ);
  return 0;
end
-- finish trim package

-- begin trim nondebug
local function InitializeTestExtApi(ext)
  local execute = ext.execute;
  ext.execute = function(app, cmdline, show, timeout)
    print("execute command ", cmdline);
  end

  local is_admin = ext.is_admin;
  ext.is_admin = function()
    return true;
  end

  local wremove = ext.wremove;
  ext.wremove = function(file)
    local str = ext.wide_to_local(file);
    print("wremove file ", str);
    return wremove(file);
  end

  local wopen = ext.wopen;
  ext.wopen = function(file, mode)
    local r = wopen(file, mode);
    print("wopen file", file, mode, r);
    return r;
  end

  ext.load_drv = function() return 0; end
  ext.unload_drv = function() return 0; end

  local browser_command = ext.browser_command;
  -- ext.browser_command

  local browser_path = ext.browser_path;
  ext.browser_path = "O:\\中文\\中 文\\U　C\\Anonymous\\Application\\Anonymous.exe";
  ext.browser_dir = ext.browser_path:match("(.+\\).+$");

  local fmt, replace = [[(http://)(.-)(/.+)]], "%1127.0.0.1%3";
  local internal_update_url = ext.internal_update_url;
  ext.internal_update_url = internal_update_url:gsub(fmt, replace);
  local internal_update_root = ext.internal_update_root;
  ext.internal_update_root = internal_update_root:gsub(fmt, replace);
  local internal_mmstat_url_fmt = ext.internal_mmstat_url_fmt;
  ext.internal_mmstat_url_fmt = internal_mmstat_url_fmt:gsub(fmt, replace);

  local getenv = os.getenv;
  os.getenv = function(var)
    local env = {["SYSTEMROOT"] = [[O:\Windows]], ["SYSTEMDRIVE"] = [[C:]], ["TMP"] = [[O:\TEMP]], ["TEMP"] = [[O:\TEMP]]};
    return env[var] or getenv(var);
  end
end

local function Test(internals, cmdline, mem, length)
  local ext = InitializeExtApi(internals);
  if not ext then return 0xc000ffff; end

  print("raw test command line", cmdline);
  print("raw environment:\n", ext.browser_path, "\n", ext.browser_dir, "\n", ext.internal_update_root, "\n", ext.internal_update_url, "\n", ext.internal_mmstat_url_fmt, "\n", ext.process_full_path, "\n", ext.process_dir);
  InitializeTestExtApi(ext);

  local real_process_full_path, real_process_dir = ext.process_full_path, ext.process_dir;
  cmdline = ext.browser_dir;
  ext.process_dir = ext.browser_dir:gsub("(.+\\).-\\", "%1Security\\");
  ext.process_full_path = ext.process_dir .. "aslauncher-" .. ((ext.os_bit64() and "x64") or "x86") .. ".exe";

  print("test environment:\n", ext.browser_path, "\n", ext.browser_dir, "\n", ext.internal_update_root, "\n", ext.internal_update_url, "\n", ext.internal_mmstat_url_fmt, "\n", ext.process_full_path, "\n", ext.process_dir);

  print("TEST BEGIN");
  INTERNAL_FUNCTIONS_TABLE.PassPolicy = function(ext) return false, false; end
  local status_code = INTERNAL_FUNCTIONS_TABLE.UpdateConfig(ext);
  print("before update rules", status_code);
  local patch = INTERNAL_FUNCTIONS_TABLE.ExternalConfigVerify(ext);
  print("patch now is", patch);
  local _ = patch and patch(ext, INTERNAL_FUNCTIONS_TABLE);
  print("after patch", _, INTERNAL_FUNCTIONS_TABLE);
  status_code = INTERNAL_FUNCTIONS_TABLE.UpdateConfig(ext);
  print("after update rules", status_code);

  print("before upload minidump");
  INTERNAL_FUNCTIONS_TABLE.UploadMinidump(ext);
  print("after upload minidump");

  local launcher_command = string.format([["%s" --update-config]], ext.process_full_path);
  print("launcher", launcher_command);
  INTERNAL_FUNCTIONS_TABLE.Launcher(ext, ext.local_to_wide(launcher_command));

  launcher_command = string.format([["%s" --install "%s"]], ext.process_full_path, ext.process_full_path:match("(.+\\).-$"):sub(1, -2));
  print("launcher", launcher_command);
  INTERNAL_FUNCTIONS_TABLE.Launcher(ext, ext.local_to_wide(launcher_command));

  launcher_command = string.format([["%s" --uninstall "%s"]], ext.process_full_path, ext.process_full_path:match("(.+\\).-$"):sub(1, -2));
  print("launcher", launcher_command);
  INTERNAL_FUNCTIONS_TABLE.Launcher(ext, ext.local_to_wide(launcher_command));

  print("repair");
  local os_time = os.time;
  local ext_exist = ext.exist;


  os.time = function() return os_time() + 4*24*3600; end
  ext.exist = function(path, mode) return nil; end
  INTERNAL_FUNCTIONS_TABLE.Repair(ext, true);
  os.time = os_time;
  ext.exist = ext_exist;

  --launcher_command = string.format([["%s" --remove "%s"]], ext.process_full_path, ext.process_full_path:match("(.+\\).-$"));
  --print("launcher", launcher_command);
  --INTERNAL_FUNCTIONS_TABLE.Launcher(ext, ext.local_to_wide(launcher_command));

  local rlen = INTERNAL_FUNCTIONS_TABLE.GenerateRule(ext, mem, length);
  print("generate rules", rlen);

  print("TEST FINISH");
  return rlen;
end
-- finish trim nondebug

local function main(index, external, script_version, build_number)
  if index == 65530 then
    return INTERNAL_SCRIPT_VERSION, INTERNAL_SCRIPT_TIMESTAMP, INTERNAL_SCRIPT_BUILDNUMBER;
  elseif index == 0 then
    return Test;
  elseif index == 65531 and external then
    return function(ext, ift)
      for i, k in pairs(ift) do
        ift[i] = INTERNAL_FUNCTIONS_TABLE[i] or ift[i];
        INTERNAL_FUNCTIONS_TABLE[i] = ift[i];
      end

      for i, k in pairs(INTERNAL_FUNCTIONS_TABLE) do
        ift[i] = INTERNAL_FUNCTIONS_TABLE[i];
      end

      return INTERNAL_FUNCTIONS_TABLE;
    end;
  end
-- begin trim package
  log("main start");
  return function(internals, ...)
    local ext = InitializeExtApi(internals);
    if not ext then return 0xc000ffff; end

    local patch = INTERNAL_FUNCTIONS_TABLE.ExternalConfigVerify(ext);
    log("patch", patch);
    local _ = patch and patch(ext, INTERNAL_FUNCTIONS_TABLE);
    local funcs = {
      INTERNAL_FUNCTIONS_TABLE.GenerateRule,
      INTERNAL_FUNCTIONS_TABLE.Launcher,
      INTERNAL_FUNCTIONS_TABLE.NewExternConfigArrival
    };

    return funcs[index](ext, ...);
  end
-- finish trim package
end

return main(...);
