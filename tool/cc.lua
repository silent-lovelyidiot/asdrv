local function get_build_number()
  local f = io.open(os.getenv("TOOL_DIR") .. "\\build_number", "r");
  local build = f:read("a");
  f:close();

  return tonumber(build);
end

local function get_file_last_modify_time(f)
  return internal.timestamp(f);
end

local __r_package_version__ = 1.0;
-- 处理in文件，将一些编译时变量替换，生成二进制文件luac。
-- 在luac头部增加随机盐，盐=hmac(luac) .. 12字节随机数，共32字节，并整体通过公钥最后16字节作为密钥使用AES进行加密，生成二进制文件data。
local function gen_script_h(config_in, config_out, action)
  print("action", action);
  local inf = io.open(config_in, "rb");
  local data = inf:read("a");
  inf:close();

  if action ~= "Debug" then
    print("trim nondebug");
    data = data:gsub("(-- begin trim nondebug.--- finish trim nondebug)", "");
    data = data:gsub("(log%(.-%);)", "-- %1");
  end

  if action == "Package" then
    print("trim package");
    data = data:gsub("(-- begin trim package.--- finish trim package)", "");
  end

  local pubkeyfile = io.open(os.getenv("TOOL_DIR") .. "\\eccpublic.blob", "rb");
  local pubkey = pubkeyfile:read("a");
  pubkeyfile:close();

  local pubkey_str = string.format(string.rep("\\x%02x", #pubkey), pubkey:byte(1, -1));
  pubkey_str = string.format("'%s'", pubkey_str);

  local replace = {
    ["__r_time_stamp__"] = get_file_last_modify_time(config_in);
    ["__r_build__"] = get_build_number();
    ["__r_pubkey__"] = pubkey_str;
    ["__r_package_version__"] = __r_package_version__;
  };

  data = data:gsub("(__r_[%w_]+__)", replace);
  data = data:gsub("(print.-%);)", "-- %1");



  local f = io.open(os.getenv("GEN_DIR") .. "\\final_" .. config_out:match([=[([^\]+)%.h]=]) .. ".lua", "wb");
  f:write(data);
  f:close();

  data, f = load(data, "internal script lua", "t", {});
  if not data then
    print("load error", f);
  end
  print("current script", config_in)
  print("current script internal version", data(65530, false));
  print("string.dump strip", action ~= "Debug");
  data = string.dump(data, action ~= "Debug");

  f = io.open(os.getenv("GEN_DIR") .. "\\final_" .. config_out:match([=[([^\]+)%.h]=]) .. ".luac", "wb");
  f:write(data);
  f:close();

  local salt = string.pack("c20Ld", internal.hmac(data), os.time(), math.random());

  data = internal.encrypt(pubkey:sub(-16), salt .. data);
  f = io.open(os.getenv("GEN_DIR") .. "\\final_" .. config_out:match([=[([^\]+)%.h]=]) .. ".data", "wb");
  f:write(data);
  f:close();

  local fmt = string.rep("0x%02x, ", 8);
  fmt = "  " .. fmt:sub(1, -2) .. "\n";
  fmt = string.rep(fmt, #data // 8);
  if #data % 8 ~= 0 then
    fmt = fmt .. "  " .. string.rep("0x%02x, ", #data % 8):sub(1, -2) .. "\n";
  end

  data = string.format(fmt, data:byte(1, -1));

  local f = io.open(config_out, "wb");
  f:write(data);
  f:close();
end

-- 构建 version.h
local function update_version(update)
  -- os.remove(os.getenv("GEN_DIR") .. "\\version.h");
  local build = tonumber(get_build_number());
  if update == "true" or update == true then
    os.remove(os.getenv("GEN_DIR") .. "\\version.h");
    build = build + 1;
    print("new build_number: " .. build);
    local f = io.open(os.getenv("TOOL_DIR") .. "\\build_number", "w");
    f:write(build);
    f:close();
  end

  local f = io.open(os.getenv("GEN_DIR") .. "\\version.h", "r");
  if f then
    local d = f:read("a");
    if d and d:match("BUILD_VERSION") then
      f:close();
      return;
    end
    f:close();
  end

  local f = io.open(os.getenv("GEN_DIR") .. "\\version.h", "w");
  f:write(string.format('#define  BUILD_VERSION "%s.%s.%s.%s"\n', 1, build, os.date("%d"), os.date("%H")));
  f:close();
end

-- 构建internal_script_*.h，version.h
local function pre_compile(TOOL_DIR, SRC_DIR, GEN_DIR, ARCH, ACTION)
  print("pre_compile start");
  update_version(false);

  local files = {
    {
      ["src"] = SRC_DIR .. "\\lua\\internal_script.lua",
      ["dst"] = GEN_DIR .. "\\internal_script_" .. ARCH .. ".h",
    },
  };

  local update = {};

  if ACTION == "Debug" then
    for _, f in pairs(files) do
      local dt =  get_file_last_modify_time(f.dst);
      local st = get_file_last_modify_time(f.src);
      if st > dt then
        table.insert(update, f);
      end
    end
  else
    update = files;
  end

  for _, k in pairs(update) do
    gen_script_h(k.src, k.dst, ACTION);
  end

  print("pre_compile finish");
end

-- hash = hmac(hmac(data) .. head .. data)。
-- 使用ecc私钥对hash进行签名。
-- 最终数据 = head .. data .. sign。
-- 验证
local function gen_package(config_out)
  print("gen_package start");
  local TOOL_DIR = os.getenv("TOOL_DIR");
  local SRC_DIR = os.getenv("SRC_DIR");
  local GEN_DIR = os.getenv("GEN_DIR");

  local x86luac = io.open(GEN_DIR .. "\\final_internal_script_x86.luac", "rb"):read("a");
  local x64luac = io.open(GEN_DIR .. "\\final_internal_script_x64.luac", "rb"):read("a");

  print("verify all in one");
  assert(#x86luac == #x64luac
    and x86luac:sub(1, 13) == x64luac:sub(1, 13)
    and x86luac:sub(-(#x86luac - 14)) == x64luac:sub(-(#x64luac - 14))
    and x86luac:byte(14) == 4 and x64luac:byte(14) == 8, "gen luac error: x86 ~= x64");
  print("verify all in one ok");
  local d = io.open(GEN_DIR .. "\\final_internal_script_x86.data", "rb"):read("a");

  local time = os.time();
  local version = __r_package_version__;
  time = time + version;
  print("package version", version);
  -- d1 + d4 = d3
  local data = string.pack(string.format("ddddc%d", (#d + 7) // 8 * 8), time, version, time + #d, #d, d);
  local hash = internal.hmac(internal.hmac(d) .. data);

  print("sign");
  local prikey = io.open(TOOL_DIR .. "\\eccprivate.blob", "rb"):read("a");
  local sign = internal.sign_hash(prikey, hash);
  print("sign length", #sign);
  data = data .. sign;
  print("sign ok");

  print("verify sign");
  local d = io.open(GEN_DIR .. "\\final_internal_script_x86.data", "rb"):read("a");
  local hash = internal.hmac(internal.hmac(d) .. data:sub(1, -97));

  local pubkey = io.open(TOOL_DIR .. "\\eccpublic.blob", "rb"):read("a");
  assert(internal.verify_sign(pubkey, hash, sign) == 0x00018000, "ecc key mismatched");
  print("verify sign ok");
  io.open(config_out, "wb"):write(data):close();
  print("gen_package finish");
end

local function gen_update_package(file_in, file_out)
  local TOOL_DIR = os.getenv("TOOL_DIR");
  local f = io.open(file_in, "rb");
  local d = f:read("a");
  f:close();

  local hash = internal.hmac(d);
  local prikey = io.open(TOOL_DIR .. "\\eccprivate.blob", "rb"):read("a");
  local sign = internal.sign_hash(prikey, hash);

  assert(#sign == 96, "sign hash error");
  f = io.open(file_out, "wb");
  f:write(sign):write(d):close();

  f = io.open(file_out, "rb");
  d = f:read("a");
  f:close();

  sign, d = string.unpack("c96c" .. #d - 96, d);
  hash = internal.hmac(d);

  local pubkey = io.open(TOOL_DIR .. "\\eccpublic.blob", "rb"):read("a");
  assert(internal.verify_sign(pubkey, hash, sign) == 0x00018000, "ecc key mismatched");

end

local proc = {
  ["gen_package"] = gen_package;
  ["pre_compile"] = pre_compile;
  ["update_version"] = update_version;
  ["gen_update_package"] = gen_update_package;
}

local func = proc[arg[1]];
func(select(2, table.unpack(arg)));