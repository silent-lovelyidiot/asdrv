#include "../../lua/src/lua.hpp"

#include <Windows.h>

#include <crtdbg.h>

#include <malloc.h>
#include <memory.h>
#include <intrin.h>

#pragma region lua_crypt_routine
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

EXTERN_C int lua_crypt_hash(lua_State* L) {
  BCRYPT_ALG_HANDLE alg;
  auto st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (st == 0) {
    BCRYPT_HASH_HANDLE hash;
    st = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    if (st == 0) {
      size_t len = 0;
      const char* data = lua_tolstring(L, 1, &len);
      _ASSERT(len);
      st = BCryptHashData(hash, (PUCHAR)data, len & 0xffffffff, 0);
      if (st == 0) {
        UCHAR buffer[20];
        st = BCryptFinishHash(hash, buffer, 20, 0);
        if (st == 0) {
          lua_pushlstring(L, (char*)buffer, 20);
        }
      }
      _ASSERT(st == 0);
      BCryptDestroyHash(hash);
    }
    _ASSERT(st == 0);
    BCryptCloseAlgorithmProvider(alg, 0);
  }
  _ASSERT(st == 0);
  return st == 0 ? 1 : 0;
}

EXTERN_C int lua_crypt_verify_sign(lua_State* L) {
  BCRYPT_ALG_HANDLE alg;
  auto st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P384_ALGORITHM, nullptr, 0);
  if (st == 0) {
    size_t len = 0;
    const char* pubkey = lua_tolstring(L, 1, &len);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    st = BCryptImportKeyPair(alg, nullptr, BCRYPT_PUBLIC_KEY_BLOB, &hKey, (PUCHAR)pubkey, len & 0xffffffff, 0);
    if (st == 0) {
      const char* hash = lua_tolstring(L, 2, &len);
      _ASSERT(len == 20);
      size_t siglen = 0;
      const char* sig = lua_tolstring(L, 3, &siglen);
      _ASSERT(siglen == 0x60);
      st = BCryptVerifySignature(hKey, nullptr, (PUCHAR)hash, len & 0xffffffff, (PUCHAR)sig, siglen & 0xffffffff, 0);
      _ASSERT(st == 0);
      st |= 0x00018000;

      BCryptDestroyKey(hKey);
    }
    _ASSERT((st & ~0x00018000) == 0);
    BCryptCloseAlgorithmProvider(alg, 0);
  }
  _ASSERT((st & ~0x00018000) == 0);

  lua_pushinteger(L, st);
  return 1;
}

EXTERN_C int lua_crypt_sign_hash(lua_State* L) {
  BCRYPT_ALG_HANDLE alg;
  auto st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P384_ALGORITHM, nullptr, 0);
  if (st == 0) {
    size_t len = 0;
    const char* prikey = lua_tolstring(L, 1, &len);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    st = BCryptImportKeyPair(alg, nullptr, BCRYPT_PRIVATE_KEY_BLOB, &hKey, (PUCHAR)prikey, len & 0xffffffff, 0);
    if (st == 0) {
      const char* hash = lua_tolstring(L, 2, &len);
      _ASSERT(len == 20);
      ULONG rlen = 0;
      luaL_Buffer b;
      luaL_buffinitsize(L, &b, 256);
      st = BCryptSignHash(hKey, nullptr, (PUCHAR)hash, len & 0xffffffff, (PUCHAR)b.b, 256, &rlen, 0);
      if (st == 0) {
        luaL_pushresultsize(&b, rlen);
      }
      _ASSERT(rlen == 0x60);
      BCryptDestroyKey(hKey);
    }

    BCryptCloseAlgorithmProvider(alg, 0);
  }
  _ASSERT(st == 0);

  return st == 0 ? 1 : 0;
}

int bcrypt_symm_crypt(lua_State* L, int encrypt) {
  BCRYPT_ALG_HANDLE alg;
  auto st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
  if (st == 0) {
    size_t len = 0;
    const char* pubkey = lua_tolstring(L, 1, &len);
    _ASSERT(len == 16);

    constexpr size_t BlobArrayCount = (16 + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)) / sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 1;
    BCRYPT_KEY_DATA_BLOB_HEADER blob[BlobArrayCount];
    blob->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    blob->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    blob->cbKeyData = 16;
    memcpy(blob + 1, pubkey, 16);

    len = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 16;

    BCRYPT_KEY_HANDLE hKey = nullptr;
    st = BCryptImportKey(alg, nullptr, BCRYPT_KEY_DATA_BLOB, &hKey, nullptr, 0, (PUCHAR)blob, len & 0xffffffff, 0);
    if (st == 0) {
      const char* data = lua_tolstring(L, 2, &len);
      ULONG rlen = 0;
      luaL_Buffer b;
      luaL_buffinitsize(L, &b, 16 + (len + 15) & ~15);
      if (encrypt) {
        st = BCryptEncrypt(hKey, (PUCHAR)data, len & 0xffffffff, nullptr, nullptr, 0, (PUCHAR)b.b, b.size & 0xffffffff, &rlen, BCRYPT_BLOCK_PADDING);
      } else {
        st = BCryptDecrypt(hKey, (PUCHAR)data, len & 0xffffffff, nullptr, nullptr, 0, (PUCHAR)b.b, b.size & 0xffffffff, &rlen, BCRYPT_BLOCK_PADDING);
      }
      if (st == 0) {
        luaL_pushresultsize(&b, rlen);
      }
      _ASSERT(st == 0);
      BCryptDestroyKey(hKey);
    }

    BCryptCloseAlgorithmProvider(alg, 0);
  }
  _ASSERT(st == 0);
  return st == 0 ? 1 : 0;
}

EXTERN_C int lua_crypt_encrypt(lua_State* L) {
  return bcrypt_symm_crypt(L, 1);
};

EXTERN_C int lua_crypt_decrypt(lua_State* L) {
  return bcrypt_symm_crypt(L, 0);
};

#pragma endregion CRYPTÏà¹ØAPI