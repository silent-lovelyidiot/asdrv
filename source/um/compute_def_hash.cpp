#include <Windows.h>

/*
 *  RFC 1321 compliant MD5 implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The MD5 algorithm was designed by Ron Rivest in 1991.
 *
 *  http://www.ietf.org/rfc/rfc1321.txt
 */
#include <stdint.h>
#include <memory.h>

typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
mbedtls_md5_context;

//static void mbedtls_zeroize( void *v, size_t n ) {
//    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
//}
/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

/*
 * MD5 context setup
 */
void mbedtls_md5_starts( mbedtls_md5_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
}

#if !defined(MBEDTLS_MD5_PROCESS_ALT)
void mbedtls_md5_process( mbedtls_md5_context *ctx, const unsigned char data[64] )
{
    uint32_t X[16], A, B, C, D;

    GET_UINT32_LE( X[ 0], data,  0 );
    GET_UINT32_LE( X[ 1], data,  4 );
    GET_UINT32_LE( X[ 2], data,  8 );
    GET_UINT32_LE( X[ 3], data, 12 );
    GET_UINT32_LE( X[ 4], data, 16 );
    GET_UINT32_LE( X[ 5], data, 20 );
    GET_UINT32_LE( X[ 6], data, 24 );
    GET_UINT32_LE( X[ 7], data, 28 );
    GET_UINT32_LE( X[ 8], data, 32 );
    GET_UINT32_LE( X[ 9], data, 36 );
    GET_UINT32_LE( X[10], data, 40 );
    GET_UINT32_LE( X[11], data, 44 );
    GET_UINT32_LE( X[12], data, 48 );
    GET_UINT32_LE( X[13], data, 52 );
    GET_UINT32_LE( X[14], data, 56 );
    GET_UINT32_LE( X[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define P(a,b,c,d,k,s,t)                                \
{                                                       \
    a += F(b,c,d) + X[k] + t; a = S(a,s) + b;           \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];

#define F(x,y,z) (z ^ (x & (y ^ z)))

    P( A, B, C, D,  0,  7, 0xD76AA478 );
    P( D, A, B, C,  1, 12, 0xE8C7B756 );
    P( C, D, A, B,  2, 17, 0x242070DB );
    P( B, C, D, A,  3, 22, 0xC1BDCEEE );
    P( A, B, C, D,  4,  7, 0xF57C0FAF );
    P( D, A, B, C,  5, 12, 0x4787C62A );
    P( C, D, A, B,  6, 17, 0xA8304613 );
    P( B, C, D, A,  7, 22, 0xFD469501 );
    P( A, B, C, D,  8,  7, 0x698098D8 );
    P( D, A, B, C,  9, 12, 0x8B44F7AF );
    P( C, D, A, B, 10, 17, 0xFFFF5BB1 );
    P( B, C, D, A, 11, 22, 0x895CD7BE );
    P( A, B, C, D, 12,  7, 0x6B901122 );
    P( D, A, B, C, 13, 12, 0xFD987193 );
    P( C, D, A, B, 14, 17, 0xA679438E );
    P( B, C, D, A, 15, 22, 0x49B40821 );

#undef F

#define F(x,y,z) (y ^ (z & (x ^ y)))

    P( A, B, C, D,  1,  5, 0xF61E2562 );
    P( D, A, B, C,  6,  9, 0xC040B340 );
    P( C, D, A, B, 11, 14, 0x265E5A51 );
    P( B, C, D, A,  0, 20, 0xE9B6C7AA );
    P( A, B, C, D,  5,  5, 0xD62F105D );
    P( D, A, B, C, 10,  9, 0x02441453 );
    P( C, D, A, B, 15, 14, 0xD8A1E681 );
    P( B, C, D, A,  4, 20, 0xE7D3FBC8 );
    P( A, B, C, D,  9,  5, 0x21E1CDE6 );
    P( D, A, B, C, 14,  9, 0xC33707D6 );
    P( C, D, A, B,  3, 14, 0xF4D50D87 );
    P( B, C, D, A,  8, 20, 0x455A14ED );
    P( A, B, C, D, 13,  5, 0xA9E3E905 );
    P( D, A, B, C,  2,  9, 0xFCEFA3F8 );
    P( C, D, A, B,  7, 14, 0x676F02D9 );
    P( B, C, D, A, 12, 20, 0x8D2A4C8A );

#undef F

#define F(x,y,z) (x ^ y ^ z)

    P( A, B, C, D,  5,  4, 0xFFFA3942 );
    P( D, A, B, C,  8, 11, 0x8771F681 );
    P( C, D, A, B, 11, 16, 0x6D9D6122 );
    P( B, C, D, A, 14, 23, 0xFDE5380C );
    P( A, B, C, D,  1,  4, 0xA4BEEA44 );
    P( D, A, B, C,  4, 11, 0x4BDECFA9 );
    P( C, D, A, B,  7, 16, 0xF6BB4B60 );
    P( B, C, D, A, 10, 23, 0xBEBFBC70 );
    P( A, B, C, D, 13,  4, 0x289B7EC6 );
    P( D, A, B, C,  0, 11, 0xEAA127FA );
    P( C, D, A, B,  3, 16, 0xD4EF3085 );
    P( B, C, D, A,  6, 23, 0x04881D05 );
    P( A, B, C, D,  9,  4, 0xD9D4D039 );
    P( D, A, B, C, 12, 11, 0xE6DB99E5 );
    P( C, D, A, B, 15, 16, 0x1FA27CF8 );
    P( B, C, D, A,  2, 23, 0xC4AC5665 );

#undef F

#define F(x,y,z) (y ^ (x | ~z))

    P( A, B, C, D,  0,  6, 0xF4292244 );
    P( D, A, B, C,  7, 10, 0x432AFF97 );
    P( C, D, A, B, 14, 15, 0xAB9423A7 );
    P( B, C, D, A,  5, 21, 0xFC93A039 );
    P( A, B, C, D, 12,  6, 0x655B59C3 );
    P( D, A, B, C,  3, 10, 0x8F0CCC92 );
    P( C, D, A, B, 10, 15, 0xFFEFF47D );
    P( B, C, D, A,  1, 21, 0x85845DD1 );
    P( A, B, C, D,  8,  6, 0x6FA87E4F );
    P( D, A, B, C, 15, 10, 0xFE2CE6E0 );
    P( C, D, A, B,  6, 15, 0xA3014314 );
    P( B, C, D, A, 13, 21, 0x4E0811A1 );
    P( A, B, C, D,  4,  6, 0xF7537E82 );
    P( D, A, B, C, 11, 10, 0xBD3AF235 );
    P( C, D, A, B,  2, 15, 0x2AD7D2BB );
    P( B, C, D, A,  9, 21, 0xEB86D391 );

#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
}
#endif /* !MBEDTLS_MD5_PROCESS_ALT */

/*
 * MD5 process buffer
 */
void mbedtls_md5_update( mbedtls_md5_context *ctx, const unsigned char *input, size_t ilen )
{
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        mbedtls_md5_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        mbedtls_md5_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (ctx->buffer + left), input, ilen );
    }
}

static const unsigned char md5_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * MD5 final digest
 */
void mbedtls_md5_finish( mbedtls_md5_context *ctx, unsigned char output[16] )
{
    uint32_t last, padn;
    uint32_t high, low;
    unsigned char msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_LE( low,  msglen, 0 );
    PUT_UINT32_LE( high, msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    mbedtls_md5_update( ctx, md5_padding, padn );
    mbedtls_md5_update( ctx, msglen, 8 );

    PUT_UINT32_LE( ctx->state[0], output,  0 );
    PUT_UINT32_LE( ctx->state[1], output,  4 );
    PUT_UINT32_LE( ctx->state[2], output,  8 );
    PUT_UINT32_LE( ctx->state[3], output, 12 );
}



/*
 * output = MD5( input buffer )
 */
void mbedtls_md5( const unsigned char *input, size_t ilen, unsigned char output[16] )
{
    mbedtls_md5_context ctx = {0};

    mbedtls_md5_starts( &ctx );
    mbedtls_md5_update( &ctx, input, ilen );
    mbedtls_md5_finish( &ctx, output );
}

constexpr unsigned char base64_enc_map[64] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/'
};

void base64encode(const unsigned char* Str, const unsigned int Length, wchar_t* Out) {
  union base64 {
    char val[4];

    struct {
      unsigned int v2f : 2;
      unsigned int v1 : 6;
      unsigned int v3f : 4;
      unsigned int v2 : 4;
      unsigned int v4 : 6;
      unsigned int v3 : 2;

    } bit;
  };

  unsigned int i = 0;
  base64 base;
  for (; i + 3 <= Length; i += 3, Str += 3) {
    memcpy(base.val, Str, 4);
    *Out++ = base64_enc_map[base.bit.v1];
    *Out++ = base64_enc_map[(base.bit.v2f << 4) | base.bit.v2];
    *Out++ = base64_enc_map[(base.bit.v3f << 2) | base.bit.v3];
    *Out++ = base64_enc_map[base.bit.v4];
  }

  if (i < Length) {
    memset(base.val, 0, 4);
    memcpy(base.val, Str, Length - i);
    memcpy(Out, L"====", 8);
    Out[0] = base64_enc_map[base.bit.v1];

    if (i++ < Length)
      Out[1] = base64_enc_map[(base.bit.v2f << 4) | base.bit.v2];

    if (i++ < Length)
      Out[2] = base64_enc_map[(base.bit.v3f << 2) | base.bit.v3];
    Out += 4;
  }
  *Out = '\0';
}


bool CS64_WordSwapMine(const unsigned int* lower_str, const unsigned int lower_str_length, const unsigned int* hash, void* outbuffer) {
  if (lower_str_length < 2 || (lower_str_length & 0x01)) return false;

  unsigned int hash_first_dword = (hash[0] | 1) + 0x69fb0000;
  unsigned int hash_second_dword = (hash[1] | 1) + 0x13db0000;

  unsigned int length = lower_str_length;

  unsigned int low_dowrd = 0;
  unsigned int high_dword = 0;

  do {
    low_dowrd += *lower_str++;
    unsigned int value = (hash_first_dword * low_dowrd) - ((low_dowrd >> 0x10) * 0x10FA9605);
    value = ((value >> 0x10) * 0x689B6B9F) + (value * 0x79F8A395);
    low_dowrd = (value * 0xEA970001) - (value >> 0x10) * 0x3C101569;
    high_dword += low_dowrd;

    low_dowrd += *lower_str++;
    value = (hash_second_dword * low_dowrd) - (low_dowrd >> 0x10) * 0x3CE8EC25;
    value = (value * 0x59C3AF2D) - ((value >> 0x10) * 0x2232E0F1);
    low_dowrd = (value * 0x1ec90001) + ((value >> 0x10) * 0x35BD1EC9);
    high_dword += low_dowrd;

    length -= 2;
  } while (length);

  *(unsigned __int64*)outbuffer = 0ULL | (low_dowrd) | ((0LL | high_dword) << 32);
  return true;
}

bool CS64_ReversibleMine(const unsigned int* lower_str, const unsigned int lower_str_length, const unsigned int* hash, void* outbuffer) {
  if (lower_str_length < 2 || (lower_str_length & 0x01)) return false;

  unsigned int hash_first_dword = hash[0] | 1;
  unsigned int hash_second_dword = hash[1] | 1;

  unsigned int high_dword = 0;
  unsigned int low_dword = 0;
  unsigned int length = lower_str_length;

  do {
    unsigned int value = (low_dword + *lower_str++) * hash_first_dword;
    value = (value * 0xB1110000) - ((value >> 0x10) * 0x30674EEF);
    value = (value * 0x5B9F0000) - ((value >> 0x10) * 0x78F7A461); 

    value = ((value >> 0x10) * 0x12CEB96D) - (value * 0x46930000);
    low_dword = (value >> 0x10) * 0x257E1D83 + (value * 0x1D830000);
    high_dword += low_dword;

    value = (*lower_str++ + low_dword) * hash_second_dword;
    value = (value * 0x16f50000) - ((value >> 0x10) * 0x5D8BE90B);
    value = (value * 0x96FF0000) - ((value >> 0x10) * 0x2C7C6901);
    value = ((value >> 0x10) * 0x7C932B89) + (value * 0x2B890000);
    low_dword = (value * 0x9F690000) - (value >> 0x10) * 0x405B6097;
    high_dword += low_dword;

    length -= 2;
  } while(length);

  *(unsigned __int64*)outbuffer = 0ULL | (low_dword) | ((0LL | high_dword) << 32);
  return true;
}

//void CalculateSingleUserChoiceHash(const wchar_t* Protocols, const wchar_t* Sid,
//  const wchar_t* ProgID, const wchar_t* ExeFullPath, wchar_t OutHashString[16]) {
//  wchar_t HashString[512];
//  wsprintfW(HashString, L"%s%s%s%s", Protocols, Sid, ProgID, ExeFullPath);
//
//  auto Len = wcslen(HashString);
//  _wcslwr_s(HashString);
//  ZeroMemory(HashString + Len, sizeof(HashString) - Len * sizeof(wchar_t));
//
//  Len = (Len + 1) * sizeof(wchar_t);
//
//  unsigned char digest[16];
//  mbedtls_md5((const unsigned char*)HashString, Len, digest);
//
//  const unsigned int* MD5 = (const unsigned int*)digest;
//  Len = (Len / 4) & ~1;
//
//  unsigned char buffer1[8] = {0}, buffer2[8] = {0};
//  CS64_WordSwapMine((const unsigned int*)HashString, (unsigned int)Len, MD5, buffer1);
//  CS64_ReversibleMine((const unsigned int*)HashString, (unsigned int)Len, MD5, buffer2);
//
//  *(PULONGLONG)buffer1 ^= *(PULONGLONG)buffer2;
//  base64encode(buffer1, 8, OutHashString);
//}

void CalculateSingleUserChoiceHash(const wchar_t* InHashString, wchar_t OutHashString[16]) {
  wchar_t HashString[512];
  wcscpy_s(HashString, InHashString);

  auto Len = wcslen(HashString);
  _wcslwr_s(HashString);
  ZeroMemory(HashString + Len, sizeof(HashString) - Len * sizeof(wchar_t));

  Len = (Len + 1) * sizeof(wchar_t);

  unsigned char digest[16];
  mbedtls_md5((const unsigned char*)HashString, Len, digest);

  const unsigned int* MD5 = (const unsigned int*)digest;
  Len = (Len / 4) & ~1;

  unsigned char buffer1[8] = {0}, buffer2[8] = {0};
  CS64_WordSwapMine((const unsigned int*)HashString, (unsigned int)Len, MD5, buffer1);
  CS64_ReversibleMine((const unsigned int*)HashString, (unsigned int)Len, MD5, buffer2);

  *(PULONGLONG)buffer1 ^= *(PULONGLONG)buffer2;
  base64encode(buffer1, 8, OutHashString);
}