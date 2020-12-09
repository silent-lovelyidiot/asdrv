#include <wdm.h>
#include "../MpqHash.h"
#include "MpqHashHelper.h"
#include "../log.h"

//BOOLEAN InternaleHash(CONST VOID* String, CONST ULONG Length,
//  CONST VOID* Table, ULONG* HashO, ULONG* HashA, ULONG* HashB) {
//
//  if (HashO) *HashO = MpqHashData(String, Length, HashOffset, (PCULONG)Table);
//  if (HashA) *HashA = MpqHashData(String, Length, HashTypeA, (PCULONG)Table);
//  if (HashB) *HashB = MpqHashData(String, Length, HashTypeB, (PCULONG)Table);
//
//  return TRUE;
//}

// 返回MpqHash的A和B值组合成64位值，主要是考虑减少碰撞的可能。
//ULONGLONG Hash(const char* String, CONST ULONG Length, CONST VOID* Table) {
//  if ((!String && Length) || !Table) return MPQ_INVALID_HASH;
//
//  ULONG A, B;
//  BOOLEAN bl = InternaleHash((VOID*)String, Length, Table, nullptr, &A, &B);
//
//  if (bl) {
//    return ((ULONGLONG)A << 32) | B;
//  }
//  return MPQ_INVALID_HASH;
//}

inline ULONG MpqHashData(CONST VOID* Data, ULONG Size, _HashType Type,
  PCULONG Table,
  PULONG Seed1, PULONG Seed2) {
  PUCHAR D = (PUCHAR)Data;

  for(; Size; Size--, D++) {
    ULONG Ch = ToUpper(D);
    *Seed1 = (Table[(Type << 8) + Ch]) ^ (*Seed1 + *Seed2);
    *Seed2 = Ch + *Seed1 + *Seed2 + (*Seed2 << 5) + 3;
  }
  return *Seed1;
}

ULONGLONG Hash(PCUNICODE_STRING String, CONST VOID* Table) {
  if (!String) {
    ASSERT(0);
    return MPQ_INVALID_HASH;
  }

  ULONG SeedA1 = 0x7FED7FED, SeedA2 = 0xEEEEEEEE;
  ULONG SeedB1 = 0x7FED7FED, SeedB2 = 0xEEEEEEEE;

  // Length = 0;
  ULONG HashA = 0x7FED7FED, HashB = 0x7FED7FED;

  ULONG Length = String->Length / 2;
  for (ULONG i = 0; i < Length; i++) {
    UCHAR Buffer[8];
    ULONG UnicodeChar = String->Buffer[i];

    ULONG Index = 0;
    BOOLEAN IsNonZero = _BitScanReverse(&Index, UnicodeChar);
    if (!IsNonZero) Index = 0;

    ULONG BufferSize = 0;

    if (Index <= 7) {
      Buffer[0] = UnicodeChar & 0x7f;
      BufferSize = 1;
    } else if (Index <= 11) {
      Buffer[0] = 0xc0 | ((UnicodeChar >> 6) & 0x1f);
      Buffer[1] = 0x80 | (UnicodeChar & 0x3f);
      BufferSize = 2;
    }else if (Index <= 16) {
      Buffer[0] = 0xe0 | ((UnicodeChar >> 12) & 0x0f);
      Buffer[1] = 0x80 | ((UnicodeChar >> 6 ) & 0x3f);
      Buffer[2] = 0x80 | (UnicodeChar & 0x3f);
      BufferSize = 3;
    }  else if (Index <= 21) {
      Buffer[0] = 0xf0 | ((UnicodeChar >> 18) & 0x07);
      Buffer[1] = 0x80 | ((UnicodeChar >> 12 ) & 0x3f);
      Buffer[2] = 0x80 | ((UnicodeChar >> 6 ) & 0x3f);
      Buffer[3] = 0x80 | (UnicodeChar & 0x3f);
      BufferSize = 4;
    } /*else if (Index <= 26) {
      Buffer[0] = 0xf8 | ((UnicodeChar >> 24 ) & 0x03);
      Buffer[1] = 0x80 | ((UnicodeChar >> 18 ) & 0x3f);
      Buffer[2] = 0x80 | ((UnicodeChar >> 12 ) & 0x3f);
      Buffer[3] = 0x80 | ((UnicodeChar >> 6 ) & 0x3f);
      Buffer[4] = 0x80 | (UnicodeChar & 0x3f);
      BufferSize = 5;
    } else if (Index <= 31) {
      Buffer[0] = 0xfc | ((UnicodeChar >> 30 ) & 0x01);
      Buffer[1] = 0x80 | ((UnicodeChar >> 24 ) & 0x3f);
      Buffer[2] = 0x80 | ((UnicodeChar >> 18 ) & 0x3f);
      Buffer[3] = 0x80 | ((UnicodeChar >> 12 ) & 0x3f);
      Buffer[4] = 0x80 | ((UnicodeChar >> 6 ) & 0x3f);
      Buffer[5] = 0x80 | (UnicodeChar & 0x3f);
      BufferSize = 6;
    } */else {
      ASSERT(0);
      return MPQ_INVALID_HASH;
    }

    HashA = MpqHashData(Buffer, BufferSize, HashTypeA, (PCULONG)Table, &SeedA1, &SeedA2);
    HashB = MpqHashData(Buffer, BufferSize, HashTypeB, (PCULONG)Table, &SeedB1, &SeedB2);
  }

  return ((ULONGLONG)HashA << 32) | HashB;
}

ULONGLONG Hash(PCANSI_STRING String, CONST VOID* Table) {
  if (!String) return MPQ_INVALID_HASH;
  UNICODE_STRING unicode;
  NTSTATUS status = RtlAnsiStringToUnicodeString(&unicode, String, TRUE);
  if (!NT_SUCCESS(status)) return FALSE;

  ULONGLONG h = Hash(&unicode, Table);
  RtlFreeUnicodeString(&unicode);
  return h;
}