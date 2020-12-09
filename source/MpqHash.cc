#include "MpqHash.h"

#undef HashType
#undef HashTable

#pragma warning(disable : 4307)
#pragma warning(push)

VOID Encrypt(PVOID Data, SIZE_T Size, PCSTR Password, SIZE_T Length) {
  CHAR I = 0;
  for (SIZE_T P = 0, S = 0; S < Size; P++, S++) {
    if (P >= Length) {
      P -= Length;
      I += 13;
    }
    if (!Password[P]) continue;
    PUCHAR(Data)[S] ^= Password[P] + I;
  }

  return;
}

ULONG MpqHashData(CONST VOID* Data, ULONG Size, HashType Type,
  PCULONG Table,
  ULONG Seed1, ULONG Seed2) {
  PUCHAR D = (PUCHAR)Data;

  for(; Size; Size--, D++) {
    ULONG Ch = ToUpper(D);
    Seed1 = (Table[(Type << 8) + Ch]) ^ (Seed1 + Seed2);
    Seed2 = Ch + Seed1 + Seed2 + (Seed2 << 5) + 3;
  }
  return Seed1;
}

void GenHashTable(ULONG (&Table)[MPQ_HASH_TABLE_SIZE]) {
  ULONG Seed = 0x00100001;
typedef unsigned short USHORT;

  for (int i = 0; i < 0x100; i++) {
    for (int j = 0, k = i; j < 5; j++, k += 0x100) {
      Seed = (Seed * 125 + 3) % 0x2aaaab;
      USHORT Hi = Seed & 0xffff;
      Seed = (Seed * 125 + 3) % 0x2aaaab;
      USHORT Lo = Seed & 0xffff;

      Table[k] = (Hi << 0x10) | Lo;
    }
  }
}

#pragma warning(pop)

