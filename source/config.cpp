#include <ntdef.h>
#include "config.h"

#include <crtdbg.h>
#include <intrin.h>

#define CONFIG_ITEM_ENTRY_TYPE_FREE_FLAG      1
#define CONFIG_ITEM_ENTRY_TYPE_TAIL_FLAG      2
#define CONFIG_ITEM_ENTRY_TYPE_SIZE_FLAG      (CONFIG_ITEM_ENTRY_TYPE_FREE_FLAG | CONFIG_ITEM_ENTRY_TYPE_TAIL_FLAG)
#define CONFIG_ITEM_ENTRY_TYPE_SERI_FLAG      4
#define CONFIG_ITEM_ENTRY_TYPE_SAME_FLAG      8


#define CONFIG_CONFIG_HEADER_TYPE_SE_FLAG     1
#define CONFIG_CONFIG_HEADER_TYPE_DE_FLAG     2
#define CONFIG_CONFIG_HEADER_TYPE_CRYPT_FLAG  4
#define CONFIG_CONFIG_HEADER_TYPE_BAD         8

#define TABLE_HEADER_MAGIC_NUMBER             0x0816
#define TABLE_HEADER_CURRENT_VERSION          0

typedef struct _CONFIG_ITEM_HEADER {
  USHORT          Size;
  UCHAR           Index;
  UCHAR           Count;
  ULONG           Crc32;
  ULONGLONG       Hash;
} CONFIG_ITEM_HEADER, *PCONFIG_ITEM_HEADER;
static_assert(sizeof(CONFIG_ITEM_HEADER) == 0x10, "");

typedef struct _CONFIG_ITEM_ENTRY {
  USHORT          Size;
  UCHAR           Type;
  UCHAR           Reserve[1];
  ULONG           Crc32;
  ULONGLONG       Index;
  union {
    ULONGLONG     Value;
    PVOID         Ptr;
    CHAR*         Str;
    WCHAR*        Wstr;
  };
} CONFIG_ITEM_ENTRY, *PCONFIG_ITEM_ENTRY;
static_assert(sizeof(CONFIG_ITEM_ENTRY) == 0x18, "");

typedef struct _CONFIG_ITEM {
  CONFIG_ITEM_HEADER Header;
  CONFIG_ITEM_ENTRY Entry[1];
} CONFIG_ITEM, *PCONFIG_ITEM;
static_assert(sizeof(CONFIG_ITEM) == 0x28, "");

typedef struct _CONFIG_HEADER {
  USHORT          MagicNumber;
  USHORT          Size;
  USHORT          Count;
  UCHAR           Type;
  UCHAR           Version;
  ULONG           ConfigSize;
  ULONG           Crc32;
} CONFIG_HEADER, *PCONFIG_HEADER;
static_assert(sizeof(CONFIG_HEADER) == 0x10, "");

typedef struct _CONFIG_ENTRY {
  ULONGLONG       Hash;
  union {
    ULONGLONG     Value;
    PVOID         Ptr;
    PCONFIG_ITEM  Item;
  };
} CONFIG_ENTRY, *PCONFIG_ENTRY;
static_assert(sizeof(CONFIG_ENTRY) == 0x10, "");

typedef struct _CONFIG_TABLE {
  CONFIG_HEADER   Header;
  CONFIG_ENTRY    Entry[1];
} CONFIG_TABLE, *PCONFIG_TABLE;
static_assert(sizeof(CONFIG_TABLE) == 0x20, "");

inline ULONG ShamCrc32En(ULONG Val1, ULONG Val2) {
  ULONG Val = Val1 ^ Val2;
  return _rotr(Val, Val2 & 31);
}

inline ULONG ShamCrc32(ULONG Val1, ULONG Val2) {
  ULONG Val = Val1 ^ Val2;
  return _rotr(Val, Val2 & 31);
}

inline ULONG ShamCrc32De(ULONG Val1, ULONG Val2) {
  ULONG Val = _rotl(Val1, Val2 & 31);
  return Val ^ Val2;
}

#ifdef _UCRT

#include <malloc.h>
#include <search.h>

PCONFIG_ITEM GenConfigItem(ULONGLONG Hash, UCHAR MaxCount) {
  USHORT Size = FIELD_OFFSET(CONFIG_ITEM, Entry)
    + sizeof(CONFIG_ITEM::Entry) * MaxCount;
  _ASSERT(Size <= 0xffff && MaxCount > 0);
  if (Size > 0xffff) return nullptr;

  PCONFIG_ITEM Context = (PCONFIG_ITEM)malloc(Size);
  if (!Context) return nullptr;

  memset(Context, 0, Size);

  Context->Header.Hash = Hash;
  Context->Header.Size = Size;
  Context->Header.Count = MaxCount;
  return Context;
}

VOID ReleaseConfigItem(PCONFIG_ITEM Context) {
  _ASSERT(Context);
  if (!Context) return;

  for (USHORT i = 0; i < Context->Header.Count; i++) {
    if (Context->Entry[i].Type & CONFIG_ITEM_ENTRY_TYPE_FREE_FLAG) {
      free(Context->Entry[i].Ptr);
    }
  }
  free(Context);
}

int __cdecl entry_sort(void*, const void* Left, const void* Right) {
  const CONFIG_ITEM_ENTRY* L = (const CONFIG_ITEM_ENTRY*)Left;
  const CONFIG_ITEM_ENTRY* R = (const CONFIG_ITEM_ENTRY*)Right;
  //LONGLONG Value = L->Index - R->Index;
  return L->Index == R->Index ? 0 : (L->Index > R->Index ? 1 : -1);
}

BOOLEAN SetConfigItemEntry(PCONFIG_ITEM Context, ULONGLONG Index,
  PVOID Value, USHORT Length) {
  _ASSERT(Context);
  if (!Context || Context->Header.Index >= Context->Header.Count)
    return FALSE;

  _ASSERT(Length <= 0xffff);
  if ((Length && !Value) || Length > 0xffff) {
    return FALSE;
  }
  auto Entry = &Context->Entry[Context->Header.Index];
  PVOID Ptr = &Entry->Value;
  if (Length > sizeof(Entry->Value)) {
    Ptr = malloc(Length);
  }
  if (!Ptr) return FALSE;

  Context->Entry[Context->Header.Index++].Index = Index;

  memcpy(Ptr, Value, Length);
  Entry->Size = Length & 0xffff;

  if (Ptr != &Entry->Value) {
    Entry->Ptr = Ptr;
    Entry->Type |= CONFIG_ITEM_ENTRY_TYPE_FREE_FLAG;
  } else {
    Entry->Type &= ~CONFIG_ITEM_ENTRY_TYPE_FREE_FLAG;
  }

  Entry->Crc32 = ShamCrc32(0, Entry->Size);
  Entry->Crc32 = ShamCrc32(Entry->Crc32, ((ULONG*)&Entry->Index)[0]);
  Entry->Crc32 = ShamCrc32(Entry->Crc32, ((ULONG*)&Entry->Index)[1]);
  for (USHORT i = 0; i < Entry->Size / sizeof(ULONG); i++) {
    Entry->Crc32 = ShamCrc32(Entry->Crc32, ((PULONG)Ptr)[i]);
  }
  if (Entry->Size & 3) {
    ULONG Tail = 0;
    memcpy(&Tail, (CHAR*)Ptr + (Entry->Size & ~3), Entry->Size & 3);
    Entry->Crc32 = ShamCrc32(Entry->Crc32, Tail);
  }

  if (Context->Header.Index == Context->Header.Count) {
    qsort_s(Context->Entry,
      Context->Header.Count,
      sizeof(Context->Entry),
      entry_sort,
      nullptr);
    // crc
    Context->Header.Crc32 = ShamCrc32(0, ((ULONG*)&Context->Header.Hash)[0]);
    Context->Header.Crc32 = ShamCrc32(Context->Header.Crc32, ((ULONG*)&Context->Header.Hash)[1]);
    Context->Header.Crc32 = ShamCrc32(Context->Header.Crc32, Context->Header.Size);
    Context->Header.Crc32 = ShamCrc32(Context->Header.Crc32, Context->Header.Count);
    for (int i = 0; i < Context->Header.Count; i++) {
      Context->Header.Crc32 = ShamCrc32(Context->Header.Crc32, Context->Entry[i].Crc32);
    }
  }

  return TRUE;
}

typedef struct _STRING_INFORMATION {
  PVOID       String;
  USHORT      Length;
  USHORT      Offset;
} STRING_INFORMATION, *PSTRING_INFORMATION;

ULONG SerializeConfigItem(PCONFIG_ITEM Context,
  PVOID Base, PSTRING_INFORMATION StrArray, ULONG StrArrayCount) {
  if (!Context) return 0;
  _ASSERT(Context->Header.Index == Context->Header.Count);
  if (Context->Header.Index != Context->Header.Count) return 0;

  const ULONG Size = Context->Header.Size;
  if (!Base) return Size;

  PCONFIG_ITEM BaseContext = (PCONFIG_ITEM)Base;
  memcpy(Base, Context, Size);

  for (SHORT i = 0; i < Context->Header.Count; i++) {
    if (Context->Entry[i].Type & CONFIG_ITEM_ENTRY_TYPE_FREE_FLAG) {
      for (ULONG n = 0; n < StrArrayCount; n++) {
        if (BaseContext->Entry[i].Str == StrArray[n].String ||
          (BaseContext->Entry[i].Size == StrArray[n].Length &&
           memcmp(BaseContext->Entry[i].Ptr, StrArray[n].String, StrArray[n].Length) == 0)) {
          BaseContext->Entry[i].Value = StrArray[n].Offset;
          break;
        }
      }
      _ASSERT(BaseContext->Entry[i].Value != Context->Entry[i].Value);

      BaseContext->Entry[i].Type &= ~CONFIG_ITEM_ENTRY_TYPE_FREE_FLAG;
      BaseContext->Entry[i].Type |= CONFIG_ITEM_ENTRY_TYPE_TAIL_FLAG;
    }
  }

  return Size;
}

int __cdecl item_sort(void*, const void* Left, const void* Right) {
  const CONFIG_ENTRY* L = (const CONFIG_ENTRY*)Left;
  const CONFIG_ENTRY* R = (const CONFIG_ENTRY*)Right;
  //LONGLONG Value = L->Hash - R->Hash;
  return L->Hash == R->Hash ? 0 : (L->Hash > R->Hash ? 1 : -1);
}

ULONG en(void* mem, int len, ULONG pass) {
  char* m = (char*)mem;
  char* k = (char*)&pass;

  for (int i = 0, j = 0; i < len; i++, j = (j + 1) & 0x03) {
    m[i] ^= k[j];
    k[j] = _rotr8(k[j], i % 8);
    k[j] ^= (i + j) % 131;
  }
  return pass;
}

int __cdecl str_info_sort(void*, const void* Left, const void* Right) {
  const STRING_INFORMATION* L = (const STRING_INFORMATION*)Left;
  const STRING_INFORMATION* R = (const STRING_INFORMATION*)Right;

  return L->Length == R->Length ? memcmp(L->String, R->String, L->Length) : (L->Length > R->Length ? 1 : -1);
}

ULONG SerialzeConfigTailString(PCONFIG_ITEM* Items, USHORT Count,
  PSTRING_INFORMATION StrArray, PULONG StrArrayCount, 
  PVOID Base, ULONG Length) {
  if (*StrArrayCount == 0) return 0;

  PSTRING_INFORMATION Info = StrArray;
  for (ULONG i = 0; i < Count; i++) {
    for (SHORT j = 0; j < Items[i]->Header.Count; j++) {
      if (Items[i]->Entry[j].Type & CONFIG_ITEM_ENTRY_TYPE_SIZE_FLAG) {
        *Info = {0};
        Info->Length = Items[i]->Entry[j].Size;
        Info->String = Items[i]->Entry[j].Str;
        Info++;
      }
    }
  }

  _ASSERT((ULONG)(Info - StrArray) == *StrArrayCount);

  qsort_s(StrArray, *StrArrayCount, sizeof(STRING_INFORMATION), str_info_sort, nullptr);

  Info = StrArray;
  USHORT NeedLength = (Info[0].Length + 7) & ~7;
  for (ULONG i = 0, c = *StrArrayCount, j = 1; j < c; j++) {
    if (Info[i].Length == Info[j].Length && memcmp(Info[i].String, Info[j].String, Info[i].Length) == 0) {
      (*StrArrayCount)--;
    } else {
      if (i + 1 != j) {
        Info[i + 1] = Info[j];
      }
      i++;
      NeedLength += (Info[i].Length + 7) & ~7;
    }
  }

  if (Base && NeedLength <= Length) {
    USHORT offset = 0;
    for (int i = 0, c = *StrArrayCount; i < c; i++) {
      Info[i].Offset = offset;
      memmove((CHAR*)Base + offset, Info[i].String, Info[i].Length);
      offset += (Info[i].Length + 7) & ~7;
    }
    _ASSERT(offset == NeedLength);
  }
  return NeedLength;
}

ULONG SerialzeConfig(PCONFIG_ITEM* Items, USHORT Count,
  PVOID Base, ULONG Length) {
  // 支持0长的 SerialzeConfig，这样DeserialzeConfig函数返回0就表示错误，其他为Size值。
  //if (!Items || !Count) return 0;

  USHORT Size = FIELD_OFFSET(CONFIG_TABLE, Entry) + sizeof(CONFIG_TABLE::Entry) * Count;
  USHORT FixSize = Size;

  ULONG TailStrMaxMayCount = 0;
  for (ULONG i = 0; i < Count; i++) {
    FixSize += Items[i]->Header.Size;

    for (SHORT j = 0; j < Items[i]->Header.Count; j++) {
      if (Items[i]->Entry[j].Type & CONFIG_ITEM_ENTRY_TYPE_SIZE_FLAG) {
        TailStrMaxMayCount++;
      }
    }
  }
  _ASSERT(FixSize <= 60 * 1024);

  auto StrArray = (PSTRING_INFORMATION)_alloca(TailStrMaxMayCount * sizeof(STRING_INFORMATION));
  ULONG s = SerialzeConfigTailString(Items, Count, StrArray, &TailStrMaxMayCount,
    Base ? (CHAR*)Base + FixSize : nullptr,
    Length - FixSize);
  s += FixSize;
  if (Size + s > Length) return Size + s;

  for (USHORT i = 0; i < TailStrMaxMayCount; i++) {
    StrArray[i].Offset += FixSize;
  }

  PCONFIG_TABLE Table = (PCONFIG_TABLE)Base;
  {
    ULONG r = 0;
    for (ULONG i = 0; i < Count; i++) {
      PVOID b = (CHAR*)Base + Size + r;
      r += SerializeConfigItem(Items[i], b, StrArray, TailStrMaxMayCount);

      Table->Entry[i].Hash = Items[i]->Header.Hash;
      Table->Entry[i].Value = (ULONGLONG)b - (ULONGLONG)Base;
    }
    _ASSERT((PVOID)&Table->Entry[Count] == (CHAR*)Table + Size);
    _ASSERT(Size + r == FixSize);
  }

  if (Size + s <= Length && Base) {
    Table->Header = {0};
    Table->Header.MagicNumber = TABLE_HEADER_MAGIC_NUMBER;
    Table->Header.ConfigSize = Size + s;
    Table->Header.Count = Count;
    Table->Header.Size = Size;
    Table->Header.Type = CONFIG_CONFIG_HEADER_TYPE_SE_FLAG;

    Table->Header.Version = TABLE_HEADER_CURRENT_VERSION;

    qsort_s(Table->Entry,
      Table->Header.Count,
      sizeof(Table->Entry),
      item_sort,
      nullptr);

    Table->Header.Type |= CONFIG_CONFIG_HEADER_TYPE_CRYPT_FLAG;

    ULONG Crc32 = ShamCrc32(0, Table->Header.MagicNumber);
    Crc32 = ShamCrc32(Crc32, Table->Header.ConfigSize);
    Crc32 = ShamCrc32(Crc32, Table->Header.Type);
    Crc32 = ShamCrc32(Crc32, Table->Header.Count);

    for (int i = 0; i < Table->Header.Count; i++) {
      auto Item = PCONFIG_ITEM((CHAR*)Table + Table->Entry[i].Value);
      Crc32 = ShamCrc32(Crc32, ((PULONG)&Table->Entry[i])[0]);
      Crc32 = ShamCrc32(Crc32, ((PULONG)&Table->Entry[i])[1]);
      Crc32 = ShamCrc32(Crc32, ((PULONG)&Table->Entry[i])[2]);
      Crc32 = ShamCrc32(Crc32, ((PULONG)&Table->Entry[i])[3]);

      Crc32 = ShamCrc32(Crc32, Item->Header.Crc32);
    }
    Table->Header.Crc32 = Crc32;

    ULONG Pass = en(Table->Entry, Table->Header.ConfigSize - sizeof(Table->Header), Table->Header.Crc32);
    Pass;
    Crc32 = 0;
    for (ULONG i = 0; i < (Table->Header.ConfigSize - sizeof(Table->Header)) / sizeof(ULONG); i++) {
      Crc32 = ShamCrc32(Crc32, ((PULONG)Table->Entry)[i]);
    }
    Table->Header.Crc32 = ShamCrc32En(Table->Header.Crc32, Crc32);
  } else if (Base && Length >= sizeof(Table->Header)) {
    Table->Header = {0};
    Table->Header.MagicNumber = TABLE_HEADER_MAGIC_NUMBER;
    Table->Header.ConfigSize = Size + s;
  }

  return Size + s;
}
#endif // _UCRT
#include <search.h>


ULONG de(void* mem, int len, ULONG pass) {
  char* m = (char*)mem;
  char* k = (char*)&pass;

  for (int i = 0, j = 0; i < len; i++, j = (j + 1) & 0x03) {
    m[i] ^= k[j];
    k[j] = _rotr8(k[j], i % 8);
    k[j] ^= (i + j) % 131;
  }
  return pass;
}

int __cdecl item_entry_index_search(void* context, const void *key, const void *datum) {
  CONST ULONGLONG* k = (CONST ULONGLONG*)key;
  CONST CONFIG_ITEM_ENTRY* entry = (CONST CONFIG_ITEM_ENTRY*)datum;
  context;
  return *k == entry->Index ? 0 : (*k > entry->Index ? 1 : -1);
}

int __cdecl config_entry_index_search(void* context, const void *key, const void *datum) {
  CONST ULONGLONG* k = (CONST ULONGLONG*)key;
  CONST CONFIG_ENTRY* item = (CONST CONFIG_ENTRY*)datum;
  context;
  return *k == item->Hash ? 0 : (*k > item->Hash ? 1 : -1);
}

BOOLEAN GetConfigItemEntry(CONST CONFIG_ITEM* Item, ULONGLONG Index,
  PVOID Value, ULONG Length, PULONG OutSize) {
  _ASSERT(Item);
  if (!Item) return FALSE;

  if (Item->Header.Count == 0) {
    return FALSE;
  }

  PCONFIG_ITEM_ENTRY p = (PCONFIG_ITEM_ENTRY)bsearch_s(
    &Index,
    Item->Entry,
    Item->Header.Count,
    sizeof(Item->Entry),
    item_entry_index_search,
    nullptr);
  if (!p) return FALSE;

  if (OutSize) *OutSize = p->Size;

  if (Length < p->Size
    || !Value) {
    return FALSE;
  }

  CONST VOID* Ptr;
  if (p->Size > sizeof(p->Value))
    Ptr = p->Ptr;
  else
    Ptr = &p->Value;

  memcpy(Value, Ptr, p->Size);

  return TRUE;
}

CONST VOID* GetConfigItemEntry(CONST CONFIG_ITEM* Item,
  ULONGLONG Index, PULONG OutSize) {
  _ASSERT(Item);
  if (!Item) return nullptr;

  if (Item->Header.Count == 0) {
    return nullptr;
  }

  PCONFIG_ITEM_ENTRY p = (PCONFIG_ITEM_ENTRY)bsearch_s(
    &Index,
    Item->Entry,
    Item->Header.Count,
    sizeof(Item->Entry),
    item_entry_index_search,
    nullptr);
  if (!p) return FALSE;

  if (OutSize) *OutSize = p->Size;

  CONST VOID* Ptr;
  if (p->Size > sizeof(p->Value))
    Ptr = p->Ptr;
  else
    Ptr = &p->Value;

  return Ptr;
}

CONST CONFIG_ITEM* GetConfigItem(
  CONST CONFIG_TABLE* Config, ULONGLONG Index) {
  if (!Config) return nullptr;

  if (Config->Header.Count == 0) return nullptr;

  PCONFIG_ENTRY p = nullptr;

  p = (PCONFIG_ENTRY)bsearch_s(
    &Index,
    Config->Entry,
    Config->Header.Count,
    sizeof(Config->Entry),
    config_entry_index_search,
    nullptr);

  return p ? p->Item : nullptr;
}

ULONG DeserializeConfigItem(PCONFIG_ITEM Context, BOOLEAN Deserialze, PVOID Base) {
  if (!Context) return 0;

  ULONG Size = Context->Header.Size;

  for (SHORT i = 0; i < Context->Header.Count; i++) {
    if (Context->Entry[i].Type & CONFIG_ITEM_ENTRY_TYPE_TAIL_FLAG) {
      if (Deserialze) {
        Context->Entry[i].Ptr = (CHAR*)Base + Context->Entry[i].Value;
        Context->Entry[i].Type &= ~CONFIG_ITEM_ENTRY_TYPE_TAIL_FLAG;
      }
    }
  }

  return Size;
}

ULONG DeserialzeConfig(PCONFIG_TABLE Table, BOOLEAN Deserialze) {
  ULONG ConfigSize = 0;
  ULONG rConfigSize = 0;
  __try {
    if (!Table || !(Table->Header.Type & CONFIG_CONFIG_HEADER_TYPE_SE_FLAG)) __leave;
    if (Table->Header.Type & CONFIG_CONFIG_HEADER_TYPE_BAD) __leave;
    if (Table->Header.MagicNumber != TABLE_HEADER_MAGIC_NUMBER) __leave;
    if (Table->Header.Version != TABLE_HEADER_CURRENT_VERSION) __leave;
    if (!Deserialze) {
      rConfigSize = Table->Header.ConfigSize;
      __leave;
    }

    auto RawType = Table->Header.Type;
    if (RawType & CONFIG_CONFIG_HEADER_TYPE_CRYPT_FLAG) {
      ULONG Crc32 = 0;
      for (ULONG i = 0; i < (Table->Header.ConfigSize - sizeof(Table->Header)) / sizeof(ULONG); i++) {
        Crc32 = ShamCrc32(Crc32, ((PULONG)Table->Entry)[i]);
      }
      Crc32 = ShamCrc32De(Table->Header.Crc32, Crc32);

      ULONG Pass = de(Table->Entry, Table->Header.ConfigSize - sizeof(Table->Header), Crc32);
      Pass;

      ULONG CheckCrc32 = ShamCrc32(0, Table->Header.MagicNumber);
      CheckCrc32 = ShamCrc32(CheckCrc32, Table->Header.ConfigSize);
      CheckCrc32 = ShamCrc32(CheckCrc32, RawType);
      CheckCrc32 = ShamCrc32(CheckCrc32, Table->Header.Count);

      for (int i = 0; i < Table->Header.Count; i++) {
        CheckCrc32 = ShamCrc32(CheckCrc32, ((PULONG)&Table->Entry[i])[0]);
        CheckCrc32 = ShamCrc32(CheckCrc32, ((PULONG)&Table->Entry[i])[1]);
        CheckCrc32 = ShamCrc32(CheckCrc32, ((PULONG)&Table->Entry[i])[2]);
        CheckCrc32 = ShamCrc32(CheckCrc32, ((PULONG)&Table->Entry[i])[3]);

        PCONFIG_ITEM Item = PCONFIG_ITEM(Table->Entry[i].Value + (ULONGLONG)Table);
        if ((CHAR*)Item <= (CHAR*)&Table->Entry[i].Item ||
          (CHAR*)Item >= (CHAR*)Table + Table->Header.ConfigSize) {
          __leave;
        }

        CheckCrc32 = ShamCrc32(CheckCrc32, Item->Header.Crc32);
      }
      if (Crc32 != CheckCrc32) {
        Table->Header.Type |= CONFIG_CONFIG_HEADER_TYPE_BAD;
        __leave;
      }

      Table->Header.Type &= ~CONFIG_CONFIG_HEADER_TYPE_CRYPT_FLAG;
    }

    Table->Header.Type |= CONFIG_CONFIG_HEADER_TYPE_BAD;

    ULONG Size = Table->Header.Size;

    for (ULONG i = 0; i < Table->Header.Count; i++) {
      Table->Entry[i].Value += (ULONGLONG)Table;
      auto Item = Table->Entry[i].Item;
      Size += DeserializeConfigItem(Item, Deserialze, Table);

      // 计算每一个entry的crc32
      for (ULONG j = 0; j < Table->Entry[i].Item->Header.Count; j++) {
        auto Entry = Item->Entry + j;

        PVOID Ptr = &Entry->Value;
        if (Entry->Size > sizeof(Entry->Value)) {
          Ptr = Entry->Ptr;
        }

        ULONG Crc32 = ShamCrc32(0, Entry->Size);
        Crc32 = ShamCrc32(Crc32, ((ULONG*)&Entry->Index)[0]);
        Crc32 = ShamCrc32(Crc32, ((ULONG*)&Entry->Index)[1]);

        for (USHORT k = 0; k < Entry->Size / sizeof(ULONG); k++) {
          Crc32 = ShamCrc32(Crc32, ((PULONG)Ptr)[k]);
        }
        if (Entry->Size & 3) {
          ULONG Tail = 0;
          memcpy(&Tail, (CHAR*)Ptr + (Entry->Size & ~3), Entry->Size & 3);
          Crc32 = ShamCrc32(Crc32, Tail);
        }

        if (Crc32 != Entry->Crc32)
          __leave;
      }

      ULONG Crc32 = ShamCrc32(0, ((ULONG*)&Item->Header.Hash)[0]);
      Crc32 = ShamCrc32(Crc32, ((ULONG*)&Item->Header.Hash)[1]);
      Crc32 = ShamCrc32(Crc32, Item->Header.Size);
      Crc32 = ShamCrc32(Crc32, Item->Header.Count);
      for (int j = 0; j < Item->Header.Count; j++) {
        Crc32 = ShamCrc32(Crc32, Item->Entry[j].Crc32);
      }
      if (Crc32 != Item->Header.Crc32)
        __leave;
    }

    Table->Header.Type &= ~CONFIG_CONFIG_HEADER_TYPE_BAD;

    if (Size <= Table->Header.ConfigSize)
      ConfigSize = Table->Header.ConfigSize;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    _ASSERT(0);
  }

  if (ConfigSize) {
    Table->Header.Type &= ~CONFIG_CONFIG_HEADER_TYPE_SE_FLAG;
    Table->Header.Type |= CONFIG_CONFIG_HEADER_TYPE_DE_FLAG;

    if (ConfigSize != Table->Header.ConfigSize) {
      Table->Header.Type &= ~CONFIG_CONFIG_HEADER_TYPE_BAD;
      ConfigSize = 0;
    }
    rConfigSize = ConfigSize;
  }
  return rConfigSize;
}

BOOLEAN IsSameConfig(CONST CONFIG_TABLE* Config1, CONST CONFIG_TABLE* Config2) {
  if (!!Config1 ^ !!Config2 || Config1 == nullptr) return FALSE;

  if (Config1->Header.MagicNumber != TABLE_HEADER_MAGIC_NUMBER
    || Config2->Header.MagicNumber != TABLE_HEADER_MAGIC_NUMBER
    || Config1->Header.Version != Config2->Header.Version) return FALSE;

  return Config1->Header.Crc32 == Config2->Header.Crc32;
}

ULONG MinimumConfigSize() {
  return sizeof(CONFIG_TABLE) + sizeof(CONFIG_ITEM);
}