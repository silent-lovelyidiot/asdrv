#ifndef __CONFIG_H__
#define __CONFIG_H__

typedef struct _CONFIG_ITEM   CONFIG_ITEM, *PCONFIG_ITEM;

typedef struct _CONFIG_TABLE  CONFIG_TABLE, *PCONFIG_TABLE;

#ifdef _UCRT

PCONFIG_ITEM GenConfigItem(ULONGLONG Hash, UCHAR MaxCount);

VOID ReleaseConfigItem(PCONFIG_ITEM Context);

BOOLEAN SetConfigItemEntry(PCONFIG_ITEM Context, ULONGLONG Index,
  PVOID Value, USHORT Length);

ULONG SerialzeConfig(PCONFIG_ITEM* Items, USHORT Count,
  PVOID Base, ULONG Length);

#endif // _UCRT

BOOLEAN IsSameConfig(CONST CONFIG_TABLE* Config1, CONST CONFIG_TABLE* Config2);

CONST CONFIG_ITEM* GetConfigItem(CONST CONFIG_TABLE* Config, ULONGLONG Index);

BOOLEAN GetConfigItemEntry(CONST CONFIG_ITEM* Item, ULONGLONG Index,
  PVOID Value, ULONG Length, PULONG OutSize);

CONST VOID* GetConfigItemEntry(CONST CONFIG_ITEM* Item, ULONGLONG Index, PULONG OutSize);

ULONG DeserialzeConfig(PCONFIG_TABLE Table, BOOLEAN Deserialze);

ULONG MinimumConfigSize();

#endif // !__CONFIG_H__