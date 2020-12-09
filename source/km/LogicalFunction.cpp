#include <ntddk.h>
#include <wdm.h>
#include "config.h"

#include <search.h>
#include "LogicalFunction.h"

#include <vadefs.h>

#include "MmProbeHelper.h"

int __cdecl white_list_search(const void *key,
  const void *datum) {
  CONST ULONGLONG* k = (CONST ULONGLONG*)key;
  CONST ULONGLONG* d = (CONST ULONGLONG*)datum;

  return *k == *d ? 0 : (*k > *d ? 1 : -1);
}

WHITE_LIST_CHECK_STATUS WhiteList(CONST CONFIG_ITEM * Item, ULONGLONG LocalIndex, ULONGLONG Hash) {
  ULONG size = 0;
  auto value = GetConfigItemEntry(Item, LocalIndex, &size);
  if (!value) return NON_INDEX_EXIST;

  return nullptr != bsearch(&Hash,
    value, size / sizeof(ULONGLONG),
    sizeof(ULONGLONG), white_list_search) ? INDEX_IN_LIST : INDEX_NOT_IN_LIST;
}

WHITE_LIST_CHECK_STATUS GlobalWhiteList(CONST CONFIG_TABLE* Config, ULONGLONG GlobalIndex, ULONGLONG LocalIndex,
  ULONGLONG Hash) {
  auto item = GetConfigItem(Config, GlobalIndex);
  return WhiteList(item, LocalIndex, Hash);
}

// Action
// 这里如果修改，需要联通config_in.lua中的算法一同修改
ULONGLONG ConfigHashValue(ULONGLONG Value, ULONG_PTR call, _CONFIG_ACTION action) {
  return Value + call * 1000 + action * 333333;
}

CONST VOID* ActionProcessComm(const CONFIG_ITEM* Item, ULONGLONG ValueHash,
  ULONG_PTR Call, _CONFIG_ACTION Action, PULONG Size) {
  return GetConfigItemEntry(Item,
    ConfigHashValue(ValueHash, Call, Action), Size);
}

// Routine
// Value以\Registry开头
NTSTATUS fRegActionKeyRedirect(CONST VOID* Value, CONST ULONG Size,
  PCUNICODE_STRING RootName, PUNICODE_STRING* String) {
  if (Size == sizeof(ULONG)) {
    return *((CONST PULONG)Value);
  }
  NTSTATUS st = STATUS_SUCCESS;
  if (!String || !*String) return st;
  PUNICODE_STRING Str = *String;
  PCWCH Val = (PCWCH)Value;

  if (Str->Buffer == nullptr)
    return st;

  if (Val[0] != L'\\') return st;
  if (RootName == nullptr && Str->Buffer[0] != L'\\') return st;

  // \Registry
  if (RootName && !(RootName->Length > Size || RootName->Length < 18)) {
    int Len = RootName->Length / 2;

    // 确保修改值与原值在一个root key下。
    if (!(Len < 9) && _wcsnicmp(RootName->Buffer, Val, Len) == 0) {
      PUNICODE_STRING RemainingName = nullptr;
      for (ULONG_PTR Rsp = (ULONG_PTR)String - 0x100; Rsp < (ULONG_PTR)String; Rsp += sizeof(ULONG_PTR) * 2) {
        PUNICODE_STRING p = (PUNICODE_STRING)Rsp;
        if (p->MaximumLength == Str->MaximumLength
          && (CHAR*)p->Buffer + p->Length == (CHAR*)Str->Buffer + Str->Length) {
          RemainingName = p;
          break;
        }
      }

      if (RemainingName) {
        int SubLen = Size - RootName->Length - 2;
        ASSERT(SubLen);
        if (SubLen < 0) SubLen = 0;
        RtlCopyMemory(Str->Buffer, &Val[Len + 1], SubLen);
        Str->Length = SubLen & 0xffff;
        RtlZeroMemory((CHAR*)Str->Buffer + Str->Length, Str->MaximumLength - Str->Length);

        *RemainingName = *Str;
        Log("redirect to %wZ %wZ", RootName, RemainingName);
        return st;//STATUS_CALLBACK_BYPASS;
      }
    }
  }
  Log("Current Root %wZ, SubKey %wZ, Redirect Key %S", RootName, Str, Val);
  // 如果要重定向到不同root下，需要更多的代码。
  return st;
}

template<typename T>
ULONG FillValueKeyInformationInternal(PVOID InfoParam, ULONG Type, ULONG Length,
  PCWCHAR ValueName, ULONG ValueNameLength,
  CONST VOID* ValueData, ULONG ValueDataLength) {
  DBG_UNREFERENCED_PARAMETER(ValueName);
  DBG_UNREFERENCED_PARAMETER(ValueNameLength);
  DBG_UNREFERENCED_PARAMETER(ValueData);
  DBG_UNREFERENCED_PARAMETER(ValueDataLength);

  T* Info = (T*)InfoParam;

  ULONG ResultLength = 0;
  ResultLength +=
    __if_exists(T::TitleIndex) {
      sizeof(T::TitleIndex) +
    }
    sizeof(T::Type);

  __if_exists(T::NameLength) {
    ResultLength += ValueNameLength + sizeof(T::NameLength);
  }
  __if_exists(T::DataLength) {
    PVOID Data;
    __if_exists(T::Data) {
      Data = &Info->Data;
    }
    ResultLength += sizeof(T::DataLength) + ValueDataLength;
  }
  __if_exists(T::DataOffset) {
    ResultLength += sizeof(T::DataOffset);
  }

  if (Info == nullptr || Length == 0/* || ResultLength > Length*/) return ResultLength;

#define CAN_WRITE_FIELD(base, field)            (Length >= ResultLength) || ((CHAR*)(&(base->field)) - (CHAR*)(base) + sizeof(base->field)) < Length
#define CAN_WRITE_BUFFER(base, buffer, length)  (Length >= ResultLength) || ((CHAR*)(base) + Length > (CHAR*)(buffer) + (length)) ? \
                                                  length : 0 // ((CHAR*)(base) + Length - (CHAR*)(buffer) > 0 ? (CHAR*)(base) + Length - (CHAR*)(buffer) : 0)
  __if_exists(T::TitleIndex) {
    if (CAN_WRITE_FIELD(Info, TitleIndex))
      Info->TitleIndex = 0;
  }

  if (CAN_WRITE_FIELD(Info, Type))
    Info->Type = Type;

  __if_exists(T::NameLength) {
    if (CAN_WRITE_FIELD(Info, NameLength))
      Info->NameLength = ValueNameLength;

    RtlCopyMemory(Info->Name, ValueName, CAN_WRITE_BUFFER(Info, Info->Name, ValueNameLength));
  }

  __if_exists(T::DataOffset) {
    if (CAN_WRITE_FIELD(Info, DataOffset))
      Info->DataOffset = ResultLength - ValueDataLength;
    Data = (PVOID)((PUCHAR)Info + Info->DataOffset);
  }

  __if_exists(T::DataLength) {
    if (CAN_WRITE_FIELD(Info, DataLength))
      Info->DataLength = ValueDataLength;
    RtlCopyMemory(Data, ValueData, CAN_WRITE_BUFFER(Info, Data, ValueDataLength));
  }

  return ResultLength;
}

ULONG FillValueKeyInformation(KEY_VALUE_INFORMATION_CLASS InfoClass, VOID* Info,
  ULONG Type, ULONG Length,
  PCWCHAR ValueName, ULONG ValueNameLength,
  CONST VOID* ValueData, ULONG ValueDataLength) {
  static decltype(FillValueKeyInformationInternal<void>)* cb[MaxKeyValueInfoClass] = {
    FillValueKeyInformationInternal<KEY_VALUE_BASIC_INFORMATION>,
    FillValueKeyInformationInternal<KEY_VALUE_FULL_INFORMATION>,
    FillValueKeyInformationInternal<KEY_VALUE_PARTIAL_INFORMATION>,
    FillValueKeyInformationInternal<KEY_VALUE_FULL_INFORMATION>,
    FillValueKeyInformationInternal<KEY_VALUE_PARTIAL_INFORMATION_ALIGN64>,
  };

  ASSERT(InfoClass < MaxKeyValueInfoClass);
  if (InfoClass >= KeyValueFullInformationAlign64) {
    PVOID AlignedInfo = (char*)(((ULONG_PTR)Info + 7) & ~7ULL);
    ULONG Offset = (ULONG)((ULONG_PTR)AlignedInfo - (ULONG_PTR)Info);
    return Offset +
        FillValueKeyInformation((KEY_VALUE_INFORMATION_CLASS)(InfoClass),
                                AlignedInfo, Type, Length - Offset, ValueName,
                                ValueNameLength, ValueData, ValueDataLength);
  }

  return cb[InfoClass](Info, Type, Length,
    ValueName, ValueNameLength, ValueData, ValueDataLength);
}

NTSTATUS fRegActionValueRevalue(CONST VOID* Value, CONST ULONG Size,
  KEY_VALUE_INFORMATION_CLASS InfoClass, VOID* Info, ULONG Length,
  PCWCHAR ValueName, ULONG ValueNameLength,
  PULONG ReturnLength) {
  if (!MmProbeForWriteUser((PVOID)Info, Length, 1))
    return STATUS_SUCCESS;
  if (!MmProbeForWriteUser((PVOID)ReturnLength, sizeof(ULONG), sizeof(ULONG)))
    return STATUS_SUCCESS;

  ULONG Type = *((CONST PULONG)Value);

  ULONG flag = Type & ~0x0f;
  Type &= 0x0f;

  ULONG r = FillValueKeyInformation(InfoClass, Info,
    Type, Length, ValueName, ValueNameLength, (char*)Value + sizeof(ULONG), Size - sizeof(ULONG));

  *ReturnLength = r;
  if (r > Length) {
    return Length >= 0x0c ? STATUS_BUFFER_OVERFLOW : STATUS_BUFFER_TOO_SMALL;
  }

  // 自增计数器
  if ((flag & LOGICAL_FUNCTION_COUNTER_FLAGS) && Type == REG_DWORD && (Size - sizeof(ULONG)) == sizeof(ULONG))
    (*(ULONG*)((char*)Value + sizeof(ULONG)))++;
  else if((flag & LOGICAL_FUNCTION_COUNTER_FLAGS) && Type == REG_QWORD && (Size - sizeof(ULONG)) == sizeof(ULONGLONG)) {
    (*(ULONGLONG*)((char*)Value + sizeof(ULONG)))++;
  }
  return STATUS_CALLBACK_BYPASS;
}

NTSTATUS fRegActionValueReenum(CONST VOID* Value, CONST ULONG Size,
  KEY_VALUE_INFORMATION_CLASS InfoClass, VOID* Info, ULONG Length,
  PULONG ReturnLength) {
  if (Size == sizeof(ULONG)) {
    return *((CONST PULONG)Value);
  }

  if (!MmProbeForWriteUser((PVOID)Info, Length, 1))
    return STATUS_SUCCESS;
  if (!MmProbeForWriteUser((PVOID)ReturnLength, sizeof(ULONG), sizeof(ULONG)))
    return STATUS_SUCCESS;

  if (Size < sizeof(ULONG) * 3) return STATUS_SUCCESS;
  CONST CHAR* Data = (CONST CHAR*)Value;
  ULONG Type;
  RtlCopyMemory(&Type, Data, sizeof(ULONG));
  Data += sizeof(ULONG);

  ULONG ValueNameLength;
  RtlCopyMemory(&ValueNameLength, Data, sizeof(ULONG));
  Data += sizeof(ULONG);

  ULONG ValueDataLength;
  RtlCopyMemory(&ValueDataLength, Data, sizeof(ULONG));
  Data += sizeof(ULONG);

  PCWCHAR ValueName = (PCWCHAR)Data;
  Data += ValueNameLength;

  if ((ULONG)(Data + ValueDataLength - (CHAR*)Value) != Size) {
    return STATUS_SUCCESS;
  }

  ULONG r = FillValueKeyInformation(InfoClass, Info, Type, Length,
    ValueName, ValueNameLength, Data, ValueDataLength);

  *ReturnLength = r;
  if (r > Length) {
    return Length >= 0x0c ? STATUS_BUFFER_OVERFLOW : STATUS_BUFFER_TOO_SMALL;
  }

  return STATUS_CALLBACK_BYPASS;
}

NTSTATUS fRegActionQueryKeyRedirect(CONST VOID* Value, CONST ULONG Size,
  KEY_INFORMATION_CLASS InfoClass, VOID* Info, ULONG Length,
  PULONG ReturnLength) {
  if (InfoClass != KeyNameInformation) return STATUS_SUCCESS;
  if (!ReturnLength) return STATUS_SUCCESS;

  if (!MmProbeForWriteUser((PVOID)Info, Length, 1))
    return STATUS_SUCCESS;
  if (!MmProbeForWriteUser((PVOID)ReturnLength, sizeof(ULONG), sizeof(ULONG)))
    return STATUS_SUCCESS;

  *ReturnLength = Size;

  if (Size > Length) {
    return Length >= 0x0c ? STATUS_BUFFER_OVERFLOW : STATUS_BUFFER_TOO_SMALL;
  }

  if (Info) {
    RtlCopyMemory(Info, Value, Size);
  }

  return STATUS_CALLBACK_BYPASS;
}

NTSTATUS fRegActionSetValueNotice(CONST VOID* Value, CONST ULONG Size, ULONG* Type,
  PVOID* Data, ULONG* DataSize) {
  if (Size < sizeof(NTSTATUS)) return STATUS_SUCCESS;
  NTSTATUS st;
  RtlCopyMemory(&st, Value, sizeof(NTSTATUS));

  // Data, DataSize如果需要访问的话 需要使用 MmProbeForXXX进行测试。
  Type, Data, DataSize;
  extern VOID ForceDllInject();
  ForceDllInject();
  return STATUS_SUCCESS;
}

CONST VOID* ActionProcessRoutine[ConfigActionMaxValue - ConfigActionBaseValue] = {
  fRegActionKeyRedirect,
  fRegActionValueRevalue,
  fRegActionValueReenum,
  fRegActionQueryKeyRedirect,
  fRegActionSetValueNotice,
};
