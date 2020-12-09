#ifndef __LOGICAL_FUNCTION_H__
#define __LOGICAL_FUNCTION_H__

#include "../log.h"

// 这里如果修改，需要联通config_in.lua中的算法一同修改
enum _CONFIG_ACTION {
  ConfigActionBaseValue = MaxRegNtNotifyClass + 3,
  RegActionKeyRedirect = ConfigActionBaseValue,
  RegActionValueRevalue,
  RegActionValueReenum,
  RegActionQueryKeyRedirect,
  RegActionSetValueNotice,// 56
  ConfigActionMaxValue,
};

#define LOGICAL_FUNCTION_COUNTER_FLAGS  0x80000000UL

CONST VOID* ActionProcessRoutine[];

typedef enum _WHITE_LIST_CHECK_STATUS {
  NOT_INITIALIZED = -2,
  NON_INDEX_EXIST = -1,
  INDEX_NOT_IN_LIST = 0,
  INDEX_IN_LIST = 1,
} WHITE_LIST_CHECK_STATUS;

WHITE_LIST_CHECK_STATUS GlobalWhiteList(CONST CONFIG_TABLE* Config, ULONGLONG GlobalIndex, ULONGLONG LocalIndex,
  ULONGLONG Hash);

BOOLEAN GlobalWhiteListEx(CONST CONFIG_TABLE* Config, ULONGLONG GlobalIndex, ULONGLONG LocalIndex,
  PUNICODE_STRING String);

WHITE_LIST_CHECK_STATUS WhiteList(CONST CONFIG_ITEM* Item, ULONGLONG LocalIndex, ULONGLONG Hash);

BOOLEAN WhiteListEx(CONST CONFIG_ITEM* Item, ULONGLONG LocalIndex, PUNICODE_STRING String);

CONST VOID* ActionProcessComm(const CONFIG_ITEM* Item, ULONGLONG ValueHash,
  ULONG_PTR Call, _CONFIG_ACTION Action, PULONG Size);

/*
 *  ValueHash表示当前Item下搜索需要的Hash值，通常通过ValueName计算得出
 *  Casll表示REG_NOTIFY_CLASS值，明确当前的触发过程。
 *  Action表示需要进行的操作。
 *  Other...表示Action所需要的参数，各函数不同。
*/
template<typename... T>
NTSTATUS ActionProcess(const CONFIG_ITEM* Item, ULONGLONG ValueHash,
  ULONG_PTR Call, _CONFIG_ACTION Action, T... Other) {
  NTSTATUS st = STATUS_SUCCESS;

  ULONG Size;
  CONST VOID* Value = ActionProcessComm(Item, ValueHash, Call, Action, &Size);
  if (!Value) return st;

  if (!(ConfigActionBaseValue <= Action && Action < ConfigActionMaxValue))
    return st;

  CONST VOID* k = ActionProcessRoutine[Action - ConfigActionBaseValue];
  typedef NTSTATUS (*ActionRoutine)(CONST VOID*, CONST ULONG, T...);
  auto f = ActionRoutine(k);

  __try {
    st = f(Value, Size, Other...);
  } __except(Log("GetExceptionInformation %p", GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
    Log("%p, %p, %d, %p", f, Value, Size, Other...);
    ASSERT(0);
  }
  return st;
}

#endif // !__LOGICAL_FUNCTION_H__