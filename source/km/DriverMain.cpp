#include <Ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#include "config.h"
#include "constexpr.h"
#include "macro.h"

#include "CmRegistryFilter.h"

#include "log.h"
#include "MpqHash.h"

#include "GlobalEnvironment.h"

#include "UndocumentedApi.h"
#include "DllInject.h"

#include "../gen/version.h"

PGLOBAL_ENVIRONMENT _Global;

extern BOOLEAN DrvDelegateRoutine(ULONG_PTR Delegate, PVOID Ctx, ULONGLONG ProcessHash, ULONGLONG KeyHash);

// #pragma code_seg("PAGE")

#pragma warning(push)
#pragma warning(disable: 4307)
VOID SetGlobalUpdateConfig(PGLOBAL_ENVIRONMENT Global) {
  ConstexprHashOABS(UpdateKeyHash, "\\Registry\\Machine\\Software\\Anonymous\\HasUpdate");
  ConstexprHashOABS(DrvSetUnloadKeyHash, "\\Registry\\Machine\\Software\\Anonymous\\DrvInstall");

  constexpr LONGLONG  DEALY_UPDATE_CONFIG = (10 * 1000 * 1000) * 3600LL; // 1 hour
  constexpr LONGLONG  DEALY_UPDATE_CONFIG_RUNNING = (10 * 1000 * 1000) * 120LL; // 2 minute
  constexpr LONGLONG  DEALY_UPDATE_FAILED = (10 * 1000 * 1000) * 15LL; // 15 seconds

  Global->UpdateConfigCycle = DEALY_UPDATE_CONFIG;
  Global->UpdateConfigFaileDealy = DEALY_UPDATE_FAILED;
  Global->UpdateConfigFirstDealy = DEALY_UPDATE_CONFIG_RUNNING;
  Global->UpdateConfigForceKeyHash = UpdateKeyHashULL;
  Global->DrvSetUnloadKeyHash = DrvSetUnloadKeyHashULL;
  Global->DrvFlags = 0;
  Global->CsrssExeFullPathHash = 0;

  if (!Global->Config) return;

  auto item = GetConfigItem(Global->Config, CONFIG_GLOBAL_INDEX_CONFIG);
  if (!item) return;

  ULONG size = 0;
  auto ptr = GetConfigItemEntry(item, CONFIG_LOCAL_INDEX_UPDATE, &size);
  if (ptr && size == sizeof(ULONGLONG)) {
    Global->UpdateConfigCycle = *(PULONGLONG)ptr;
  }

  ptr = GetConfigItemEntry(item, CONFIG_LOCAL_INDEX_UPDATE_FIRST, &size);
  if (ptr && size == sizeof(ULONGLONG)) {
    Global->UpdateConfigFirstDealy = *(PULONGLONG)ptr;
  }

  ptr = GetConfigItemEntry(item, CONFIG_LOCAL_INDEX_UPDATE_FAILE, &size);
  if (ptr && size == sizeof(ULONGLONG)) {
    Global->UpdateConfigFaileDealy = *(PULONGLONG)ptr;
  }

  ptr = GetConfigItemEntry(item, CONFIG_LOCAL_INDEX_UPDATE_FORCE, &size);
  if (ptr && size == sizeof(ULONGLONG)) {
    Global->UpdateConfigForceKeyHash = *(PULONGLONG)ptr;
  }

  ptr = GetConfigItemEntry(item, CONFIG_LOCAL_INDEX_DRV_SET_UNLOAD, &size);
  if (ptr && size == sizeof(ULONGLONG)) {
    Global->DrvSetUnloadKeyHash = *(PULONGLONG)ptr;
  }

  ptr = GetConfigItemEntry(item, CONFIG_LOCAL_INDEX_DRV_FLAGS, &size);
  if (ptr && size == sizeof(ULONGLONG)) {
    Global->DrvFlags = *(PULONGLONG)ptr;
  }

  ptr = GetConfigItemEntry(item, CONFIG_LOCAL_INDEX_CSRSS_HASH, &size);
  if (ptr && size == sizeof(ULONGLONG)) {
    Global->CsrssExeFullPathHash = *(PULONGLONG)ptr;
  }
}
#pragma warning(pop)

VOID ClearMapPoolPagesInUserSpace(PVOID* PoolMemory, PMDL* PagesMdl, PVOID* MmPagesPointer) {
  if (MmPagesPointer && *MmPagesPointer) {
    MmUnmapLockedPages(*MmPagesPointer, *PagesMdl);
    *MmPagesPointer = nullptr;
  }

  if (PagesMdl && *PagesMdl) {
    for (PMDL current = *PagesMdl; current != nullptr;) {
      auto tmp = current->Next;
      if (current->MdlFlags & MDL_PAGES_LOCKED) {
        MmUnlockPages(current);
      }
      current = tmp;
    }

    IoFreeMdl(*PagesMdl);
    *PagesMdl = nullptr;
  }

  if (PoolMemory && *PoolMemory) {
    ExFreePool(*PoolMemory);
    *PoolMemory = nullptr;
  }
}

PVOID MapPoolPagesInUserSpace(PVOID* PoolMemory, ULONG Size, PMDL* PagesMdl) {
  ASSERT(PagesMdl == nullptr || *PagesMdl == nullptr);

  if (!*PoolMemory) {
    *PoolMemory = MALLOC(Size);
    if (*PoolMemory) RtlZeroMemory(*PoolMemory, Size);
  }
  if (!*PoolMemory) return nullptr;
  if (!PagesMdl) return nullptr;

  if (!*PagesMdl)
    *PagesMdl = IoAllocateMdl(*PoolMemory, Size, FALSE, FALSE, nullptr);
  if (!*PagesMdl) return nullptr;

  MmBuildMdlForNonPagedPool(*PagesMdl);

  PVOID Ptr = nullptr;
  __try {
    Ptr = MmMapLockedPagesSpecifyCache(*PagesMdl, UserMode, MmCached, nullptr, FALSE,
      *NtBuildNumber >= 9200 ? (MdlMappingNoExecute | HighPagePriority) : HighPagePriority);
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    ASSERT(0);
  }
  return Ptr;
}

EXTERN_C POBJECT_TYPE* MmSectionObjectType;
BOOLEAN InitializeInjectSectionObject(PGLOBAL_ENVIRONMENT Env) {
  HANDLE RootHandle = nullptr;
  NTSTATUS st = STATUS_UNSUCCESSFUL;

  __try {
    if (!_Global->DriverRootPath.Length)
      __leave;

    IO_STATUS_BLOCK block;
    OBJECT_ATTRIBUTES FileAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(
      &_Global->DriverRootPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

    st = ZwCreateFile(&RootHandle, FILE_READ_DATA, &FileAttributes,
      &block, nullptr, 0, FILE_SHARE_READ,
      FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    if (!NT_SUCCESS(st)) {
      Log("ZwCreateFile Error! %08x", st);
      __leave;
    }

    UNICODE_STRING FileName = {
      8, 8
    };

#ifdef _M_X64
    constexpr int ForMaxLoop = 2;
    FileName.Buffer = L":x86:x64";
#else
    constexpr int ForMaxLoop = 1;
    FileName.Buffer = L":x86";
#endif // _M_X64

    FileAttributes.ObjectName = &FileName;
    FileAttributes.RootDirectory = RootHandle;
    for (int i = 0; i < ForMaxLoop; i++) {
      FileName.Buffer += i * 4;
      ASSERT(Env->InjectFileHandle[i] == nullptr);
      st = ZwCreateFile(&Env->InjectFileHandle[i], FILE_READ_DATA | FILE_GENERIC_EXECUTE, &FileAttributes,
        &block, nullptr, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
      if (!NT_SUCCESS(st)) __leave;
    }
  } __except (Log("GetExceptionInformation %p", GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
    st = STATUS_UNSUCCESSFUL;
    ASSERT(0);
  }
  if (RootHandle) ZwClose(RootHandle);

  return NT_SUCCESS(st);
}

BOOLEAN InitializeInjectMapObject(PGLOBAL_ENVIRONMENT Env) {
#ifdef _M_X64
  constexpr int ForMaxLoop = 2;
#else
  constexpr int ForMaxLoop = 1;
#endif // _M_X64

  PAGED_CODE();
  for (int i = 0; i < ForMaxLoop; i++) {
    if (Env->InjectFileHandle[i]) {
      ASSERT(Env->InjectDllMemorySize[i] == 0);
      ASSERT(Env->InjectDllMemory[i] == nullptr);

      HANDLE h = CreateInjectDllHandle(Env->InjectFileHandle[i]);
      if (!h) continue;
      auto InjectDllPtr = MapInjectDll(NtCurrentProcess(), h, &Env->InjectDllMemorySize[i]);
      ZwClose(h);
      if (!InjectDllPtr) {
        Env->InjectDllMemorySize[i] = 0;
        continue;
      }

      PVOID mem = nullptr;
      MapPoolPagesInUserSpace(&mem, Env->InjectDllMemorySize[i] & 0xffffffff, nullptr);
      if (!mem) {
        ZwUnmapViewOfSection(NtCurrentProcess(), InjectDllPtr);
        Env->InjectDllMemorySize[i] = 0;
        continue;
      }
      RtlCopyMemory(mem, InjectDllPtr, Env->InjectDllMemorySize[i]);
      ZwUnmapViewOfSection(NtCurrentProcess(), InjectDllPtr);
      Env->InjectDllMemory[i] = mem;
    }
  }
  return !!Env->InjectDllMemory[0] && (ForMaxLoop == 1 || !!Env->InjectDllMemory[1]);
}

constexpr NTSTATUS NonCallbackRunning = -1;

VOID UnloadSelfCallBack(
  IN PVOID,
  IN PVOID,
  IN PVOID Result
) {
  NTSTATUS& st = *(NTSTATUS*)Result;
  Log("%p, %08x", Result, st);

  st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES,
    _Global->ServiceKeyName.Buffer,
    L"ObjectName",
    REG_SZ,
    _Global->DriverObjectName.Buffer,
    _Global->DriverObjectName.Length + sizeof(wchar_t));
  ASSERT(NonCallbackRunning != st);
  Log("Write ObjectName %08x, %wZ", st, _Global->DriverObjectName);
  if (NT_SUCCESS(st)) {
    Log("DriverUnload %p, Flags %08x", _Global->DrvObj->DriverUnload, _Global->DrvObj->Flags);
    _Global->DrvObj->DriverUnload = _Global->DriverUnload;

    _Global->DrvFlags &= ~DRV_FLAGS_RESTORE_REGISTRY;
  }
}

VOID RestoreSelfCallBack(
  IN PVOID,
  IN PVOID,
  IN PVOID
) {
  DWORD32 Value = 1;

  NTSTATUS st = STATUS_SUCCESS;

  if (_Global->DriverFilePath.Length) {
    st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer,
      L"ImagePath", REG_EXPAND_SZ, _Global->DriverFilePath.Buffer, _Global->DriverFilePath.Length + sizeof(wchar_t));
    Log("ImagePath %wZ", _Global->DriverFilePath);

    ASSERT(st == STATUS_SUCCESS);
  } else {
    ASSERT(0);
  }

  if (_Global->DriverObjectName.Length) {
    st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer,
      L"ObjectName", REG_SZ, _Global->DriverObjectName.Buffer, _Global->DriverObjectName.Length + sizeof(wchar_t));
    Log("ObjectName %wZ", _Global->DriverObjectName);
    ASSERT(st == STATUS_SUCCESS);
  } else {
    ASSERT(0);
  }

  if (_Global->RepairCommand.Length) {
    st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer,
      L"RepairCommand", REG_SZ, _Global->RepairCommand.Buffer, _Global->RepairCommand.Length + sizeof(wchar_t));
    Log("RepairCommand %wZ", _Global->RepairCommand);
    ASSERT(st == STATUS_SUCCESS);
  } else {
    ASSERT(0);
  }

  st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer,
    L"Start", REG_DWORD, (PVOID)&Value, sizeof(DWORD32));
  ASSERT(st == STATUS_SUCCESS);

  st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer,
    L"Type", REG_DWORD, (PVOID)&Value, sizeof(DWORD32));
  ASSERT(st == STATUS_SUCCESS);

  st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer,
    L"ErrorControl", REG_DWORD, (PVOID)&Value, sizeof(DWORD32));
  ASSERT(st == STATUS_SUCCESS);

}

VOID SystemPowerStateCallBack(
  IN PVOID,
  IN PVOID pState,
  IN PVOID pValue) {
  ULONG_PTR State = (ULONG_PTR)pState;
  ULONG_PTR Value = (ULONG_PTR)pValue;

  Log("State %p, Value %p", pState, pValue);

  if (!Value && State == PO_CB_SYSTEM_STATE_LOCK) {
    if (_Global->DrvFlags & DRV_FLAGS_RESTORE_REGISTRY)
      RestoreSelfCallBack(nullptr, nullptr, nullptr);

    if ((_Global->DrvFlags & DRV_FLAGS_REPAIR_COMMAND) && _Global->RepairCommand.Length) {
      NTSTATUS st = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, LR"(\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\RunOnce)",
        L"asdrv_repair", REG_SZ, _Global->RepairCommand.Buffer, _Global->RepairCommand.Length + sizeof(wchar_t));
      Log("asdrv_repair %wZ", _Global->RepairCommand);
      st;
      ASSERT(st == STATUS_SUCCESS);
    } else {
      ASSERT(0);
    }
  }
}
#pragma code_seg("PAGE")
VOID DrvUnload(__in struct _DRIVER_OBJECT *drvobj) {
  drvobj;
  if (_Global) {
    if (_Global->CbRegistration) ExUnregisterCallback(_Global->CbRegistration);
    if (_Global->CallBackObject) ObDereferenceObject(_Global->CallBackObject);

    if (_Global->SystemPowerStateCbRegistration) ExUnregisterCallback(_Global->SystemPowerStateCbRegistration);
    if (_Global->SystemPowerStateCallBackObject) ObDereferenceObject(_Global->SystemPowerStateCallBackObject);

    int Count = 0;

    LARGE_INTEGER Delay;
    Delay.QuadPart = DEALY_TIME;

    LONG DelegateStatus = InterlockedCompareExchange(
      &_Global->DelegateStatus,
      DELEGATE_STATUS_IN_DELEGATE,
      DELEGATE_STATUS_WAIT_TIMER);

    PCM_REGISTRY_FILTER_CONTEXT CurrentFilter = (PCM_REGISTRY_FILTER_CONTEXT)InterlockedCompareExchangePointer(
      (volatile PVOID*)&_Global->Filter, nullptr, _Global->Filter);
    if (CurrentFilter) {
      UninitializeRegistryFilter(CurrentFilter);
      CurrentFilter = nullptr;
    }

    while (DelegateStatus != DELEGATE_STATUS_WAIT_TIMER) {
      DelegateStatus = InterlockedCompareExchange(
        &_Global->DelegateStatus,
        DELEGATE_STATUS_IN_DELEGATE,
        DELEGATE_STATUS_WAIT_TIMER);

      if (!CurrentFilter) {
        CurrentFilter = (PCM_REGISTRY_FILTER_CONTEXT)InterlockedCompareExchangePointer(
          (volatile PVOID*)&_Global->Filter, nullptr, _Global->Filter);
      }
      KeDelayExecutionThread(KernelMode, FALSE, &Delay);
      Count++;
    }

    if (CurrentFilter) {
      UninitializeRegistryFilter(CurrentFilter);
    }
    Log("Count %d", Count);

    if (_Global->Config) {
      ExFreePool(_Global->Config);
    }

    ClearMapPoolPagesInUserSpace(&_Global->UpdateConfig, &_Global->UpdateMdl, nullptr);

    if (_Global->Altitude[0]) ExDeleteNPagedLookasideList(&_Global->StackStretchList);

    if (_Global->DrvFlags & DRV_FLAGS_RESTORE_REGISTRY) {
      Log("Restore Registry");
      RestoreSelfCallBack(nullptr, nullptr, nullptr);
    }

    for (int i = 0; i < _ARRAYSIZE(_Global->InjectFileHandle); i++) {
      if (_Global->InjectFileHandle[i]) ZwClose(_Global->InjectFileHandle[i]);

      if (_Global->InjectDllMemory[i]) ExFreePool(_Global->InjectDllMemory[i]);
    }

    if (_Global->DriverFileHandle) ZwClose(_Global->DriverFileHandle);

    if (IoGetDriverObjectExtension(drvobj, &drvobj->DriverExtension) != _Global) {
      ExFreePool(_Global);
      Log("ExFreePool(_Global);");
    }
  }
  Log("Over DriverObject %p\n", drvobj);
}

#pragma code_seg("INIT")
VOID InitializeGlobalConstants(PGLOBAL_ENVIRONMENT Global) {
  RtlZeroMemory(Global, sizeof(GLOBAL_ENVIRONMENT));
  RtlCopyMemory(Global->CallbackString, LR"(\Callback\)", sizeof(Global->CallbackString));
  static_assert(sizeof(Global->CallbackString) == sizeof(LR"(\Callback\)") - sizeof(wchar_t), R"(sizeof \Callback\ conflict)");

  Global->ServiceKeyName = {
    0,
    sizeof(Global->ServiceKeyNameBuffer),
    (PWCH)Global->ServiceKeyNameBuffer
  };

  Global->DriverFilePath = {
    0,
    sizeof(Global->DriverFilePathBuffer),
    (PWCH)Global->DriverFilePathBuffer
  };

  Global->DriverRootPath = {
    0,
    sizeof(Global->DriverRootPathBuffer),
    (PWCH)Global->DriverRootPathBuffer
  };
  

  Global->DriverRegistryPath = {
    0,
    sizeof(Global->DriverRegistryPathBuffer),
    (PWCH)Global->DriverRegistryPathBuffer
  };

  Global->DriverObjectName = {
    0,
    sizeof(Global->DriverObjectNameBuffer),
    (PWCH)Global->DriverObjectNameBuffer
  };

  Global->RepairCommand = {
    0,
    sizeof(Global->RepairCommandBuffer),
    (PWCH)Global->RepairCommandBuffer
  };

  GenHashTable((ULONG(&)[MPQ_HASH_TABLE_SIZE])Global->Table);
  SetGlobalUpdateConfig(Global);
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT drvobj, PUNICODE_STRING regpath) {
  Log("Loading DriverObject %p", drvobj);

  NTSTATUS status = STATUS_UNSUCCESSFUL;
  __try {
    NTSTATUS st = IoAllocateDriverObjectExtension(drvobj, &drvobj->DriverExtension,
      sizeof(GLOBAL_ENVIRONMENT), (PVOID*)&_Global);
    if (!NT_SUCCESS(st)) {
      _Global = (PGLOBAL_ENVIRONMENT)MALLOC(sizeof(GLOBAL_ENVIRONMENT));
      if (!_Global) {
        ASSERT(0);
        __leave;
      }
    }

    InitializeGlobalConstants(_Global);
    _Global->DrvObj = drvobj;

    RtlCopyUnicodeString(&_Global->DriverObjectName, &drvobj->DriverName);
    if (_Global->DriverObjectName.Length != drvobj->DriverName.Length) {
      ASSERT(FALSE);
      __leave;
    }
    Log("ObjectName %wZ", _Global->DriverObjectName);
    RtlCopyUnicodeString(&_Global->DriverRegistryPath, regpath);
    if (_Global->DriverRegistryPath.Length != regpath->Length) {
      ASSERT(FALSE);
      __leave;
    }

    {
      for (auto i = _Global->DriverRegistryPath.Length / 2 - 1; i >= 0; i--) {
        if (_Global->DriverRegistryPath.Buffer[i] == L'\\') {
          // _Global???????0
          st = RtlAppendUnicodeToString(&_Global->ServiceKeyName, _Global->DriverRegistryPath.Buffer + i + 1);
          if (!NT_SUCCESS(st)) __leave;
          break;
        }
      }
    }

    if (!_Global->ServiceKeyName.Length) __leave;

    MapPoolPagesInUserSpace(&_Global->UpdateConfig, UPDATE_CONFIG_MAX_SIZE, nullptr);
    if (_Global->UpdateConfig) {
      ((PLONG)_Global->UpdateConfig)[0] = -UPDATE_CONFIG_MAX_SIZE;
    }

    RTL_QUERY_REGISTRY_TABLE QueryTable[] = {
      {
        nullptr,
        RTL_QUERY_REGISTRY_DIRECT,
        L"ImagePath",
        &_Global->DriverFilePath,
        REG_SZ | REG_EXPAND_SZ,
        nullptr,
        0
      },
      {
        nullptr,
        RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_TYPECHECK,
        _Global->UpdateConfig ? STORE_VALUE_NAME : nullptr,
        _Global->UpdateConfig,
        REG_BINARY << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT,
        nullptr,
        0
      },
      {
        nullptr,
        RTL_QUERY_REGISTRY_DIRECT,
        L"RepairCommand",
        &_Global->RepairCommand,
        REG_SZ | REG_EXPAND_SZ,
        nullptr,
        0
      },
      {0}
    };
    {
      RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer, QueryTable, nullptr, nullptr);
    }

    if (_Global->UpdateConfig) {
      ULONG Size = DeserialzeConfig((PCONFIG_TABLE)_Global->UpdateConfig, TRUE);
      if (MinimumConfigSize() < Size && Size <= UPDATE_CONFIG_MAX_SIZE) {
        Log("Load Config From Registry %wZ", regpath);
        _Global->UpdateConfig = InterlockedExchangePointer((PVOID*)&_Global->Config, _Global->UpdateConfig);
        SetGlobalUpdateConfig(_Global);
        ASSERT(_Global->UpdateConfig == nullptr);
      }
    }

    // \??\c:\windows\system32\drivers:asdrv.sys => \??\c:\windows\system32\drivers
    // \??\c:\windows\system32\drivers\asdrv.sys => \??\c:\windows\system32\drivers\asdrv.sys
    if (_Global->DriverFilePath.Length) {
      {
        IO_STATUS_BLOCK block;
        OBJECT_ATTRIBUTES FileAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&_Global->DriverFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

        st = ZwCreateFile(&_Global->DriverFileHandle, FILE_READ_DATA, &FileAttributes,
          &block, nullptr, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ,
          FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
        ASSERT(_Global->DriverFileHandle);
      }

      USHORT LastIndex = _Global->DriverFilePath.Length / 2 - 1;
      for (int i = LastIndex; i >= 0; i--) {
        if (_Global->DriverFilePath.Buffer[i] == L':') {
          if (i == LastIndex || (i + 1 <= LastIndex &&
            (_Global->DriverFilePath.Buffer[i + 1] == L'\0' ||
              _Global->DriverFilePath.Buffer[i + 1] != L'\\'
              ))) {
            RtlCopyUnicodeString(&_Global->DriverRootPath, &_Global->DriverFilePath);

            _Global->DriverRootPath.Buffer[i] = L'\0';
            _Global->DriverRootPath.Length = (USHORT)(i * 2);
            break;
          }
        }
      }
    }

    Log("Driver File Path %wZ, %wZ", &_Global->DriverFilePath, &_Global->DriverRootPath);
    if (_Global->DriverRootPath.Length == 0 && _Global->Config == nullptr) {
      ASSERT(0);
      __leave;
    }

    RtlCopyMemory(_Global->Altitude, L"9876540", sizeof(L"9876540"));

    ExInitializeNPagedLookasideList(&_Global->StackStretchList,
      nullptr, nullptr, *NtBuildNumber >= 9600 ? NonPagedPoolNx : NonPagedPool,
      LOOK_SIDE_ENTRY_MAX_SIZE, LINE_NUMBER, 0);

    if (!InitializeInjectSectionObject(_Global)) __leave;
    if (!InitializeInjectMapObject(_Global)) __leave;

    {
      UNICODE_STRING ObjName = {
        sizeof(_Global->CallbackString) + _Global->ServiceKeyName.Length,
        sizeof(_Global->CallbackString) + _Global->ServiceKeyName.Length,
        (PWCHAR)_Global->CallbackString
      };

      OBJECT_ATTRIBUTES ObjAttributes;
      InitializeObjectAttributes(&ObjAttributes,
        &ObjName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_PERMANENT,
        nullptr,
        nullptr);
      st = ExCreateCallback(&_Global->CallBackObject,
        &ObjAttributes,
        TRUE,
        TRUE);
      Log("ExCreateCallback %08x, %wZ", st, &ObjName);

      if (NT_SUCCESS(st)) {
        st = NonCallbackRunning;
        ExNotifyCallback(_Global->CallBackObject, nullptr, &st);
        Log("Callback Result %08x", st);
        if (NT_SUCCESS(st)) {
          st = ZwUnloadDriver(regpath);
          Log("ZwUnloadDriver %08x, %wZ", st, regpath);
          if (!NT_SUCCESS(st)) __leave;
        } else if (st != NonCallbackRunning) {
          __leave;
        } else {
          ASSERT(st == NonCallbackRunning);
        }
        _Global->DriverUnload = DrvUnload;
        _Global->CbRegistration = ExRegisterCallback(_Global->CallBackObject, UnloadSelfCallBack, _Global);
        ASSERT(_Global->CbRegistration);
        if (!_Global->CbRegistration) __leave;
      } else {
        __leave;
      }
    }

    status = InitializeRegistryFilter(_Global->DrvObj, _Global->Altitude,
      &_Global->StackStretchList, _Global->Config,
      _Global->Table, DrvDelegateRoutine, &_Global->Filter);
    if (!NT_SUCCESS(status)) {
      Log("InitializeRegistryFilter Unsuccessed %08x", status);
      __leave;
    }

    status = STATUS_SUCCESS;

    {
      UNICODE_STRING ObjName = RTL_CONSTANT_STRING(LR"(\Callback\PowerState)");

      OBJECT_ATTRIBUTES ObjAttributes;
      InitializeObjectAttributes(&ObjAttributes,
        &ObjName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_PERMANENT,
        nullptr,
        nullptr);
      st = ExCreateCallback(&_Global->SystemPowerStateCallBackObject,
        &ObjAttributes,
        FALSE,
        TRUE);
      Log("ExCreateCallback %08x, %wZ", st, &ObjName);

      if (NT_SUCCESS(st)) {
        _Global->SystemPowerStateCbRegistration = ExRegisterCallback(
          _Global->SystemPowerStateCallBackObject, SystemPowerStateCallBack, _Global);
      }

    }
#define W2(x)       L ## x
#define W1(x)       W2(x)
    {
      const wchar_t version[] = W1(BUILD_VERSION);
      RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer, L"Version", REG_SZ, (PVOID)version, sizeof(version));
    }
#ifdef DBG
    const wchar_t time[] = W1(__TIMESTAMP__);
    RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, _Global->ServiceKeyName.Buffer, L"TimeStamp", REG_SZ, (PVOID)time, sizeof(time));
#endif // DBG
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    Log("Driver Entry Unsuccess!");
    ASSERT(0);
  }

  if (!NT_SUCCESS(status)) {
    DrvUnload(drvobj);
  }
  Log("Finish Driver Entry %08x\n", status);
  return status;
}