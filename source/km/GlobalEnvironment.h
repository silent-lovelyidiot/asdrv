#ifndef __GLOBAL_ENVIRONMENT_H__
#define __GLOBAL_ENVIRONMENT_H__

typedef struct _GLOBAL_ENVIRONMENT_CORE {
  // Altitude和Table的放置方式是有意义的，可以参考InitializeRegistryFilter的注释。
  WCHAR                       Altitude[8];
  ULONG                       Table[MPQ_HASH_TABLE_SIZE];

  UNICODE_STRING              DriverRegistryPath;
  UNICODE_STRING              Reserve0;
  // 驱动路径。
  UNICODE_STRING              DriverFilePath;
  // 全路径，表示注入dll的RootObject路径。
  UNICODE_STRING              DriverRootPath;

  UNICODE_STRING              ServiceKeyName;
  UNICODE_STRING              DriverObjectName;

  PDRIVER_OBJECT              DrvObj;
  PDRIVER_UNLOAD              DriverUnload;

  PCALLBACK_OBJECT            CallBackObject;
  PVOID                       CbRegistration;

  PCALLBACK_OBJECT            SystemPowerStateCallBackObject;
  PVOID                       SystemPowerStateCbRegistration;

  UNICODE_STRING              RepairCommand;

  PCM_REGISTRY_FILTER_CONTEXT Filter;
  PCONFIG_TABLE               Config;

  // 表示即将更新的配置信息。
  PVOID                       UpdateConfig;
  PMDL                        UpdateMdl;

  // 定期更新配置的计时器。
  LARGE_INTEGER               Timer;
  ULONGLONG                   CsrssExeFullPathHash;

  LONGLONG                    UpdateConfigCycle;
  LONGLONG                    UpdateConfigFirstDealy;
  LONGLONG                    UpdateConfigFaileDealy;
  ULONGLONG                   UpdateConfigForceKeyHash;
  ULONGLONG                   DrvSetUnloadKeyHash;
  ULONGLONG                   DrvFlags;

  // 表示当前起作用的Filter所使用的配置信息。
  NPAGED_LOOKASIDE_LIST       StackStretchList;

  HANDLE                      InjectFileHandle[2];
  HANDLE                      DriverFileHandle;
  HANDLE                      Reserve3;

  SIZE_T                      CurrentInjectMemorySize;
  PVOID                       CurrentInjectDllBase;

  PMDL                        InjectDllMdl[2];
  PVOID                       InjectDllMemory[2];
  SIZE_T                      InjectDllMemorySize[2];

  // DelegateStatus起到同步作用，在DelegateStatus != DELEGATE_STATUS_WAIT_TIMER的情况下需要考虑将值置回DELEGATE_STATUS_WAIT_TIMER。
  volatile LONG               DelegateStatus;
  ULONG                       UpdateConfigSuccess;

} GLOBAL_ENVIRONMENT_CORE, *PGLOBAL_ENVIRONMENT_CORE;

static_assert(FIELD_OFFSET(GLOBAL_ENVIRONMENT_CORE, StackStretchList) % 16 == 0, "");

constexpr int SizeOfCallback = sizeof(LR"(\Callback\)") - sizeof(wchar_t);

typedef struct _GLOBAL_ENVIRONMENT_FIXED : _GLOBAL_ENVIRONMENT_CORE {
  UCHAR                       NullString0[(16 - ((FIELD_OFFSET(GLOBAL_ENVIRONMENT_CORE, DelegateStatus) + 8) & 0x0f))];
  UCHAR                       NullString1[(16 - (SizeOfCallback & 0x0f))];
  UCHAR                       CallbackString[SizeOfCallback];
  UCHAR                       ServiceKeyNameBuffer[32];
  UCHAR                       NullString2[4];
  UCHAR                       DriverRegistryPathBuffer[192 * 2];
  UCHAR                       NullString3[16];
  UCHAR                       DriverObjectNameBuffer[192 * 2];
  UCHAR                       NullString4[16];
} GLOBAL_ENVIRONMENT_FIXED, *PGLOBAL_ENVIRONMENT_FIXED;

static_assert(FIELD_OFFSET(GLOBAL_ENVIRONMENT_FIXED, ServiceKeyNameBuffer) % 16 == 0, "");

constexpr int PathBufferMaxLength = (2 * PAGE_SIZE - sizeof(_GLOBAL_ENVIRONMENT_FIXED) - 36) / 3;
typedef struct _GLOBAL_ENVIRONMENT : _GLOBAL_ENVIRONMENT_FIXED {
  UCHAR                       RepairCommandBuffer[PathBufferMaxLength];
  UCHAR                       NullString5[12];
  UCHAR                       DriverFilePathBuffer[PathBufferMaxLength];
  UCHAR                       NullString6[12];
  UCHAR                       DriverRootPathBuffer[PathBufferMaxLength];
  UCHAR                       NullString7[12];
} GLOBAL_ENVIRONMENT, *PGLOBAL_ENVIRONMENT;

static_assert(FIELD_OFFSET(GLOBAL_ENVIRONMENT, CallbackString)
  + FIELD_SIZE(GLOBAL_ENVIRONMENT, CallbackString) == FIELD_OFFSET(GLOBAL_ENVIRONMENT, ServiceKeyNameBuffer),
  R"(Callback object name error!)");

static_assert(PathBufferMaxLength >= 260 * 2, "sizeof(_GLOBAL_ENVIRONMENT::Buffer) must greater than or equal to 260 * 2");

static_assert(sizeof(_GLOBAL_ENVIRONMENT) == 2 * PAGE_SIZE && PAGE_SIZE == 4096, "");

#define DELEGATE_STATUS_WAIT_TIMER  0
#define DELEGATE_STATUS_IN_DELEGATE 1
#define DELEGATE_STATUS_APC_BLOCK1  2
#define DELEGATE_STATUS_APC_BLOCK2  3

constexpr LONGLONG  DEALY_TIME = -(10*1000*1000)*1LL; // 1 second

#endif // !__GLOBAL_ENVIRONMENT_H__
