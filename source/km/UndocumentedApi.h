#ifndef __UNDOCUMENTED_API_H__
#define __UNDOCUMENTED_API_H__

extern "C" {

POBJECT_TYPE NTAPI ObGetObjectType(_In_ PVOID Object);

PCSTR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

//NTSTATUS NTAPI ZwQueryInformationProcess(
//  _In_      HANDLE           ProcessHandle,
//  _In_      PROCESSINFOCLASS ProcessInformationClass,
//  _Out_     PVOID            ProcessInformation,
//  _In_      ULONG            ProcessInformationLength,
//  _Out_opt_ PULONG           ReturnLength
//);

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
__drv_functionClass(KNORMAL_ROUTINE)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
VOID
NTAPI
KNORMAL_ROUTINE (
    __in_opt PVOID NormalContext,
    __in_opt PVOID SystemArgument1,
    __in_opt PVOID SystemArgument2
    );
typedef KNORMAL_ROUTINE *PKNORMAL_ROUTINE;

typedef
__drv_functionClass(KKERNEL_ROUTINE)
__drv_maxIRQL(APC_LEVEL)
__drv_minIRQL(APC_LEVEL)
__drv_requiresIRQL(APC_LEVEL)
__drv_sameIRQL
VOID
NTAPI
KKERNEL_ROUTINE (__in struct _KAPC *Apc,
		 __deref_inout_opt PKNORMAL_ROUTINE *NormalRoutine,
		 __deref_inout_opt PVOID *NormalContext,
		 __deref_inout_opt PVOID *SystemArgument1,
		 __deref_inout_opt PVOID *SystemArgument2
		 );
typedef KKERNEL_ROUTINE *PKKERNEL_ROUTINE;

typedef
__drv_functionClass(KRUNDOWN_ROUTINE)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
VOID
NTAPI
KRUNDOWN_ROUTINE (__in struct _KAPC *Apc
		  );
typedef KRUNDOWN_ROUTINE *PKRUNDOWN_ROUTINE;

VOID NTAPI KeInitializeApc (
		 __out PRKAPC Apc,
		 __in PRKTHREAD Thread,
		 __in KAPC_ENVIRONMENT Environment,
		 __in PKKERNEL_ROUTINE KernelRoutine,
		 __in_opt PKRUNDOWN_ROUTINE RundownRoutine,
		 __in_opt PKNORMAL_ROUTINE NormalRoutine,
		 __in_opt KPROCESSOR_MODE ProcessorMode,
		 __in_opt PVOID NormalContext
		 );

BOOLEAN
NTAPI
KeInsertQueueApc (__inout PRKAPC Apc,
		  __in_opt PVOID SystemArgument1,
		  __in_opt PVOID SystemArgument2,
		  __in KPRIORITY Increment
		  );

BOOLEAN NTAPI KeTestAlertThread(KPROCESSOR_MODE Mode);

BOOLEAN NTAPI KeAlertThread(PKTHREAD Thread, KPROCESSOR_MODE AlertMode);

PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);

NTSTATUS NTAPI ZwQueryInformationProcess(
  _In_      HANDLE           ProcessHandle,
  _In_      PROCESSINFOCLASS ProcessInformationClass,
  _Out_     PVOID            ProcessInformation,
  _In_      ULONG            ProcessInformationLength,
  _Out_opt_ PULONG           ReturnLength
);

NTSTATUS NTAPI NtQueryInformationProcess(
  _In_      HANDLE           ProcessHandle,
  _In_      PROCESSINFOCLASS ProcessInformationClass,
  _Out_     PVOID            ProcessInformation,
  _In_      ULONG            ProcessInformationLength,
  _Out_opt_ PULONG           ReturnLength
);

#if (NTDDI_VERSION >= NTDDI_WIN2K)
_Must_inspect_result_
_Post_satisfies_(*ViewSize >= _Old_(*ViewSize))
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Outptr_result_bytebuffer_(*ViewSize) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
    );
#endif

NTSTATUS NTAPI ZwProtectVirtualMemory(
     __in HANDLE ProcessHandle,
     __inout PVOID *BaseAddress,
     __inout PSIZE_T RegionSize,
     __in ULONG NewProtectWin32,
     __out PULONG OldProtect
);


typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation,
    SectionImageInformation,
    SectionRelocationInformation, // name:wow64:whNtQuerySection_SectionRelocationInformation
    MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

NTSTATUS NTAPI ZwQuerySection(
    _In_ HANDLE SectionHandle,
    _In_ SECTION_INFORMATION_CLASS SectionInformationClass,
    _Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation,
    _In_ SIZE_T SectionInformationLength,
    _Out_opt_ PSIZE_T ReturnLength);

struct _PEB* NTAPI PsGetProcessPeb(PEPROCESS Process);

typedef struct WOW64_PROCESS *PWOW64_PROCESS;
PWOW64_PROCESS NTAPI PsGetProcessWow64Process(PEPROCESS Process);

int _cdecl _wtoi(const wchar_t *str);
int _cdecl swscanf_s(const wchar_t *Src, const wchar_t *Format, ...);
}

#endif // __UNDOCUMENTED_API_H__
