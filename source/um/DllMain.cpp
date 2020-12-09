#include <Windows.h>
#include <intrin.h>

#include "log.h"
#include "macro.h"

#include "UnmapViewOfSection.h"

#include <crtdbg.h>

#include "ImageHelper.h"

EXTERN_C {
  extern PKNORMAL_ROUTINE const CallbackRoutine[];
  extern IMAGE_DOS_HEADER __ImageBase;

  BOOL WINAPI _DllMainCRTStartup(
    HINSTANCE const instance,
    DWORD     const reason,
    LPVOID    const reserved
  );
}

__declspec(noinline) PVOID ImageBaseInMemory() {
  PVOID Base = FoundImageBaseAddress(_ReturnAddress(), nullptr);
  return Base;
}

__declspec(noinline) PVOID ImageBaseInFile(PIMAGE_HELPER_CONTEXT Context) {
 return GetImageBaseAddressDefault(Context);
}

__declspec(noinline) PVOID ImageBaseInPe() {
  PVOID ImageBase = ImageBaseInMemory();
  auto Context = InitializeImageHelperContext(ImageBase);
  if (!Context) return nullptr;
  return ImageBaseInFile(Context);
}

__declspec(noinline) void RestoreUserStack(PVOID Ptr, ULONG_PTR Routine) {
  if (!Ptr) return;
  PVOID ImageBase = ImageBaseInMemory();
  PVOID PeBase = ImageBaseInPe();

  PULONG_PTR Stack = (PULONG_PTR)Ptr;

  if (ImageBase == PeBase) {
    *Stack ^= (ULONG_PTR)CallbackRoutine[Routine];
  } else {
    PULONG_PTR RealCallback = RVA_DECODE(PULONG_PTR, ImageBase, ((ULONG_PTR)&CallbackRoutine - (ULONG_PTR)&__ImageBase));
    ULONG_PTR RealRoutine = RVA_DECODE(ULONG_PTR, ImageBase, RealCallback[Routine] - (ULONG_PTR)PeBase);
    *Stack ^= RealRoutine;
  }
}

DEF_IMPORT_DESC(KERNEL32);
DEF_IMPORT_DESC(ntdll);

PVOID GetNtdllImageBaseAddressFromAPC(PVOID RetuanAddressFromKernelApc, PVOID AddressOfRetuanStack) {
  PVOID ImageBaseMemory = ImageBaseInMemory();
  PIMAGE_HELPER_CONTEXT Context = InitializeImageHelperContext(ImageBaseMemory);
  if (!Context) return FALSE;
  PVOID ImageBaseDefault = ImageBaseInFile(Context);

  PVOID Ntdll = nullptr;
  {

    ULONG NameAddress = 0;
    if (ImageBaseMemory != ImageBaseDefault) {
      NameAddress = *RVA_DECODE(PULONG, ImageBaseMemory, (ULONG_PTR)&IMPORT_DESC(ntdll).Name - (ULONG_PTR)&__ImageBase);
    } else {
      NameAddress = IMPORT_DESC(ntdll).Name;
    }

    CONST CHAR* ntdll = RVA_DECODE(CONST CHAR*, ImageBaseMemory, NameAddress);

    Ntdll = FoundImageBaseAddress(RetuanAddressFromKernelApc, ntdll);
    if (!Ntdll && AddressOfRetuanStack) {
      // for asapp

      Ntdll = FoundImageBaseAddress(
        (void*)*(PULONG_PTR)AddressOfRetuanStack,
        ntdll);
    }
  }
  return Ntdll;
}

PVOID Initialized = nullptr;
PIMAGE_HELPER_CONTEXT CurrentContext = nullptr;
// MUST NOT CONTAIN "GS Buffers"
// https://msdn.microsoft.com/en-us/library/8dbf701c(v=vs.100).aspx
__declspec(safebuffers) BOOLEAN Initialize(
  __in PVOID RetuanAddressFromKernelApc,/*__in_opt PVOID ProcessSectionBaseAddress*/
  __in PVOID ReturnStack,
  __in ULONG_PTR) {
  PVOID ImageBaseMemory = ImageBaseInMemory();
  PIMAGE_HELPER_CONTEXT Context = InitializeImageHelperContext(ImageBaseMemory);
  if (!Context) return FALSE;
  PVOID ImageBaseDefault = ImageBaseInFile(Context);

  if (*(int*)((CHAR*)ImageBaseMemory + ((CHAR*)&Initialized - (CHAR*)&__ImageBase))) return TRUE;

  PVOID Kernel32 = nullptr;
  ULONG_PTR Diff = (CHAR*)ImageBaseMemory - (CHAR*)ImageBaseDefault;

  PVOID Ntdll = GetNtdllImageBaseAddressFromAPC(RetuanAddressFromKernelApc, ReturnStack);
  if (!Ntdll) return FALSE;

  if (Diff) {
    if (!RelocationImageRelocEntry(Context,
      Ntdll,
      Diff)) return FALSE;
  }

  {
    CONST CHAR* KERNEL32 = RVA_DECODE(CONST CHAR*, ImageBaseMemory, IMPORT_DESC(KERNEL32).Name);

    Kernel32 = GetImageBaseAddressFromPeb(Context, Ntdll, KERNEL32);
    if (!Kernel32) return FALSE;
  }

  RelocationImageImportEntry(Context, Kernel32, FALSE);
  ApplyInjectDllSEH(Context, Ntdll);

  InitializeDataSection(Context);
  _DllMainCRTStartup((HINSTANCE)GetImageBaseAddress(Context), DLL_PROCESS_ATTACH, nullptr);
  CurrentContext = Context;
  Initialized = Ntdll;
  return TRUE;
}

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

EXTERN_C
NTSTATUS
WINAPI
NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_When_(return==0, __drv_freesMem(Region))
EXTERN_C
NTSTATUS
NTAPI
NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
    );

DEF_IMPORT_PROC(NtUnmapViewOfSection);
DEF_IMPORT_PROC(NtFreeVirtualMemory);

VOID Uninitialize(PVOID Unload, LPVOID AddressOfRetuanAddressApc, PVOID ReturnStackAddress) {
  PVOID ImageBaseAddress = ImageBaseInMemory();
  ULONG_PTR Init = *(ULONG_PTR*)((CHAR*)ImageBaseAddress + ((CHAR*)&Initialized - (CHAR*)&__ImageBase));
  if (Init) {
    auto Context = InitializeImageHelperContext(ImageBaseAddress);
    if (!Context) return;

    _DllMainCRTStartup((HINSTANCE)&__ImageBase, DLL_PROCESS_DETACH, nullptr);

    CancelInjectDllSEH(Context, Initialized);
    Log("Last Log Record!");
    FreeLibraryImportEntry(Context);
    CurrentContext = nullptr;
    Initialized = nullptr;
  }


  if (Unload == USER_CALLBACK_ROUTINE_UNMAP) {
    PVOID UnmapViewOfSection = NtUnmapViewOfSection;
    if (!Init) {
      PVOID Ntdll = GetNtdllImageBaseAddressFromAPC((PVOID)(*(PULONG_PTR)AddressOfRetuanAddressApc), ReturnStackAddress);
      if (!Ntdll) return;
      auto NtdllContext = InitializeImageHelperContext(Ntdll);
      if (!NtdllContext) return;
      PULONG_PTR Address = RVA_DECODE(PULONG_PTR, ImageBaseAddress,
        (ULONG_PTR)&IMPORT_PROC(NtUnmapViewOfSection) - (ULONG_PTR)&__ImageBase);
      CONST CHAR* Name = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, ImageBaseAddress, *Address)->Name;
      UnmapViewOfSection = GetProcAddressMine(NtdllContext, Name);
      if (!UnmapViewOfSection) return;
    }
    UnmapViewOfSectionFromApc(ImageBaseAddress, AddressOfRetuanAddressApc, UnmapViewOfSection);
  } else if (Unload == USER_CALLBACK_ROUTINE_FREE) {
    PVOID FreeVirtualMemory = NtFreeVirtualMemory;
    if (!Init) {
      PVOID Ntdll = GetNtdllImageBaseAddressFromAPC((PVOID)(*(PULONG_PTR)AddressOfRetuanAddressApc), ReturnStackAddress);
      if (!Ntdll) return;
      auto NtdllContext = InitializeImageHelperContext(Ntdll);
      if (!NtdllContext) return;
      PULONG_PTR Address = RVA_DECODE(PULONG_PTR, ImageBaseAddress,
        (ULONG_PTR)&IMPORT_PROC(NtFreeVirtualMemory) - (ULONG_PTR)&__ImageBase);
      CONST CHAR* Name = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, ImageBaseAddress, *Address)->Name;
      FreeVirtualMemory = GetProcAddressMine(NtdllContext, Name);
      if (!FreeVirtualMemory) return;
    }
    FreeVirtualMemoryFromApc(ImageBaseAddress, AddressOfRetuanAddressApc, FreeVirtualMemory);
  }
}

VOID WINAPI UpdateConfig(
  __in_opt PVOID BaseAddress,
  __in_opt PVOID Size,
  __in_opt PVOID ) {
  Log("BaseAddress %p, %d", BaseAddress, (ULONG_PTR)Size);
  __try {
    extern ULONG UpdateConfigInternal(LPVOID BaseAddress, ULONG Size);
    UpdateConfigInternal(BaseAddress, (ULONG)(ULONG_PTR)Size);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Log("UpdateConfig error");
    _ASSERT(0);
  }
}

VOID WINAPI SELF(
  __in_opt PVOID,
  __in_opt PVOID,
  __in_opt PVOID ) {

}

template<PKNORMAL_ROUTINE F, PVOID P, ULONG_PTR N>
VOID WINAPI CallbackRoutineComm(
  __in_opt PVOID ReturnStackOrUnloadMethod,
  __in_opt PVOID SystemArgument1,
  __in_opt PVOID SystemArgument2) {
  if (ReturnStackOrUnloadMethod != USER_CALLBACK_ROUTINE_UNMAP
    && ReturnStackOrUnloadMethod != USER_CALLBACK_ROUTINE_FREE) {
    RestoreUserStack(ReturnStackOrUnloadMethod, N);
    if (Initialize(_ReturnAddress(), ReturnStackOrUnloadMethod, N)) {
      ApplyInjectDllSEH(CurrentContext, Initialized);
      F(SystemArgument1, SystemArgument2, P);
      CancelInjectDllSEH(CurrentContext, Initialized);
    }
  } else {
    Uninitialize(ReturnStackOrUnloadMethod, _AddressOfReturnAddress(), SystemArgument1);
  }
}

#ifdef DBG
VOID WINAPI TestScript(
  __in_opt PVOID BaseAddress,
  __in_opt PVOID Size,
  __in_opt PVOID ) {
  Log("BaseAddress %p, %d", BaseAddress, (ULONG_PTR)Size);
  __try {
    extern ULONG TestScriptInternal(LPVOID BaseAddress, ULONG Size);
    TestScriptInternal(BaseAddress, (ULONG)(ULONG_PTR)Size);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    Log("TestScriptInternal error");
  }
}
#endif // DBG

#pragma const_seg()
EXTERN_C PKNORMAL_ROUTINE const CallbackRoutine[USER_CALLBACK_ROUTINE_MAX_VAILD] = {
  (PKNORMAL_ROUTINE)&CallbackRoutine,
  (PKNORMAL_ROUTINE)&__ImageBase,

  CallbackRoutineComm<UpdateConfig, nullptr, USER_CALLBACK_ROUTINE_CONFIG>,
#ifdef DBG
  CallbackRoutineComm<TestScript, nullptr, USER_CALLBACK_ROUTINE_TEST>,
#else
  nullptr,
#endif // DBG
  CallbackRoutineComm<SELF, nullptr, USER_CALLBACK_ROUTINE_SELF>,
  nullptr,
  (PKNORMAL_ROUTINE)&__ImageBase,
};