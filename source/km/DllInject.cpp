#include <ntifs.h>

#include <ntimage.h>

#include "UndocumentedApi.h"

#include "../macro.h"
#include "../constexpr.h"
#include "../log.h"

#include "MmProbeHelper.h"

//#pragma code_seg("PAGE")
VOID NTAPI KernelFreeApcRoutine(__in struct _KAPC *Apc,
  __deref_inout_opt PKNORMAL_ROUTINE *NormalRoutine,
  __deref_inout_opt PVOID *NormalContext,
  __deref_inout_opt PVOID *SystemArgument1,
  __deref_inout_opt PVOID *SystemArgument2
     ) {
  DBG_UNREFERENCED_PARAMETER(NormalRoutine);
  DBG_UNREFERENCED_PARAMETER(NormalContext);
  DBG_UNREFERENCED_PARAMETER(SystemArgument1);
  DBG_UNREFERENCED_PARAMETER(SystemArgument2);

  ExFreePool(Apc);
}

VOID NTAPI RundownClearRoutine(__in struct _KAPC *Apc) {
  ExFreePool(Apc);
  Log("inject dll in rundown 1!");
}


PULONG_PTR GetCurrentThreadUserReturnStack() {
  ULONG_PTR Base, Limit;
  IoGetStackLimits(&Limit, &Base);
  PVOID Initialize = IoGetInitialStack();

  PULONG_PTR Ptr = (PULONG_PTR)Initialize;
#ifdef _M_X64
  ASSERT(Ptr[0] == (ULONG_PTR)Base && (Ptr)[1] == (ULONG_PTR)Limit);
  if (!(Ptr[0] == (ULONG_PTR)Base && (Ptr)[1] == (ULONG_PTR)Limit))
    return nullptr;
  ULONG_PTR Stack = Ptr[-2];
#else
  ULONG_PTR Stack = 0;
  int offset = 0x234 / sizeof(ULONG_PTR);
  offset = -offset;
  if (Ptr[0] == (ULONG_PTR)Base && (Ptr)[1] == (ULONG_PTR)Limit) {
    Stack = Ptr[-6];
  } else if (Ptr[offset] == ((PULONG_PTR)SharedUserData)[0x304 / sizeof(ULONG_PTR)]) {
    Stack = Ptr[offset + 3];
  } else {
    ASSERT(FALSE);
    Log("Get User Return Stack Error!");
    return nullptr;
  }
#endif // _M_X64

  _NT_TIB* UserTebPtr = (_NT_TIB*)PsGetCurrentThreadTeb();
  if (!UserTebPtr) {
    Log("Get User Teb Error!");
    return nullptr;
  }

  if (!MmProbeForReadUser((PVOID)UserTebPtr, sizeof(_NT_TIB), sizeof(ULONG_PTR)))
    return nullptr;

  static_assert(FIELD_OFFSET(_NT_TIB, StackLimit) == sizeof(ULONG_PTR) * 2, "TEB ERROR");
  // limit base
  if ((ULONG_PTR)UserTebPtr->StackLimit <= Stack && Stack < (ULONG_PTR)UserTebPtr->StackBase) {
    return (PULONG_PTR)(Stack);
  }
  Log("Stack %p NOT IN User Stack Range", Stack);
  return nullptr;
}

BOOLEAN GetImageParts(CONST VOID* Base, PIMAGE_NT_HEADERS* NtHeader, PVOID* OptionalHeader,
  PIMAGE_SECTION_HEADER* SectionHeader) {
  PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Base;
  if (!Dos || Dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

  PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((CHAR*)Dos + Dos->e_lfanew);
  if (Nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

  if (NtHeader) *NtHeader = Nt;
  if (OptionalHeader) {
    if (Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
      Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
      return FALSE;
    *OptionalHeader = &Nt->OptionalHeader;
  }
  if (SectionHeader) *SectionHeader = IMAGE_FIRST_SECTION(Nt);

  return TRUE;
}

#define OPT(Opt, Mem)   (PIMAGE_OPTIONAL_HEADER(Opt)->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ?\
                            PIMAGE_OPTIONAL_HEADER64(Opt)->##Mem : PIMAGE_OPTIONAL_HEADER32(Opt)->##Mem)

template<typename T>
ULONG_PTR GetUserApcRoutineInternal(PVOID Base, PULONG OffsetArray) {
  static_assert(sizeof(T) == 4 || sizeof(T) == 8, "ULONG or ULONGLONG");
  PIMAGE_NT_HEADERS Nt;
  PVOID Opt;
  PIMAGE_SECTION_HEADER Section;
  if (!GetImageParts(Base, &Nt, &Opt, &Section)) {
    return 0;
  }

  ULONG Address = OPT(Opt, DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
  ULONG Size = OPT(Opt, DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
  ULONG SizeOfSearch = OPT(Opt, SizeOfImage);

  while (Section->VirtualAddress) {
    if (Section->VirtualAddress == Address) {
      SizeOfSearch = Section->Misc.VirtualSize;
      break;
    }
    Section++;
  }

  if (!SizeOfSearch) return 0;

  T* p = (T*)((CHAR*)Base + Address + Size);
  for (SIZE_T i = 0; i < SizeOfSearch - Size - sizeof(T); i += sizeof(T), p++) {
    if (p[0] - p[1] == (ULONG_PTR)((CHAR*)p - (CHAR*)Base)) {

      if (OffsetArray) {
        for (int j = 0, k = 0; j < USER_CALLBACK_ROUTINE_MAX_VAILD; j++, k++) {
          OffsetArray[j] = (ULONG)((ULONG_PTR)(p[k]) - (ULONG_PTR)Base);
        }
      }

      return (ULONG_PTR)p - (ULONG_PTR)Base;
    }
  }
  return 0;
}

BOOLEAN InsertUserApcToCurrentThread(KKERNEL_ROUTINE KernelApcRoutine,
  PKRUNDOWN_ROUTINE RundownApcRoutine,
  PKNORMAL_ROUTINE UserApcRoutine,
  PVOID NormalContext,
  PVOID SystemArgument1,
  PVOID SystemArgument2) {
  PKAPC apc = (PKAPC)MALLOC(sizeof(KAPC));
  if (!apc) {
    return FALSE;
  }
  Log("UserApcRoutine %p", UserApcRoutine);
  KeInitializeApc(apc,
    PsGetCurrentThread(),
    OriginalApcEnvironment,
    KernelApcRoutine ? KernelApcRoutine : KernelFreeApcRoutine,
    RundownApcRoutine ? RundownApcRoutine : RundownClearRoutine,
    UserApcRoutine,
    UserMode,
    NormalContext);

  BOOLEAN bl = KeInsertQueueApc(apc, SystemArgument1, SystemArgument2, IO_NO_INCREMENT);
  if (!bl) {
    ExFreePool(apc);
  }
  return bl;
}

BOOLEAN CallUserApcRoutineInternal(
  KKERNEL_ROUTINE KernelApcRoutine,
  PKRUNDOWN_ROUTINE RundownApcRoutine,
  PKNORMAL_ROUTINE UserApcRoutine,
  __in_opt PVOID SystemArgument1,
  __in_opt PVOID SystemArgument2) {
  if (!KeAreApcsDisabled()) return FALSE;

  PULONG_PTR ReturnStack = GetCurrentThreadUserReturnStack();
  if (ReturnStack && !MmProbeForWriteUser((PVOID)ReturnStack, sizeof(ULONG_PTR), sizeof(ULONG_PTR)))
    return FALSE;

#ifdef _M_X64
  PKNORMAL_ROUTINE UserCallFunctionRaw = UserApcRoutine;
  Log("UserCallFunction x86 %p", UserApcRoutine);
  NTSTATUS st = PsWrapApcWow64Thread(nullptr, (PVOID*)&UserApcRoutine);
  st;
#endif // _M_X64

  BOOLEAN bl = InsertUserApcToCurrentThread(KernelApcRoutine,
    RundownApcRoutine,
    UserApcRoutine,
    ReturnStack,
    SystemArgument1,
    SystemArgument2);

  if (bl) {
    BOOLEAN OldState = KeTestAlertThread(UserMode);
    if (OldState) {
      KeTestAlertThread(UserMode);
    }

    if (ReturnStack) {
#ifdef _M_X64
      *ReturnStack ^= (ULONG_PTR)UserCallFunctionRaw;
#elif _M_IX86
      *ReturnStack ^= (ULONG_PTR)UserApcRoutine;
#endif // _M_X64
    }
  }

  return bl;
}

template<typename T>
PKNORMAL_ROUTINE UserApcRoutineAddress(PVOID Base, ULONG_PTR Routine) {
  ULONG_PTR UserApcRoutineOffset = GetUserApcRoutineInternal<T>(Base, nullptr);
  if (!UserApcRoutineOffset) return nullptr;

  UserApcRoutineOffset += (ULONG_PTR)Base;

  T RealUserApcRoutineOffset = T(UserApcRoutineOffset
    - ((T*)UserApcRoutineOffset)[USER_CALLBACK_ROUTINE_BASE]
    + ((T*)UserApcRoutineOffset)[Routine]);
  return (PKNORMAL_ROUTINE)RealUserApcRoutineOffset;
}

BOOLEAN CallUserApcRoutine(PVOID Base,
  KKERNEL_ROUTINE KernelApcRoutine,
  KRUNDOWN_ROUTINE RundownApcRoutine,
  ULONG Routine,
  __in_opt PVOID SystemArgument1,
  __in_opt PVOID SystemArgument2) {
  if (Routine >= USER_CALLBACK_ROUTINE_MAX_VAILD) return FALSE;
  Log("Base %p", Base);
  BOOLEAN bl = FALSE;
#ifdef _M_X64
  BOOLEAN IsWow64Process = PsGetProcessWow64Process(PsGetCurrentProcess()) != nullptr;
  if (IsWow64Process) {
#endif // _M_X64

    auto UserApcRoutineOffset32 = UserApcRoutineAddress<ULONG>(Base, Routine);
    if (!UserApcRoutineOffset32) goto error;

    bl = CallUserApcRoutineInternal(KernelApcRoutine,
      RundownApcRoutine,
      UserApcRoutineOffset32,
      SystemArgument1,
      SystemArgument2);

#ifdef _M_X64
  } else {
    auto UserApcRoutineOffset64 = UserApcRoutineAddress<ULONGLONG>(Base, Routine);
    if (!UserApcRoutineOffset64) goto error;

    bl = CallUserApcRoutineInternal(KernelApcRoutine,
      RundownApcRoutine,
      UserApcRoutineOffset64,
      SystemArgument1,
      SystemArgument2);
  }
#endif // _M_X64
error:
  return bl;
}


#define SEC_IMAGE         0x1000000  

PVOID InjectDll(HANDLE RootDirectory, PCUNICODE_STRING FileName) {
  PVOID SectionBaseAddress = nullptr;

  OBJECT_ATTRIBUTES FileAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);
  FileAttributes.RootDirectory = RootDirectory;

  IO_STATUS_BLOCK block = {0};
  HANDLE FileHandle = nullptr;
  NTSTATUS st = ZwCreateFile(&FileHandle, FILE_READ_DATA | FILE_GENERIC_EXECUTE, &FileAttributes,
    &block, nullptr, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ,
    FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

  if (NT_SUCCESS(st)) {
    OBJECT_ATTRIBUTES SectionAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(nullptr, OBJ_KERNEL_HANDLE);

    LARGE_INTEGER li = {0, 0};
    HANDLE SectionHandle;
    st = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, &SectionAttributes, &li, PAGE_READONLY, SEC_IMAGE, FileHandle);

    if (NT_SUCCESS(st)) {
      SIZE_T ViewSize = 0;

      st = ZwMapViewOfSection(SectionHandle, ZwCurrentProcess(),
       &SectionBaseAddress, 0, 0, nullptr, &ViewSize, ViewUnmap, 0, PAGE_WRITECOPY);
      ZwClose(SectionHandle);
    }
#ifdef DBG
    else {
      Log("ZwCreateSection Failed %08x", st);
    }
#endif // DBG

    ZwClose(FileHandle);
  }
#ifdef DBG
  else {
    Log("ZwCreateFile Failed %08x", st);
  }
#endif // DBG

  return SectionBaseAddress;
}

HANDLE CreateInjectDllHandle(HANDLE RootDirectory, PCUNICODE_STRING FileName) {
  HANDLE SectionHandle = nullptr;

  OBJECT_ATTRIBUTES FileAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);
  FileAttributes.RootDirectory = RootDirectory;

  IO_STATUS_BLOCK block = {0};
  HANDLE FileHandle = nullptr;
  NTSTATUS st = ZwCreateFile(&FileHandle, FILE_READ_DATA | FILE_GENERIC_EXECUTE, &FileAttributes,
    &block, nullptr, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ,
    FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

  if (NT_SUCCESS(st)) {
    OBJECT_ATTRIBUTES SectionAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(nullptr, OBJ_KERNEL_HANDLE);

    LARGE_INTEGER li = {0, 0};
    st = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, &SectionAttributes, &li, PAGE_READONLY, SEC_IMAGE, FileHandle);

    ZwClose(FileHandle);
  }
  return SectionHandle;
}

HANDLE CreateInjectDllHandle(HANDLE FileHandle, PLARGE_INTEGER li) {
  if (!FileHandle) return nullptr;
  HANDLE SectionHandle = nullptr;
  OBJECT_ATTRIBUTES SectionAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(nullptr, OBJ_KERNEL_HANDLE);

  LARGE_INTEGER tmp = {0, 0};
  if (!li) li = &tmp;
  NTSTATUS st = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, &SectionAttributes, li, PAGE_READONLY, SEC_IMAGE, FileHandle);
  st;
#ifdef DBG
  Log("ZwCreateSection Result %08x", st);
#endif // DBG
  return SectionHandle;
}

PVOID MapInjectDll(HANDLE Process, HANDLE SectionHandle, PSIZE_T ViewSize) {
  if (!SectionHandle) return nullptr;
  PVOID SectionBaseAddress = nullptr;
  SIZE_T tViewSize = 0;
  if (!ViewSize) ViewSize = &tViewSize;
  NTSTATUS st = ZwMapViewOfSection(SectionHandle, Process,
    &SectionBaseAddress, 0, 0, nullptr, ViewSize, ViewUnmap, 0, PAGE_WRITECOPY);
  st;
#ifdef DBG
  Log("ZwMapViewOfSection Result %08x, %p", st, SectionBaseAddress);
#endif // DBG
  return SectionBaseAddress;
}
