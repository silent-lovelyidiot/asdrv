#include <Windows.h>

#include "um/NtApi.h"

#include "macro.h"
#include "config.h"
#include "log.h"

#pragma comment(lib, "ntdll.lib")

#include <intrin.h>

PVOID DllSectionInject(HANDLE SectionHandle) {
  PVOID SectionBaseAddress = nullptr;
  SIZE_T ViewSize = 0;

  NTSTATUS st = NtMapViewOfSection(SectionHandle, NtCurrentProcess(),
   &SectionBaseAddress, 0, 0, nullptr, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_WRITECOPY);
  st;
  //Log("%08x, %p", st, SectionBaseAddress);
  return SectionBaseAddress;
}

ULONG SizeOfImageFile(CONST VOID* Data) {
  PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Data;
  if (!Dos || Dos->e_magic != IMAGE_DOS_SIGNATURE) return ~0UL;

  PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((CHAR*)Data + Dos->e_lfanew);

  if (Nt->Signature != IMAGE_NT_SIGNATURE) return ~0UL;

  if (Nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
    PIMAGE_OPTIONAL_HEADER64 Opt = (PIMAGE_OPTIONAL_HEADER64)(&Nt->OptionalHeader);
    return Opt->SizeOfImage;
  } else if (Nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
    PIMAGE_OPTIONAL_HEADER32 Opt = (PIMAGE_OPTIONAL_HEADER32)(&Nt->OptionalHeader);
    return Opt->SizeOfImage;
  }
  return ~0UL;
}

ULONG TimeStampOfImageFile(CONST VOID* Data) {
  PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Data;
  if (!Dos || Dos->e_magic != IMAGE_DOS_SIGNATURE) return ~0UL;

  PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((CHAR*)Data + Dos->e_lfanew);

  if (Nt->Signature != IMAGE_NT_SIGNATURE) return ~0UL;

  return Nt->FileHeader.TimeDateStamp;
}

NTSTATUS CreateInjectDllSection(HANDLE* SectionHandle, PUNICODE_STRING FileName) {
  //UNICODE_STRING FileName = RTL_CONSTANT_STRING(LR"(\??\c:\windows\system32\drivers\drvts.sys:dll)");
  OBJECT_ATTRIBUTES FileAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(FileName, OBJ_CASE_INSENSITIVE);

  IO_STATUS_BLOCK block = {0};
  HANDLE FileHandle = nullptr;
  NTSTATUS st = NtCreateFile(&FileHandle, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE, &FileAttributes,
    &block, nullptr, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ,
    FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

  if (NT_SUCCESS(st)) {
    OBJECT_ATTRIBUTES SectionAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(nullptr, 0);
    char buffer[512];
    DWORD count = 0;
    ReadFile(FileHandle, buffer, 512, &count, nullptr);

    LARGE_INTEGER li = {SizeOfImageFile(buffer), 0};

    st = NtCreateSection(SectionHandle, SECTION_ALL_ACCESS, &SectionAttributes, &li, PAGE_EXECUTE, SEC_IMAGE, FileHandle);
    NtClose(FileHandle);
  }

  //Log("%08x", st);
  return st;
}

EXTERN_C
NTSTATUS
WINAPI
NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
);

#define STATUS_IMAGE_NOT_AT_BASE         ((NTSTATUS)0x40000003L)

NTSTATUS InjectDll(PCUNICODE_STRING FileName, PVOID* SectionBaseAddress, PSIZE_T ViewSize = nullptr) {
  OBJECT_ATTRIBUTES FileAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(FileName, OBJ_CASE_INSENSITIVE);

  IO_STATUS_BLOCK block = {0};
  HANDLE FileHandle = nullptr;
  NTSTATUS st = NtCreateFile(&FileHandle, FILE_READ_DATA | FILE_GENERIC_EXECUTE, &FileAttributes,
    &block, nullptr, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ,
    FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

  if (NT_SUCCESS(st)) {
    OBJECT_ATTRIBUTES SectionAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(nullptr, 0);

    LARGE_INTEGER li = {0, 0};
    HANDLE SectionHandle;
    st = NtCreateSection(&SectionHandle, SECTION_ALL_ACCESS, &SectionAttributes, &li, PAGE_READONLY, SEC_IMAGE, FileHandle);

    if (NT_SUCCESS(st)) {
      SIZE_T tViewSize = 0;
      if (!ViewSize) ViewSize = &tViewSize;
      st = NtMapViewOfSection(SectionHandle, NtCurrentProcess(),
        SectionBaseAddress, 0, 0, nullptr, ViewSize, ViewUnmap, 0, PAGE_WRITECOPY);
      Log("NtMapViewOfSection st %08x %p", st, *SectionBaseAddress);

      NtClose(SectionHandle);
    }

    NtClose(FileHandle);
  }
  return st;
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

PIMAGE_DATA_DIRECTORY GetImageDataDirectoryArray(PVOID BaseAddress, PWORD Machine, PDWORD SizeOfImage) {
  PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)BaseAddress;
  if (!Dos || Dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

  PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((CHAR*)BaseAddress + Dos->e_lfanew);

  if (Nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

  if (Machine) *Machine = Nt->FileHeader.Machine;

  if (Nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
    PIMAGE_OPTIONAL_HEADER64 Opt = (PIMAGE_OPTIONAL_HEADER64)(&Nt->OptionalHeader);
    if (SizeOfImage) *SizeOfImage = Opt->SizeOfImage;
    return Opt->DataDirectory;
  } else if (Nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
    PIMAGE_OPTIONAL_HEADER32 Opt = (PIMAGE_OPTIONAL_HEADER32)(&Nt->OptionalHeader);
    if (SizeOfImage) *SizeOfImage = Opt->SizeOfImage;
    return Opt->DataDirectory;
  }

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

#include <stdio.h>

typedef struct _APC_PARAM {
  PKNORMAL_ROUTINE* RoutineBase;
  const wchar_t*    argv_0;
  const wchar_t*    argv_1;
  const wchar_t*    argv_2;
  const wchar_t*    argv_3;
  const wchar_t*    argv_end;
} APC_PARAM, *PAPC_PARAM;

PVOID FreeMagic = USER_CALLBACK_ROUTINE_UNMAP;
VOID CALLBACK APCTestScriptProc(_In_ ULONG_PTR dwParam) {
  PAPC_PARAM ApcParam = (PAPC_PARAM)dwParam;

  PULONG_PTR v = (PULONG_PTR)ApcParam->RoutineBase;

#ifdef DBG
  constexpr int routine = USER_CALLBACK_ROUTINE_TEST;
#else
  constexpr int routine = USER_CALLBACK_ROUTINE_CONFIG;
#endif // DBG

  char buffer[UPDATE_CONFIG_MAX_SIZE];
  memcpy(buffer, &ApcParam->argv_0, sizeof(const wchar_t*)*(&ApcParam->argv_end - &ApcParam->argv_0));
  auto f = (PKNORMAL_ROUTINE)((ULONG_PTR)ApcParam->RoutineBase - v[USER_CALLBACK_ROUTINE_BASE] + v[routine]);

  PULONG_PTR ra = (PULONG_PTR)_AddressOfReturnAddress();
  Log("f %p, ra %p, ra[0] %p, ra[mix] %p", f, ra, ra[0], ra[0] ^ (ULONG_PTR)(f));

  ra[0] ^= (ULONG_PTR)(f);

  f(ra, buffer, (PVOID)UPDATE_CONFIG_MAX_SIZE);
  f(FreeMagic, nullptr, nullptr);
}

#include <crtdbg.h>

int __cdecl wmain(int argc, wchar_t** argv) {
  argc, argv;
#ifdef DBG
  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
#endif

  UNICODE_STRING File = {
    (USHORT)(wcslen(argv[1]) * 2),
    (USHORT)(wcslen(argv[1]) * 2),
    argv[1]
  };
  PVOID Base1 = nullptr, Base2 = nullptr;
  SIZE_T size1 = 0, size2 = 0;
  NTSTATUS st = InjectDll(&File, &Base1, &size1);
  st = InjectDll(&File, &Base2, &size2);

  NtUnmapViewOfSection(NtCurrentProcess(), Base1);

  Base1 = VirtualAlloc(nullptr, size2,  MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  RtlCopyMemory(Base1, Base2, size2);
  if (GetTickCount() % 100 > 50) {
    NtUnmapViewOfSection(GetCurrentProcess(), Base2);
    Base2 = Base1;
    FreeMagic = USER_CALLBACK_ROUTINE_FREE;
  }
  Log("base %p", Base2);
  PKNORMAL_ROUTINE* m = (PKNORMAL_ROUTINE*)((ULONG_PTR)Base2 + (ULONG_PTR)GetUserApcRoutineInternal<ULONG_PTR>(Base2, nullptr));

  APC_PARAM dwParam = {
    m,
    argv[0],
    argv[2],
    argv[3],
    argv[4],
  };

  QueueUserAPC(APCTestScriptProc, GetCurrentThread(), (ULONG_PTR)&dwParam);

  SleepEx(1000000, TRUE);
  VirtualFree(Base1, 0, MEM_RELEASE);

  Log("asapp test success!");
  return 0;
}


