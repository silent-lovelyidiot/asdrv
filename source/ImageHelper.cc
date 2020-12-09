#include <minwindef.h>
#include <intrin.h>

#include <crtdbg.h>

#include "ImageHelper.h"

#include "ImageHelperDefinition.h"

DEF_IMPORT_PROC(NtProtectVirtualMemory);
DEF_IMPORT_PROC(LdrProcessRelocationBlock);

DEF_IMPORT_PROC(RtlGetCurrentPeb);
DEF_IMPORT_PROC(RtlAcquirePebLock);
DEF_IMPORT_PROC(RtlReleasePebLock);

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

typedef struct _IMAGE_HELPER_CONTEXT : IMAGE_OPTIONAL_HEADER {
} IMAGE_HELPER_CONTEXT, *PIMAGE_HELPER_CONTEXT;

// 字符串比较函数
inline int CmpString(PCSTR Str1, PCSTR Str2) {
  PCSTR Ch1 = Str1, Ch2 = Str2;
  int r = *Ch1 - *Ch2;

  while (r == 0 && *Ch1 && *Ch2) {
    Ch1++, Ch2++;
    r = *Ch1 - *Ch2;
  }

  return r;
}

inline BOOLEAN StringEqual(PCSTR Str1, PCSTR Str2, BOOLEAN CaseSensitive) {
  CHAR Case = ~(CaseSensitive ? 0 : 'A' ^ 'a');
  PCSTR Ch1 = Str1, Ch2 = Str2;
  for (; *Ch1 && *Ch2; Ch1++, Ch2++) {
    CHAR Value = (*Ch1 ^ *Ch2) & Case;
    if (Value) return FALSE;
  }

  return ((*Ch1) | (*Ch2)) == 0;
}

// 内部函数
PCSTR GetImageInternalNameInternal(PIMAGE_HELPER_CONTEXT Context) {
  CONST IMAGE_DATA_DIRECTORY* DataDirectory =
    &Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!DataDirectory->Size) return nullptr;

  auto ImageBaseAddress = GetImageBaseAddress(Context);

  PIMAGE_EXPORT_DIRECTORY ExportDirectory = RVA_DECODE(PIMAGE_EXPORT_DIRECTORY,
    ImageBaseAddress, DataDirectory->VirtualAddress);

  return RVA_DECODE(PCSTR, ImageBaseAddress, ExportDirectory->Name);
}

PVOID GetDllBaseAddressFromImportEntryInternal(PIMAGE_HELPER_CONTEXT Context, PCSTR DllName) {
  auto ImageBaseAddress = GetImageBaseAddress(Context);

  CONST IMAGE_DATA_DIRECTORY* DataDirectory =
    &Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!DataDirectory->Size) return nullptr;

  PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = RVA_DECODE(PIMAGE_IMPORT_DESCRIPTOR,
    ImageBaseAddress, DataDirectory->VirtualAddress);

  for(PIMAGE_IMPORT_DESCRIPTOR Desc = ImportDescriptor; Desc->Characteristics; Desc++) {
    if (StringEqual(DllName, RVA_DECODE(CHAR*, ImageBaseAddress, Desc->Name), FALSE)) {

      auto Thunk = RVA_DECODE(PIMAGE_THUNK_DATA, ImageBaseAddress, Desc->FirstThunk);
      PVOID BaseAddress = FoundImageBaseAddress((PVOID)Thunk->u1.Function, DllName);
      if (BaseAddress) return BaseAddress;
      break;
    }
  }

  for (PIMAGE_IMPORT_DESCRIPTOR Desc = ImportDescriptor; Desc->Characteristics; Desc++) {
    PVOID Address = nullptr;
    auto Thunk = RVA_DECODE(PIMAGE_THUNK_DATA, ImageBaseAddress, Desc->FirstThunk);
    auto BaseAddress = FoundImageBaseAddress((PVOID)Thunk->u1.Function, nullptr);
    PIMAGE_HELPER_CONTEXT DllContext = nullptr;
    if (BaseAddress && (DllContext = InitializeImageHelperContext(BaseAddress)) != nullptr)
      Address = GetDllBaseAddressFromImportEntryInternal(DllContext, DllName);
    if (Address) return Address;
  }

  return nullptr;
}

PVOID GetProcAddressForwarderInternal(PIMAGE_HELPER_CONTEXT Context, PCSTR ForwarderString);

PVOID GetProcAddressMineInternal(PIMAGE_HELPER_CONTEXT Context,
  PCSTR ProcName) {
  CONST IMAGE_DATA_DIRECTORY* DataDirectory =
    &Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!DataDirectory->Size) return nullptr;

  auto ImageBaseAddress = GetImageBaseAddress(Context);

  PIMAGE_EXPORT_DIRECTORY ExportDirectory = RVA_DECODE(PIMAGE_EXPORT_DIRECTORY,
    ImageBaseAddress, DataDirectory->VirtualAddress);

  PDWORD Names = RVA_DECODE(PDWORD, ImageBaseAddress, ExportDirectory->AddressOfNames);
  PDWORD Functions = RVA_DECODE(PDWORD, ImageBaseAddress, ExportDirectory->AddressOfFunctions);
  PUSHORT Numbers = RVA_DECODE(PUSHORT, ImageBaseAddress, ExportDirectory->AddressOfNameOrdinals);

  ULONG_PTR ProcId = (ULONG_PTR)ProcName;
  if (ProcId <= 64 * 1024 && ProcId) {
    ULONG_PTR r = RVA_DECODE(ULONG_PTR, ImageBaseAddress, Functions[Numbers[ProcId - ExportDirectory->Base]]);
    return PVOID(r);
  } else {
    int index_low = 0, index_high = ExportDirectory->NumberOfNames;

    while (index_low < index_high) {
      int index = (index_low + index_high) / 2;

      PCSTR name = RVA_DECODE(PCSTR, ImageBaseAddress, Names[index]);
      int r = CmpString(ProcName, name);
      if (r == 0) {
        ULONG_PTR ProcAddress = RVA_DECODE(ULONG_PTR, ImageBaseAddress, Functions[Numbers[index]]);
        if (ProcAddress < (ULONG_PTR)(ExportDirectory) ||
          ProcAddress >= (ULONG_PTR)((CHAR*)ExportDirectory + DataDirectory->Size)) {
          return PVOID(ProcAddress);
        }

        return GetProcAddressForwarderInternal(Context, (PCSTR)ProcAddress);
      }

      if (r > 0 && index_low < index) {
        index_low = index;
      } else if (r < 0 && index < index_high) {
        index_high = index;
      } else {
        break;
      }
    }
  }
  return nullptr;
}

PVOID GetProcAddressForwarderInternal(PIMAGE_HELPER_CONTEXT Context, PCSTR ForwarderString) {
  // 可能溢出
  CHAR Name[320];
  CONST CHAR *s = ForwarderString;
  CHAR *n = Name;
  for (; *s; s++, n++) {
    if (*s == '.') {
      *n++ = *s++;
      n[0] = 'd';
      n[1] = 'l';
      n[2] = 'l';
      n[3] = '\0';
      break;
    }
    *n = *s;
  }
  auto Base = GetDllBaseAddressFromImportEntryInternal(Context, Name);
  if (!Base) return nullptr;

  PIMAGE_HELPER_CONTEXT DllContext = InitializeImageHelperContext(Base);
  if (!DllContext) return nullptr;

  for (n = Name;; s++, n++) {
    *n = *s;
    if (!*s) break;
  }

  return GetProcAddressMineInternal(DllContext, Name);
}

template<typename T>
T* GetProcAddressMine(PIMAGE_HELPER_CONTEXT Context, PVOID ImageBaseAddressWithProc, T* Offset) {
  auto ImageProcContext = InitializeImageHelperContext(ImageBaseAddressWithProc);
  if (!ImageProcContext) return nullptr;

  auto ImageBaseAddress = GetImageBaseAddress(Context);

  PULONG_PTR Address = RVA_DECODE(PULONG_PTR, ImageBaseAddress,
    (ULONG_PTR)Offset - (ULONG_PTR)&__ImageBase);
  CONST CHAR* Name = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, ImageBaseAddress, *Address)->Name;

  return (T*)GetProcAddressMine(ImageProcContext, Name);
}

BOOLEAN RelocationImageRelocEntryInternal(PIMAGE_HELPER_CONTEXT Context,
  decltype(LdrProcessRelocationBlock)* pLdrProcessRelocationBlock,
  decltype(NtProtectVirtualMemory)* pNtProtectVirtualMemory,
  ULONG_PTR Diff) {

  auto ImageBaseAddress = GetImageBaseAddress(Context);

  const IMAGE_DATA_DIRECTORY* Directory = &Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (!Directory->Size) return FALSE;

  PIMAGE_BASE_RELOCATION BaseReloc = RVA_DECODE(PIMAGE_BASE_RELOCATION,
    ImageBaseAddress, Directory->VirtualAddress);

  while (BaseReloc && BaseReloc->VirtualAddress) {
    ULONG old = 0;
    if (pNtProtectVirtualMemory) {
      PVOID BaseAddress = RVA_DECODE(PVOID, ImageBaseAddress,
        BaseReloc->VirtualAddress);
      SIZE_T Size = BaseReloc->SizeOfBlock;
      if (pNtProtectVirtualMemory((HANDLE)-1, &BaseAddress, &Size, PAGE_EXECUTE_WRITECOPY, &old))
        pNtProtectVirtualMemory((HANDLE)-1, &BaseAddress, &Size, PAGE_EXECUTE_READWRITE, &old);
    }
    BaseReloc = pLdrProcessRelocationBlock(RVA_DECODE(ULONG_PTR, ImageBaseAddress, BaseReloc->VirtualAddress),
      (BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT),
      (PUSHORT)(BaseReloc + 1), Diff);

    if (pNtProtectVirtualMemory && old != PAGE_NOACCESS) {
      PVOID BaseAddress = RVA_DECODE(PVOID, ImageBaseAddress,
        BaseReloc->VirtualAddress);
      SIZE_T Size = BaseReloc->SizeOfBlock;
      pNtProtectVirtualMemory((HANDLE)-1, &BaseAddress, &Size, old, &old);
    }
  }
  return TRUE;
}

// 公开函数
PIMAGE_HELPER_CONTEXT InitializeImageHelperContext(PVOID ImageBaseAddress) {
  if (!ImageBaseAddress) return nullptr;

  auto ImageDosHeader = (PIMAGE_DOS_HEADER)ImageBaseAddress;
  if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return nullptr;

  auto ImageNtHeaders = (PIMAGE_NT_HEADERS)((CHAR*)ImageDosHeader + ImageDosHeader->e_lfanew);
  if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    return nullptr;

  if (ImageNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    return nullptr;

  return (PIMAGE_HELPER_CONTEXT)&ImageNtHeaders->OptionalHeader;
}

PVOID GetImageBaseAddressDefault(PIMAGE_HELPER_CONTEXT Context) {
  return (PVOID)Context->ImageBase;
}

PVOID GetImageBaseAddress(PIMAGE_HELPER_CONTEXT Context) {
  return (PVOID)((ULONG_PTR)Context & (ULONG_PTR)~65535);
}

PVOID FoundImageBaseAddress(PVOID AddressInImage, PCSTR DllName) {
  ULONG_PTR Base = (ULONG_PTR)AddressInImage & (ULONG_PTR)~65535;
  while (*(WORD*)Base != IMAGE_DOS_SIGNATURE) {
    Base -= 64 * 1024;
  }

  auto Context = InitializeImageHelperContext((PVOID)Base);
  if (!Context) return nullptr;
  if (!DllName) return (PVOID)Base;

  auto InternalName = GetImageInternalNameInternal(Context);
  if (InternalName && StringEqual(InternalName, DllName, FALSE))
    return (PVOID)Base;

  return nullptr;
}

PCSTR GetImageInternalName(PIMAGE_HELPER_CONTEXT Context) {
  return GetImageInternalNameInternal(Context);
}

PVOID GetProcAddressMine(PIMAGE_HELPER_CONTEXT Context, PCSTR ProcName) {
  return GetProcAddressMineInternal(Context, ProcName);
}

BOOLEAN RelocationImageRelocEntry(PIMAGE_HELPER_CONTEXT Context,
  PVOID Ntdll,
  ULONG_PTR Diff
  ) {
  if (Diff == 0) return TRUE;

  auto pLdrProcessRelocationBlock = GetProcAddressMine(Context, Ntdll, &IMPORT_PROC(LdrProcessRelocationBlock));
  if (!pLdrProcessRelocationBlock) return FALSE;

  auto pNtProtectVirtualMemory = (decltype(NtProtectVirtualMemory)*)GetProcAddressMine(
    Context, Ntdll, &IMPORT_PROC(NtProtectVirtualMemory));
  if (!pNtProtectVirtualMemory) return FALSE;

  return RelocationImageRelocEntryInternal(Context, pLdrProcessRelocationBlock,
    pNtProtectVirtualMemory, Diff);
}

PVOID GetCurrentProcessPeb(PIMAGE_HELPER_CONTEXT Context, PVOID Ntdll) {
  auto pRtlGetCurrentPeb = GetProcAddressMine(Context, Ntdll, &IMPORT_PROC(RtlGetCurrentPeb));
  return pRtlGetCurrentPeb();
}

PVOID GetImageBaseAddressFromPeb(PIMAGE_HELPER_CONTEXT Context, PVOID Ntdll, PCSTR ImageName) {
  auto pRtlAcquirePebLock = GetProcAddressMine(Context, Ntdll, &IMPORT_PROC(RtlAcquirePebLock));
  auto pRtlReleasePebLock = GetProcAddressMine(Context, Ntdll, &IMPORT_PROC(RtlReleasePebLock));
  if (!pRtlAcquirePebLock || !pRtlReleasePebLock) return nullptr;

  PEB* Peb = (PEB*)GetCurrentProcessPeb(Context, Ntdll);
  if (!Peb) return nullptr;

  pRtlAcquirePebLock();

  auto List = &Peb->Ldr->InMemoryOrderModuleList;
  List = List->Flink;

  PVOID BaseAddress = nullptr;
  while (!BaseAddress && &Peb->Ldr->InMemoryOrderModuleList != List) {
    auto entry = CONTAINING_RECORD(List, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    // entry存储的路径均为unicode字符串
    BaseAddress = FoundImageBaseAddress(entry->DllBase, ImageName);
    List = List->Flink;
  }

  pRtlReleasePebLock();
  return BaseAddress;
}

#include <Windows.h>
DEF_IMPORT_PROC(LoadLibraryA);
DEF_IMPORT_PROC(VirtualProtect);
DEF_IMPORT_PROC(FreeLibrary);

BOOLEAN RelocationImageImportEntry(PIMAGE_HELPER_CONTEXT Context, PVOID Kernel32, BOOLEAN HideFuncName) {
  auto pLoadLibraryA = GetProcAddressMine(Context, Kernel32, &IMPORT_PROC(LoadLibraryA));
  auto pVirtualProtect = GetProcAddressMine(Context, Kernel32, &IMPORT_PROC(VirtualProtect));
  auto pFreeLibrary = GetProcAddressMine(Context, Kernel32, &IMPORT_PROC(FreeLibrary));

  if (!pLoadLibraryA || !pVirtualProtect || !pFreeLibrary) return FALSE;

  PIMAGE_DATA_DIRECTORY ImportDirectory = &Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  PIMAGE_DATA_DIRECTORY IatDirectory = &Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
  if (!ImportDirectory->Size || !IatDirectory->Size) return FALSE;

  auto ImageBaseAddress = GetImageBaseAddress(Context);
  PVOID IatAddress = RVA_DECODE(PVOID, ImageBaseAddress, IatDirectory->VirtualAddress);
  ULONG Old = 0;
  if (!pVirtualProtect(IatAddress, IatDirectory->Size, PAGE_WRITECOPY, &Old))
    pVirtualProtect(IatAddress, IatDirectory->Size, PAGE_READWRITE, &Old);

  PIMAGE_IMPORT_DESCRIPTOR Descriptor = RVA_DECODE(PIMAGE_IMPORT_DESCRIPTOR, ImageBaseAddress, ImportDirectory->VirtualAddress);

  while (Descriptor->Characteristics) {
    HMODULE Module = pLoadLibraryA(RVA_DECODE(CHAR*, ImageBaseAddress, Descriptor->Name));
    auto ModuleContext = InitializeImageHelperContext(Module);

    if (Module) {
      PULONG_PTR Original = RVA_DECODE(PULONG_PTR, ImageBaseAddress, Descriptor->OriginalFirstThunk);
      auto Thunk = RVA_DECODE(PIMAGE_THUNK_DATA, ImageBaseAddress, Descriptor->FirstThunk);


      for (; *Original; Original++, Thunk++) {
        auto Func = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, ImageBaseAddress, *Original);

        ULONG_PTR Address = (ULONG_PTR)GetProcAddressMine(ModuleContext, Func->Name);
        if (!Address) continue;

        // JMP [i32]
        if (((UCHAR*)Address)[0] == 0xff && ((UCHAR*)Address)[1] == 0x25) {
          ULONG JmpAddress = 0;
          for (int i = 0; i < 4; i++) {
            ((UCHAR*)&JmpAddress)[i] = ((UCHAR*)Address)[i + 2];
          }
#ifdef _M_X64
          UCHAR* FinalAddress = (UCHAR*)Address + 6 + JmpAddress;
#else
          UCHAR* FinalAddress = (UCHAR*)JmpAddress;
#endif // _M_X64
          for (int i = 0; i < sizeof(ULONG_PTR); i++) {
            ((UCHAR*)&Address)[i] = ((UCHAR*)FinalAddress)[i];
          }
        }
#ifdef _M_IX86
        // MOV EDI, EDI
        if (((UCHAR*)Address)[0] == 0x8b && ((UCHAR*)Address)[1] == 0xff) {
          Address += 2;
        }
#endif // _M_IX86
        Thunk->u1.Function = (ULONG_PTR)Address;

        ULONG tOld = 0;
        if (HideFuncName && (pVirtualProtect(Func->Name, 4096, PAGE_WRITECOPY, &tOld)
          || pVirtualProtect(Func->Name, 4096, PAGE_READWRITE, &tOld))) {
          for (CHAR* Ch = Func->Name; *Ch; Ch++)
            *Ch = '\0';
          pVirtualProtect(Func->Name, 4096, tOld, &tOld);
        }
      }
    }
    Descriptor++;
  }
  if (Old != PAGE_NOACCESS) {
    pVirtualProtect(IatAddress, IatDirectory->Size, Old, &Old);
  }

  return TRUE;
}

BOOLEAN InitializeDataSection(PIMAGE_HELPER_CONTEXT Context) {
  PIMAGE_NT_HEADERS ImageNtHeaders = CONTAINING_RECORD(Context, IMAGE_NT_HEADERS, OptionalHeader);
  PIMAGE_SECTION_HEADER ImageSectionHeader = IMAGE_FIRST_SECTION(ImageNtHeaders);

  auto ImageBaseAddress = GetImageBaseAddress(Context);
  DWORD old = 0;
  BOOL bl = VirtualProtect(ImageBaseAddress,
    (CHAR*)ImageSectionHeader - (CHAR*)ImageBaseAddress,
    PAGE_READONLY,
    &old);

  _ASSERT(bl);
  while (ImageSectionHeader->VirtualAddress) {
    if (ImageSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
      old = 0;

      bl = VirtualProtect(RVA_DECODE(PVOID, ImageBaseAddress, ImageSectionHeader->VirtualAddress),
        ImageSectionHeader->Misc.VirtualSize, PAGE_WRITECOPY, &old)
        || VirtualProtect(RVA_DECODE(PVOID, ImageBaseAddress, ImageSectionHeader->VirtualAddress),
        ImageSectionHeader->Misc.VirtualSize, PAGE_READWRITE, &old);
      _ASSERT(bl);
    } else if(!(ImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
      old = 0;
      bl = VirtualProtect(RVA_DECODE(PVOID, ImageBaseAddress, ImageSectionHeader->VirtualAddress),
        ImageSectionHeader->Misc.VirtualSize,
        PAGE_READONLY,
        &old);
      _ASSERT(bl);
    } else if (ImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
      old = 0;
      bl = VirtualProtect(RVA_DECODE(PVOID, ImageBaseAddress, ImageSectionHeader->VirtualAddress),
        ImageSectionHeader->Misc.VirtualSize,
        PAGE_EXECUTE_READ,
        &old);
      _ASSERT(bl);
    }
    ImageSectionHeader++;
  }

  return TRUE;
}

VOID FreeLibraryImportEntry(PIMAGE_HELPER_CONTEXT Context) {
  PIMAGE_DATA_DIRECTORY DataDirectory = &Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!DataDirectory->Size) return;

  auto ImageBaseAddress = GetImageBaseAddress(Context);

  PIMAGE_IMPORT_DESCRIPTOR Descriptor = RVA_DECODE(PIMAGE_IMPORT_DESCRIPTOR, ImageBaseAddress, DataDirectory->VirtualAddress);

  while (Descriptor->Characteristics) {
    HMODULE module = LoadLibraryA(RVA_DECODE(CHAR*, ImageBaseAddress, Descriptor->Name));

    FreeLibrary(module);
    FreeLibrary(module);
    Descriptor++;
  }
}

// SEH相关处理
#ifdef _M_IX86
EXTERN_C IMAGE_LOAD_CONFIG_DIRECTORY _load_config_used;
DWORD LoadConfigEntrySize = 0;
#endif // _M_IX86

BOOLEAN ApplyInjectDllSEH(PIMAGE_HELPER_CONTEXT Context, PVOID NtDll) {
#ifdef _M_X64
  NtDll;
  auto ImageBaseAddress = GetImageBaseAddress(Context);

  if (!Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) return FALSE;
  auto FunctionTable = RVA_DECODE(PRUNTIME_FUNCTION,
    ImageBaseAddress,
    Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

  return RtlAddFunctionTable(FunctionTable,
    Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION),
    (DWORD64)ImageBaseAddress);
#else
  Context, NtDll;
  auto DataDirectory = &Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
  // 采用降级攻击方式，不去修改ntdll的seh相关内容，会有安全性风险，所以在非必要时应该将seh功能关闭。
  if (DataDirectory->Size == 0 && DataDirectory->VirtualAddress == 0) return TRUE;
  DWORD old = 0;
  BOOL bl = VirtualProtect(DataDirectory, sizeof(DataDirectory), PAGE_WRITECOPY, &old)
    || VirtualProtect(DataDirectory, sizeof(DataDirectory), PAGE_READWRITE, &old);
  if (!bl) return FALSE;

  LoadConfigEntrySize = DataDirectory->Size;
  DataDirectory->Size = 0;
  DataDirectory->VirtualAddress = 0;

  VirtualProtect(DataDirectory,
    sizeof(DataDirectory),
    old,
    &old);
  return TRUE;
#endif // _M_X64
}

BOOLEAN CancelInjectDllSEH(PIMAGE_HELPER_CONTEXT Context, PVOID NtDll) {
#ifdef _M_X64
  NtDll;
  auto ImageBaseAddress = GetImageBaseAddress(Context);

  if (!Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) return FALSE;
  auto FunctionTable = RVA_DECODE(PRUNTIME_FUNCTION,
    ImageBaseAddress,
    Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

  return RtlDeleteFunctionTable(FunctionTable);
#else
  NtDll;
  auto DataDirectory = &Context->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
  // 采用降级攻击方式，不去修改ntdll的seh相关内容，会有安全性风险，所以在非必要时应该将seh功能关闭。
  if (DataDirectory->Size != 0 && DataDirectory->VirtualAddress != 0) return TRUE;

  DWORD old = 0;
  BOOL bl = VirtualProtect(DataDirectory, sizeof(DataDirectory), PAGE_WRITECOPY, &old)
    || VirtualProtect(DataDirectory, sizeof(DataDirectory), PAGE_READWRITE, &old);
  if (!bl) return FALSE;

  auto ImageBaseAddress = GetImageBaseAddress(Context);

  DataDirectory->Size = LoadConfigEntrySize;
  DataDirectory->VirtualAddress = (ULONG_PTR)&_load_config_used - (ULONG_PTR)ImageBaseAddress;

  VirtualProtect(DataDirectory,
    sizeof(DataDirectory),
    old,
    &old);
  return TRUE;
#endif // _M_X64
}
