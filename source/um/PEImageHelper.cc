#include <wtypes.h>
#include <winnt.h>

#include "PEImageHelper.h"

#include "../source/constexpr.h"

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  BYTE                          Reserved4[104];
  PVOID                         Reserved5[52];
  struct PS_POST_PROCESS_INIT_ROUTINE* PostProcessInitRoutine;
  BYTE                          Reserved6[128];
  PVOID                         Reserved7[1];
  ULONG                         SessionId;
} PEB, *PPEB;

BOOLEAN StringEqual(PCSTR Str1, PCSTR Str2, BOOLEAN CaseSensitive) {
  CHAR Case = ~(CaseSensitive ? 0 : 'A' ^ 'a');
  PCSTR Ch1 = Str1, Ch2 = Str2;
  for (; *Ch1 && *Ch2; Ch1++, Ch2++) {
    CHAR Value = (*Ch1 ^ *Ch2) & Case;
    if (Value) return FALSE;
  }

  return ((*Ch1) | (*Ch2)) == 0;
}

int CmpString(PCSTR Str1, PCSTR Str2) {
  PCSTR Ch1 = Str1, Ch2 = Str2;
  int r = *Ch1 - *Ch2;

  while (r == 0 && *Ch1 && *Ch2) {
    Ch1++, Ch2++;
    r = *Ch1 - *Ch2;
  }

  return r;
}

inline BOOLEAN GetImageParts(CONST VOID* Base, PIMAGE_NT_HEADERS* NtHeader, PVOID* OptionalHeader,
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

ULONG SizeOfImageFile(CONST VOID* Data) {
  PVOID Opt;
  if (!GetImageParts(Data, nullptr, &Opt, nullptr)) return ~0UL;

  return OPT(Opt, SizeOfImage);
}

PIMAGE_DATA_DIRECTORY GetImageDataDirectoryArray(CONST VOID* Base) {
  PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Base;
  PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((CHAR*)Dos + Dos->e_lfanew);

  LPVOID Opt = &Nt->OptionalHeader;

  return OPT(Opt, DataDirectory);
}

CONST CHAR* GetImageLibraryName(PVOID Base) {
  PIMAGE_DATA_DIRECTORY directory = GetImageDataDirectoryArray(Base);
  if (!directory) return nullptr;

  PIMAGE_DATA_DIRECTORY export_dir = directory + IMAGE_DIRECTORY_ENTRY_EXPORT;
  if (!export_dir->Size) return nullptr;

  PIMAGE_EXPORT_DIRECTORY descriptor = RVA_DECODE(PIMAGE_EXPORT_DIRECTORY, Base, export_dir->VirtualAddress);

  return RVA_DECODE(CONST CHAR*, Base, descriptor->Name);
}

PVOID FoundImageFileBaseAddress(CONST VOID* AddressInImage, PCSTR DllName) {
  ULONG_PTR Base = (ULONG_PTR)AddressInImage & ~65535;
  while (*(WORD*)Base != IMAGE_DOS_SIGNATURE) {
    Base -= 64 * 1024;
  }

  if (!DllName) return (PVOID)Base;
  CONST CHAR* LibraryName = GetImageLibraryName((PVOID)Base);
  if (LibraryName && StringEqual(DllName, LibraryName, FALSE)) {
    return (PVOID)Base;
  }

  return nullptr;
}

PVOID GetKernel32DllBaseAddress(CONST VOID* ProcessSectionBaseAddress, PCSTR Kernel32Dll) {
  PVOID Opt;
  PIMAGE_NT_HEADERS Nt;
  if (!GetImageParts(ProcessSectionBaseAddress, &Nt, &Opt, nullptr)) return nullptr;

  PIMAGE_DATA_DIRECTORY directory = OPT(Opt, DataDirectory);
  if (!directory) return nullptr;

  WORD Machine = Nt->FileHeader.Machine;

  PIMAGE_DATA_DIRECTORY import = directory + IMAGE_DIRECTORY_ENTRY_IMPORT;
  if (!import->Size) return nullptr;

  PIMAGE_IMPORT_DESCRIPTOR descriptor = RVA_DECODE(PIMAGE_IMPORT_DESCRIPTOR, ProcessSectionBaseAddress, import->VirtualAddress);

  for(PIMAGE_IMPORT_DESCRIPTOR desc = descriptor; desc->Characteristics; desc++) {
    if (StringEqual(Kernel32Dll, RVA_DECODE(CHAR*, ProcessSectionBaseAddress, desc->Name), FALSE)) {
      if (Machine == IMAGE_FILE_MACHINE_AMD64) {
        auto thunk = RVA_DECODE(PIMAGE_THUNK_DATA64, ProcessSectionBaseAddress, desc->FirstThunk);
        PVOID Base = FoundImageFileBaseAddress((PVOID)thunk->u1.Function, Kernel32Dll);
        for (; !Base && thunk->u1.Function; thunk++) {
          Base =  FoundImageFileBaseAddress((PVOID)thunk->u1.Function, Kernel32Dll);
        }
        if (Base) return Base;
      } else if (Machine == IMAGE_FILE_MACHINE_I386) {
        auto thunk = RVA_DECODE(PIMAGE_THUNK_DATA32, ProcessSectionBaseAddress, desc->FirstThunk);
        PVOID Base = FoundImageFileBaseAddress((PVOID)thunk->u1.Function, Kernel32Dll);
        for (; !Base && thunk->u1.Function; thunk++) {
          Base =  FoundImageFileBaseAddress((PVOID)thunk->u1.Function, Kernel32Dll);
        }
        if (Base) return Base;
      }
      break;
    }
  }

  for (PIMAGE_IMPORT_DESCRIPTOR desc = descriptor; desc->Characteristics; desc++) {
    PVOID address = nullptr;
    if (Machine == IMAGE_FILE_MACHINE_AMD64) {
      auto thunk = RVA_DECODE(PIMAGE_THUNK_DATA64, ProcessSectionBaseAddress, desc->FirstThunk);
      address = GetKernel32DllBaseAddress(FoundImageFileBaseAddress((PVOID)thunk->u1.Function), Kernel32Dll);
    } else if (Machine == IMAGE_FILE_MACHINE_I386) {
      auto thunk = RVA_DECODE(PIMAGE_THUNK_DATA32, ProcessSectionBaseAddress, desc->FirstThunk);
      address = GetKernel32DllBaseAddress(FoundImageFileBaseAddress((PVOID)thunk->u1.Function), Kernel32Dll);
    }
    if (address) return address;
  }

  return nullptr;
}

PVOID GetProcAddressUser(CONST VOID* ModuleBaseAddress, PCSTR ProcName);

PVOID GetProcAddressForwarder(CONST VOID* ModuleBaseAddress, PCSTR ForwarderString) {
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
  auto base = GetKernel32DllBaseAddress(ModuleBaseAddress, Name);
  if (!base) return nullptr;

  for (n = Name;; s++, n++) {
    *n = *s;
    if (!*s) break;
  }

  return GetProcAddressUser(base, Name);
}

PVOID GetProcAddressUser(CONST VOID* ModuleBaseAddress, PCSTR ProcName) {
  auto dir = GetImageDataDirectoryArray(ModuleBaseAddress);
  if (!dir) return nullptr;

  PIMAGE_DATA_DIRECTORY export_dir = dir + IMAGE_DIRECTORY_ENTRY_EXPORT;
  if (!export_dir->Size) return nullptr;

  PIMAGE_EXPORT_DIRECTORY descriptor = RVA_DECODE(PIMAGE_EXPORT_DIRECTORY, ModuleBaseAddress, export_dir->VirtualAddress);

  PDWORD func_name = RVA_DECODE(PDWORD, ModuleBaseAddress, descriptor->AddressOfNames);
  PDWORD func_address = RVA_DECODE(PDWORD, ModuleBaseAddress, descriptor->AddressOfFunctions);
  PUSHORT func_number = RVA_DECODE(PUSHORT, ModuleBaseAddress, descriptor->AddressOfNameOrdinals);

  ULONG_PTR ProcId = (ULONG_PTR)ProcName;

  if (ProcId <= 64 * 1024 && ProcId) {
      ULONG_PTR r = RVA_DECODE(ULONG_PTR, ModuleBaseAddress, func_address[func_number[ProcId - descriptor->Base]]);
      return PVOID(r);
  } else {
    int index_low = 0, index_high = descriptor->NumberOfNames;

    while(index_low < index_high) {
      int index = (index_low + index_high) / 2;

      PCSTR name = RVA_DECODE(PCSTR, ModuleBaseAddress, func_name[index]);
      int r = CmpString(ProcName, name);
      if (r == 0) {
        ULONG_PTR func = RVA_DECODE(ULONG_PTR, ModuleBaseAddress, func_address[func_number[index]]);
        if (func < (ULONG_PTR)(descriptor) ||
          func >= (ULONG_PTR)((CHAR*)descriptor + export_dir->Size)) {
          return PVOID(func);
        }

        return GetProcAddressForwarder(ModuleBaseAddress, (PCSTR)func);
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

//
// Mark a HIGHADJ entry as needing an increment if reprocessing.
//
#define LDRP_RELOCATION_INCREMENT   0x1

//
// Mark a HIGHADJ entry as not suitable for reprocessing.
//
#define LDRP_RELOCATION_FINAL       0x2

PIMAGE_BASE_RELOCATION
LdrProcessRelocationBlockLongLong(
    IN ULONG_PTR VA,
    IN ULONG SizeOfBlock,
    IN PUSHORT NextOffset,
    IN LONGLONG Diff
) {
  PUCHAR FixupVA;
  USHORT Offset;
  LONG Temp;
  ULONGLONG Value64;

  while (SizeOfBlock--) {

    Offset = *NextOffset & (USHORT)0xfff;
    FixupVA = (PUCHAR)(VA + Offset);

    //
    // Apply the fixups.
    //
    ULONG Type = (*NextOffset) >> 12;
    if (Type == IMAGE_REL_BASED_HIGHLOW) {
      //
      // HighLow - (32-bits) relocate the high and low half
      //      of an address.
      //
      *(LONG UNALIGNED *)FixupVA += (ULONG)Diff;
    } else if (Type == IMAGE_REL_BASED_HIGH) {
      //
      // High - (16-bits) relocate the high half of an address.
      //
      Temp = *(PUSHORT)FixupVA << 16;
      Temp += (ULONG)Diff;
      *(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
    } else if (Type == IMAGE_REL_BASED_HIGHADJ) {

      //
      // Adjust high - (16-bits) relocate the high half of an
      //      address and adjust for sign extension of low half.
      //

      //
      // If the address has already been relocated then don't
      // process it again now or information will be lost.
      //
      if (Offset & LDRP_RELOCATION_FINAL) {
        ++NextOffset;
        --SizeOfBlock;
      } else {
        Temp = *(PUSHORT)FixupVA << 16;
        ++NextOffset;
        --SizeOfBlock;
        Temp += (LONG)(*(PSHORT)NextOffset);
        Temp += (ULONG)Diff;
        Temp += 0x8000;
        *(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
      }
    } else if (Type == IMAGE_REL_BASED_LOW) {
      //
      // Low - (16-bit) relocate the low half of an address.
      //
      Temp = *(PSHORT)FixupVA;
      Temp += (ULONG)Diff;
      *(PUSHORT)FixupVA = (USHORT)Temp;
    } else if (Type == IMAGE_REL_BASED_IA64_IMM64) {

      //
      // Align it to bundle address before fixing up the
      // 64-bit immediate value of the movl instruction.
      //

      FixupVA = (PUCHAR)((ULONG_PTR)FixupVA & ~(15));
      Value64 = (ULONGLONG)0;

      //
      // Extract the lower 32 bits of IMM64 from bundle
      //


      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X,
              EMARCH_ENC_I17_IMM7B_SIZE_X,
              EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM7B_VAL_POS_X);
      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X,
              EMARCH_ENC_I17_IMM9D_SIZE_X,
              EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM9D_VAL_POS_X);
      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X,
              EMARCH_ENC_I17_IMM5C_SIZE_X,
              EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM5C_VAL_POS_X);
      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X,
              EMARCH_ENC_I17_IC_SIZE_X,
              EMARCH_ENC_I17_IC_INST_WORD_POS_X,
              EMARCH_ENC_I17_IC_VAL_POS_X);
      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X,
              EMARCH_ENC_I17_IMM41a_SIZE_X,
              EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM41a_VAL_POS_X);

      EXT_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
              EMARCH_ENC_I17_IMM41b_SIZE_X,
              EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM41b_VAL_POS_X);
      EXT_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
              EMARCH_ENC_I17_IMM41c_SIZE_X,
              EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM41c_VAL_POS_X);
      EXT_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
              EMARCH_ENC_I17_SIGN_SIZE_X,
              EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
              EMARCH_ENC_I17_SIGN_VAL_POS_X);
      //
      // Update 64-bit address
      //

      Value64 += Diff;

      //
      // Insert IMM64 into bundle
      //

      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X),
              EMARCH_ENC_I17_IMM7B_SIZE_X,
              EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM7B_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X),
              EMARCH_ENC_I17_IMM9D_SIZE_X,
              EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM9D_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X),
              EMARCH_ENC_I17_IMM5C_SIZE_X,
              EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM5C_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X),
              EMARCH_ENC_I17_IC_SIZE_X,
              EMARCH_ENC_I17_IC_INST_WORD_POS_X,
              EMARCH_ENC_I17_IC_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X),
              EMARCH_ENC_I17_IMM41a_SIZE_X,
              EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM41a_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
              EMARCH_ENC_I17_IMM41b_SIZE_X,
              EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM41b_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
              EMARCH_ENC_I17_IMM41c_SIZE_X,
              EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
              EMARCH_ENC_I17_IMM41c_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
              EMARCH_ENC_I17_SIGN_SIZE_X,
              EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
              EMARCH_ENC_I17_SIGN_VAL_POS_X);
    } else if (Type == IMAGE_REL_BASED_DIR64) {
      *(ULONGLONG UNALIGNED *)FixupVA += Diff;
    } else if (Type == IMAGE_REL_BASED_MIPS_JMPADDR) {
      //
      // JumpAddress - (32-bits) relocate a MIPS jump address.
      //
      Temp = (*(PULONG)FixupVA & 0x3ffffff) << 2;
      Temp += (ULONG)Diff;
      *(PULONG)FixupVA = (*(PULONG)FixupVA & ~0x3ffffff) |
        ((Temp >> 2) & 0x3ffffff);
    } else if (Type != IMAGE_REL_BASED_ABSOLUTE) {
//      && Type != IMAGE_REL_BASED_SECTION && Type != IMAGE_REL_BASED_REL32)
      return (PIMAGE_BASE_RELOCATION)NULL;
    }
    ++NextOffset;
  }
  return (PIMAGE_BASE_RELOCATION)NextOffset;
}

// 按照目前流程 RelocLibraryRelocEntry && RelocLibraryImportEntry会被最先调用，所以除了这两个函数外
// 所有调用不能使用DEF_IMPORT_PROC方式。
DEF_IMPORT_PROC(LoadLibraryA);
DEF_IMPORT_PROC(VirtualProtect);
DEF_IMPORT_PROC(FreeLibrary);

VOID RelocLibraryRelocEntry(__in CONST VOID* Kernel32,
  __in CONST VOID* DllBase, __in CONST VOID* RawDllBase,
  __in ULONG_PTR Diff) {
  //if (DllBase == RawDllBase) return;
  PIMAGE_DATA_DIRECTORY Dir = GetImageDataDirectoryArray(DllBase);
  if (!Dir) return;

  PIMAGE_BASE_RELOCATION BaseReloc = RVA_DECODE(PIMAGE_BASE_RELOCATION,
    DllBase, Dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
  if (BaseReloc == DllBase) return;

  CONST CHAR* Name;
  {
    PULONG_PTR Address = RVA_DECODE(PULONG_PTR, DllBase,
      (ULONG_PTR)&IMPORT_PROC(VirtualProtect) - (ULONG_PTR)RawDllBase);
    Name = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, DllBase, *Address)->Name;
  }
  auto CallVirtualProtect = (decltype(VirtualProtect)*)GetProcAddressUser(
    Kernel32, Name);

  while(BaseReloc && BaseReloc->VirtualAddress) {
    DWORD old = 0;
    BOOL bl = CallVirtualProtect(RVA_DECODE(PVOID, DllBase,
      BaseReloc->VirtualAddress), 4096, PAGE_EXECUTE_WRITECOPY, &old);
    if (!bl) {
      bl = CallVirtualProtect(RVA_DECODE(PVOID, DllBase,
        BaseReloc->VirtualAddress), 4096, PAGE_EXECUTE_READWRITE, &old);
    }
    BaseReloc = LdrProcessRelocationBlockLongLong((ULONG_PTR)DllBase + BaseReloc->VirtualAddress,
      (BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT),
      (PUSHORT)(BaseReloc + 1), Diff);
    bl = CallVirtualProtect(RVA_DECODE(PVOID, DllBase,
      BaseReloc->VirtualAddress), 4096, old, &old);
  }
}

VOID FreeLibraryImportEntry(__in PVOID DllBase) {
  PVOID Opt;
  PIMAGE_NT_HEADERS Nt;
  if (!GetImageParts(DllBase, &Nt, &Opt, nullptr)) return;

  PIMAGE_DATA_DIRECTORY directory = OPT(Opt, DataDirectory);

  PIMAGE_DATA_DIRECTORY import = directory + IMAGE_DIRECTORY_ENTRY_IMPORT;
  if (!import->Size || !import->VirtualAddress) return;

  PIMAGE_IMPORT_DESCRIPTOR descriptor = RVA_DECODE(PIMAGE_IMPORT_DESCRIPTOR, DllBase, import->VirtualAddress);

  while (descriptor->Characteristics) {
    HMODULE module = LoadLibraryA(RVA_DECODE(CHAR*, DllBase, descriptor->Name));

    FreeLibrary(module);
    FreeLibrary(module);
    descriptor++;
  }
}

BOOLEAN WINAPI RelocLibraryImportEntry(
  __in PVOID Kernel32,
  __in PVOID DllBase) {
  auto CallLoadLibraryA = (decltype(LoadLibraryA)*)GetProcAddressUser(
    Kernel32, IMPORT_PROC_NAME(DllBase, LoadLibraryA));

  auto CallVirtualProtect = (decltype(VirtualProtect)*)GetProcAddressUser(
    Kernel32, IMPORT_PROC_NAME(DllBase, VirtualProtect));

  auto CallFreeLibrary = (decltype(FreeLibrary)*)GetProcAddressUser(
    Kernel32, IMPORT_PROC_NAME(DllBase, FreeLibrary));

  if (!CallLoadLibraryA || !CallVirtualProtect || !CallFreeLibrary) return FALSE;

  PVOID Opt;
  PIMAGE_NT_HEADERS Nt;
  if (!GetImageParts(DllBase, &Nt, &Opt, nullptr)) return FALSE;
  WORD Machine = Nt->FileHeader.Machine;

  PIMAGE_DATA_DIRECTORY directory = OPT(Opt, DataDirectory);

  PIMAGE_DATA_DIRECTORY import = directory + IMAGE_DIRECTORY_ENTRY_IMPORT;
  PIMAGE_DATA_DIRECTORY iat = directory + IMAGE_DIRECTORY_ENTRY_IAT;
  if (!import->Size || !iat->Size) return FALSE;

  PVOID iat_address = RVA_DECODE(PVOID, DllBase, iat->VirtualAddress);
  DWORD old = 0;
  BOOL bl = CallVirtualProtect(iat_address, iat->Size, PAGE_WRITECOPY, &old);
  if (!bl) CallVirtualProtect(iat_address, iat->Size, PAGE_READWRITE, &old);

  PIMAGE_IMPORT_DESCRIPTOR descriptor = RVA_DECODE(PIMAGE_IMPORT_DESCRIPTOR, DllBase, import->VirtualAddress);

  while (descriptor->Characteristics) {
    HMODULE module = CallLoadLibraryA(RVA_DECODE(CHAR*, DllBase, descriptor->Name));

    if (module) {
      if (Machine == IMAGE_FILE_MACHINE_AMD64) {
        PULONGLONG original = RVA_DECODE(PULONGLONG, DllBase, descriptor->OriginalFirstThunk);
        auto thunk = RVA_DECODE(PIMAGE_THUNK_DATA64, DllBase, descriptor->FirstThunk);

        for (; *original; original++, thunk++) {
          auto func = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, DllBase, *original);
          ULONGLONG address = (ULONGLONG)GetProcAddressUser(module, func->Name);
          if (!address) continue;
          thunk->u1.Function = address;
        }
      } else if (Machine == IMAGE_FILE_MACHINE_I386) {
        PDWORD original = RVA_DECODE(PDWORD, DllBase, descriptor->OriginalFirstThunk);
        auto thunk = RVA_DECODE(PIMAGE_THUNK_DATA32, DllBase, descriptor->FirstThunk);

        for (; *original; original++, thunk++) {
          auto func = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, DllBase, *original);
          DWORD address = (DWORD)(ULONGLONG)GetProcAddressUser(module, func->Name);
          if (!address) continue;
          thunk->u1.Function = address;
        }
      }
    }
    descriptor++;
  }
  CallVirtualProtect(iat_address, iat->Size, old, &old);
  return TRUE;
}

EXTERN_C PEB* NTAPI RtlGetCurrentPeb();

EXTERN_C VOID NTAPI RtlAcquirePebLock();
EXTERN_C VOID NTAPI RtlReleasePebLock();

DEF_IMPORT_PROC(RtlGetCurrentPeb);
DEF_IMPORT_PROC(RtlAcquirePebLock);
DEF_IMPORT_PROC(RtlReleasePebLock);

PVOID GetDllBaseAddress(CONST VOID* NtdllBaseAddress, CONST VOID* NameInBaseAddress, CONST VOID* RawNameInBaseAddress, CONST CHAR* DllName) {
  CONST CHAR* Name;

  {
    PULONG_PTR Address = RVA_DECODE(PULONG_PTR, NameInBaseAddress,
      (ULONG_PTR)&IMPORT_PROC(RtlGetCurrentPeb) - (ULONG_PTR)RawNameInBaseAddress);
    Name = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, NameInBaseAddress, *Address)->Name;
  }
  auto RtlGetCurrentPebProc = (decltype(RtlGetCurrentPeb)*)GetProcAddressUser(
    NtdllBaseAddress, Name);

  {
    PULONG_PTR Address = RVA_DECODE(PULONG_PTR, NameInBaseAddress,
      (ULONG_PTR)&IMPORT_PROC(RtlAcquirePebLock) - (ULONG_PTR)RawNameInBaseAddress);
    Name = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, NameInBaseAddress, *Address)->Name;
  }
  auto RtlAcquirePebLockProc = (decltype(RtlAcquirePebLock)*)GetProcAddressUser(
    NtdllBaseAddress, Name);

  {
    PULONG_PTR Address = RVA_DECODE(PULONG_PTR, NameInBaseAddress,
      (ULONG_PTR)&IMPORT_PROC(RtlReleasePebLock) - (ULONG_PTR)RawNameInBaseAddress);
    Name = RVA_DECODE(PIMAGE_IMPORT_BY_NAME, NameInBaseAddress, *Address)->Name;
  }
  auto RtlReleasePebLockProc = (decltype(RtlReleasePebLock)*)GetProcAddressUser(
    NtdllBaseAddress, Name);

  auto peb = RtlGetCurrentPebProc();
  RtlAcquirePebLockProc();
  auto list = &peb->Ldr->InMemoryOrderModuleList;
  list = list->Flink;

  while(&peb->Ldr->InMemoryOrderModuleList != list) {
    auto entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    // entry存储的路径均为unicode字符串
    auto r = FoundImageFileBaseAddress(entry->DllBase, DllName);
    if (r) {
      RtlReleasePebLockProc();
      return r;
    }
    list = list->Flink;
  }

  RtlReleasePebLockProc();
  return nullptr;
}

BOOLEAN WINAPI InitializeDataSection(__in PVOID DllBase) {
  PIMAGE_NT_HEADERS NtHeader = RVA_DECODE(PIMAGE_NT_HEADERS, DllBase, ((PIMAGE_DOS_HEADER)DllBase)->e_lfanew);
  PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

  while (Section->VirtualAddress) {
    if (Section->Characteristics & IMAGE_SCN_MEM_WRITE) {
      DWORD old = 0;
      BOOL bl = VirtualProtect(RVA_DECODE(PVOID, DllBase, Section->VirtualAddress),
        Section->Misc.VirtualSize,
        PAGE_WRITECOPY,
        &old);
      if (!bl) {
        VirtualProtect(RVA_DECODE(PVOID, DllBase, Section->VirtualAddress),
          Section->Misc.VirtualSize,
          PAGE_READWRITE,
          &old);
      }
    }
    Section++;
  }

  return TRUE;
}

#define __NEW_IMPL__
#ifndef __NEW_IMPL__
#ifndef _M_X64
typedef ULONGLONG PRUNTIME_FUNCTION;
#endif // !_M_X64
typedef struct _INVERTED_FUNCTION_TABLE_ENTRY64 {
  PRUNTIME_FUNCTION   RuntimeFunctionTable;
  PVOID       BaseImageAddress;
  ULONG       SizeOfImage;
  ULONG       SizeOfRuntimeFunctionTable;
} INVERTED_FUNCTION_TABLE_ENTRY64, *PINVERTED_FUNCTION_TABLE_ENTRY64;

typedef struct _INVERTED_FUNCTION_TABLE_ENTRY32 {
  ULONG       SEHandlerTable;   // 需要使用RtlEncodeSystemPointer进行编码

  ULONG       BaseImageAddress;
  ULONG       SizeOfImage;

  ULONG       SEHandlerCount;
} INVERTED_FUNCTION_TABLE_ENTRY32, *PINVERTED_FUNCTION_TABLE_ENTRY32;

typedef struct _LDR_INVERTED_FUNCTION_TABLE {
  ULONG   TableCount;
  ULONG   MaxEntryCount;  //default == 0x200
  ULONG   AllTableCount;
  BOOLEAN TableFull;
  BYTE    _3[3];

  union {
    PVOID                   TableEntry;
    INVERTED_FUNCTION_TABLE_ENTRY32  TableEntry32[0x200];
    INVERTED_FUNCTION_TABLE_ENTRY64  TableEntry64[0x200];
  };
} LDR_INVERTED_FUNCTION_TABLE, *PLDR_INVERTED_FUNCTION_TABLE;



PVOID GetMrdataInvertedFunctionTable(PVOID NtDllImageBase) {
  PIMAGE_NT_HEADERS NtHeader;
  PIMAGE_SECTION_HEADER Section;

  if (!GetImageParts(NtDllImageBase, &NtHeader, nullptr, &Section)) return nullptr;

  WORD Machine = NtHeader->FileHeader.Machine;

  constexpr ULONGLONG _mrdata = ((ULONGLONG)'ata' << 32) | RA('.mrd');
  while (Section->VirtualAddress) {
    ULONGLONG Name = *(ULONGLONG*)Section->Name;
    if (Name == _mrdata) {
      UCHAR* base = RVA_DECODE(
        UCHAR*,
        NtDllImageBase,
        Section->VirtualAddress);

      for (UCHAR* end = base + Section->Misc.VirtualSize; base <= end; base += 0x10) {
        PLDR_INVERTED_FUNCTION_TABLE table = (PLDR_INVERTED_FUNCTION_TABLE)base;
        if (table->MaxEntryCount == 0x200) {
          if (Machine == IMAGE_FILE_MACHINE_AMD64) {
            if ((PVOID)table->TableEntry64[0].BaseImageAddress == NtDllImageBase)
              return base;
          } else if (Machine == IMAGE_FILE_MACHINE_I386) {
            if ((PVOID)table->TableEntry32[0].BaseImageAddress == NtDllImageBase)
              return base;
          }
        }
      }
      break;
    }
    Section++;
  }
  return nullptr;
}

template<typename T>
BOOLEAN WINAPI ApplyInjectDllSEHInternal(
  __in PVOID NtDll,
  __in PVOID DllBase) {
  PVOID Opt;
  if (!GetImageParts(DllBase, nullptr, &Opt, nullptr)) return FALSE;

  auto directory = OPT(Opt, DataDirectory);
  DWORD Size = OPT(Opt, SizeOfImage);

  PLDR_INVERTED_FUNCTION_TABLE raw_table = (PLDR_INVERTED_FUNCTION_TABLE)GetMrdataInvertedFunctionTable(NtDll);
  if (!raw_table) return FALSE;

  LDR_INVERTED_FUNCTION_TABLE new_table[64];
  new_table[0] = *raw_table;

  T* raw_entry = (T*)&raw_table->TableEntry;
  T* new_entry = (T*)&new_table->TableEntry;

  T add_entry;
  add_entry.BaseImageAddress = (decltype(T::BaseImageAddress))(ULONGLONG)DllBase;
  add_entry.SizeOfImage = Size;

  __if_exists(T::SEHandlerCount) {
    PIMAGE_DATA_DIRECTORY config = directory + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG;
    PIMAGE_LOAD_CONFIG_DIRECTORY32 dir = RVA_DECODE(PIMAGE_LOAD_CONFIG_DIRECTORY32, DllBase, config->VirtualAddress);

    // 参考RtlCaptureImageExceptionValues的实现，这里只实现了部分
    if (config->Size && config->VirtualAddress
      && (config->Size == 64 || config->Size == dir->Size)
      && dir->Size > FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFCheckFunctionPointer)) {
      add_entry.SEHandlerCount = dir->SEHandlerCount;

      constexpr int Proc[] = {RA('RtlE'), RA('ncod'), RA('eSys'), RA('temP'), RA('oint'), RA('er')};

      auto decode = (ULONG(__stdcall*)(ULONG Val))GetProcAddressUser(NtDll, (const char*)Proc);
      add_entry.SEHandlerTable = decode(dir->SEHandlerTable);
    } else {
      add_entry.SEHandlerTable = (ULONG)-1;
      add_entry.SEHandlerCount = (ULONG)-1;
    }
  }
  __if_not_exists(T::SEHandlerCount) {
    PIMAGE_DATA_DIRECTORY exception = directory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;

    add_entry.RuntimeFunctionTable = RVA_DECODE(decltype(T::RuntimeFunctionTable), DllBase, exception->VirtualAddress);
    add_entry.SizeOfRuntimeFunctionTable = exception->Size;
  }

  for (ULONG r = 1, n = 1; r < raw_table->TableCount; r++, n++) {
    if ((PVOID)raw_entry[r].BaseImageAddress < DllBase) {
      new_entry[n] = raw_entry[r];
    } else if (DllBase < (PVOID)raw_entry[r].BaseImageAddress) {
      if (r == n) {
        new_entry[n] = add_entry;
        n++;
        new_table->TableCount++;
      }

      new_entry[n] = raw_entry[r];
    }
  }

  if (raw_table->TableCount + 1 != new_table->TableCount) {
    return FALSE;
  }

  {
    DWORD old = 0;
    Size =  FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry) + (new_table[0].TableCount - 1) * sizeof(T);
    BOOL bl = VirtualProtect(raw_table, Size, PAGE_WRITECOPY, &old);
    if (!bl) VirtualProtect(raw_table, Size, PAGE_READWRITE, &old);
    CopyMemory(raw_table, new_table, Size);
    VirtualProtect(raw_table, Size, old, &old);
  }
  return TRUE;
}

template<typename T>
BOOLEAN WINAPI CancelInjectDllSEHInternal(
  __in PVOID NtDll,
  __in PVOID DllBase) {
  PLDR_INVERTED_FUNCTION_TABLE raw_table = (PLDR_INVERTED_FUNCTION_TABLE)GetMrdataInvertedFunctionTable(NtDll);
  if (!raw_table) return FALSE;

  LDR_INVERTED_FUNCTION_TABLE new_table[64];
  new_table[0] = *raw_table;

  T* raw_entry = (T*)&raw_table->TableEntry;
  T* new_entry = (T*)&new_table->TableEntry;

  for (ULONG r = 1, n = 1; r < raw_table->TableCount; r++, n++) {
    if ((PVOID)raw_entry[r].BaseImageAddress != DllBase) {
      new_entry[n] = raw_entry[r];
    } else {
      n--;
      new_table->TableCount--;
    }
  }

  if (raw_table->TableCount - 1 != new_table->TableCount) {
    return FALSE;
  }

  {
    DWORD old = 0;
    DWORD Size =  FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry) + (new_table[0].TableCount - 1) * sizeof(T);
    BOOL bl = VirtualProtect(raw_table, Size, PAGE_WRITECOPY, &old);
    if (!bl) VirtualProtect(raw_table, Size, PAGE_READWRITE, &old);
    CopyMemory(raw_table, new_table, Size);
    VirtualProtect(raw_table, Size, old, &old);
  }

  return TRUE;
}


// KiUserInvertedFunctionTable
// 允许非通过LoadLibrary载入的dll使用SEH机制
// 存在同步问题，可以考虑将进程内所有线程全部停止的策略。
BOOLEAN WINAPI ApplyInjectDllSEH(
  __in PVOID NtDll,
  __in PVOID DllBase) {

  // 64位下貌似存在所有image放在低地址空间的特性
  if (((ULONG_PTR)NtDll | (ULONG_PTR)DllBase) & 0xffffffff00000000ULL) {
    return ApplyInjectDllSEHInternal<INVERTED_FUNCTION_TABLE_ENTRY64>(NtDll, DllBase);
  }
  return ApplyInjectDllSEHInternal<INVERTED_FUNCTION_TABLE_ENTRY32>(NtDll, DllBase);
}

BOOLEAN WINAPI CancelInjectDllSEH(
  __in PVOID NtDll,
  __in PVOID DllBase) {
  if (((ULONG_PTR)NtDll | (ULONG_PTR)DllBase) & 0xffffffff00000000ULL) {
    return CancelInjectDllSEHInternal<INVERTED_FUNCTION_TABLE_ENTRY64>(NtDll, DllBase);
  }
  return CancelInjectDllSEHInternal<INVERTED_FUNCTION_TABLE_ENTRY32>(NtDll, DllBase);
}

#else
#ifdef _M_IX86
typedef struct _INVERTED_FUNCTION_TABLE_ENTRY32 {
  ULONG       SEHandlerTable;   // 需要使用RtlEncodeSystemPointer进行编码

  ULONG       BaseImageAddress;
  ULONG       SizeOfImage;

  ULONG       SEHandlerCount;
} INVERTED_FUNCTION_TABLE_ENTRY32, *PINVERTED_FUNCTION_TABLE_ENTRY32;

typedef struct _LDR_INVERTED_FUNCTION_TABLE {
  ULONG   TableCount; // offset 0
  ULONG   MaxEntryCount;  // offset 4 default == 0x200
  ULONG   AllTableCount;  // offset 8
  BOOLEAN TableFull;
  BYTE    _3[3];

  INVERTED_FUNCTION_TABLE_ENTRY32  TableEntry32[0x200];
} LDR_INVERTED_FUNCTION_TABLE, *PLDR_INVERTED_FUNCTION_TABLE;

PVOID GetMrdataInvertedFunctionTable(PVOID NtDllImageBase, PULONG* LdrpMrdataUnprotected) {
  DBG_UNREFERENCED_PARAMETER(LdrpMrdataUnprotected);

  PIMAGE_NT_HEADERS NtHeader;
  PIMAGE_SECTION_HEADER Section;

  if (!GetImageParts(NtDllImageBase, &NtHeader, nullptr, &Section)) return nullptr;

  constexpr ULONGLONG _mrdata = ((ULONGLONG)'ata' << 32) | RA('.mrd');
  while (Section->VirtualAddress) {
    ULONGLONG Name = *(ULONGLONG*)Section->Name;
    if (Name == _mrdata) {
      UCHAR* base = RVA_DECODE(
        UCHAR*,
        NtDllImageBase,
        Section->VirtualAddress);

      for (UCHAR* end = base + Section->Misc.VirtualSize; base <= end; base += 0x10) {
        PLDR_INVERTED_FUNCTION_TABLE table = (PLDR_INVERTED_FUNCTION_TABLE)base;
        if (table->MaxEntryCount == 0x200
          /*&& ((DWORD*)(table + 1))[0x00] == Section->Misc.VirtualSize &&
          (ULONG_PTR)((DWORD*)(table + 1))[0x01] ==
            RVA_DECODE(ULONG_PTR, NtDllImageBase, Section->VirtualAddress)*/
          ) {
          if ((PVOID)table->TableEntry32[0].BaseImageAddress == NtDllImageBase) {
            //if (LdrpMrdataUnprotected) *LdrpMrdataUnprotected = ((DWORD*)(table + 1)) + 2;
            return base;
          }
        }
      }
      break;
    }
    Section++;
  }
  return nullptr;
}

PVOID GetMrdataInvertedFunctionTableWin7x86(PVOID NtDllImageBase, PULONG* LdrpMrdataUnprotected) {
  DBG_UNREFERENCED_PARAMETER(LdrpMrdataUnprotected);

  PIMAGE_NT_HEADERS NtHeader;
  PIMAGE_SECTION_HEADER Section;

  if (!GetImageParts(NtDllImageBase, &NtHeader, nullptr, &Section)) return nullptr;

  constexpr ULONGLONG _data = ((ULONGLONG)'a' << 32) | RA('.dat');
  while (Section->VirtualAddress) {
    ULONGLONG Name = *(ULONGLONG*)Section->Name;
    if (Name == _data) {
      UCHAR* base = RVA_DECODE(
        UCHAR*,
        NtDllImageBase,
        Section->VirtualAddress);

      for (UCHAR* end = base + Section->Misc.VirtualSize; base <= end; base += 0x100) {
        PLDR_INVERTED_FUNCTION_TABLE table = (PLDR_INVERTED_FUNCTION_TABLE)base;
        if (table->MaxEntryCount == 0x200 && table->TableCount <= table->MaxEntryCount
          /*&& ((DWORD*)(table + 1))[0x00] == Section->Misc.VirtualSize &&
          (ULONG_PTR)((DWORD*)(table + 1))[0x01] ==
            RVA_DECODE(ULONG_PTR, NtDllImageBase, Section->VirtualAddress)*/
          ) {
          //if (LdrpMrdataUnprotected) *LdrpMrdataUnprotected = ((DWORD*)(table + 1)) + 2;
          return base;
        }
      }
      break;
    }
    Section++;
  }
  return nullptr;
}

// 这里将handler直接交给了编译器处理，所以造成不能通过外部调用
DEF_SYMBOL_ANY(BYTE, safe_se_handler_count);
DEF_SYMBOL_ANY(PVOID, safe_se_handler_table[]);

// 根据RtlpxLookupFunctionTable实现，规避seh检查
#define __FULL_COUNT__

BOOLEAN WINAPI ApplyInjectDllSEHInternal(
  __in PVOID NtDll,
  __in PVOID DllBase) {

  //PULONG LdrpMrdataUnprotected = nullptr;

  PLDR_INVERTED_FUNCTION_TABLE raw_table =
    (PLDR_INVERTED_FUNCTION_TABLE)GetMrdataInvertedFunctionTable(NtDll, nullptr);//&LdrpMrdataUnprotected);
#ifdef __FULL_COUNT__
   if (!raw_table) {
     raw_table = (PLDR_INVERTED_FUNCTION_TABLE)GetMrdataInvertedFunctionTableWin7x86(NtDll, nullptr);
     if (raw_table) {
        DWORD old = 0;
        DWORD Size =  FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry32[raw_table->TableCount]);
        BOOL bl = VirtualProtect(raw_table, Size, PAGE_WRITECOPY, &old);
        if (!bl) VirtualProtect(raw_table, Size, PAGE_READWRITE, &old);

        ((CHAR*)&raw_table->AllTableCount)[0] = TRUE;
        // (*LdrpMrdataUnprotected)++;
        VirtualProtect(raw_table, Size, old, &old);
     }
   }
#endif // __FULL_COUNT__
  if (!raw_table) {
#ifdef _DEBUG
    DebugBreak();
#endif // _DEBUG
    return FALSE;
  }
#ifdef __FULL_COUNT__
  {
    DBG_UNREFERENCED_PARAMETER(DllBase);
    DWORD old = 0;
    DWORD Size =  FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry32[raw_table->TableCount]);
    BOOL bl = VirtualProtect(raw_table, Size, PAGE_WRITECOPY, &old);
    if (!bl) VirtualProtect(raw_table, Size, PAGE_READWRITE, &old);
    raw_table->TableFull = TRUE;
    // (*LdrpMrdataUnprotected)++;
    VirtualProtect(raw_table, Size, old, &old);
    // (*LdrpMrdataUnprotected)--;
  }
#else
  PVOID Opt;
  if (!GetImageParts(DllBase, nullptr, &Opt, nullptr)) return FALSE;

  DWORD Size = OPT(Opt, SizeOfImage);

  LDR_INVERTED_FUNCTION_TABLE new_table;
  // C4701
  new_table.TableCount = 0;
  PINVERTED_FUNCTION_TABLE_ENTRY32 raw_entry = raw_table->TableEntry32;
  PINVERTED_FUNCTION_TABLE_ENTRY32 add_entry = nullptr;

  // 需要保护
  for (ULONG r = 1; r < raw_table->TableCount; r++) {
    if (DllBase == (PVOID)raw_entry[r].BaseImageAddress) {
      return TRUE;
    } else if (DllBase < (PVOID)raw_entry[r].BaseImageAddress) {
      CopyMemory(&new_table, raw_table,
        FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry32[r]));

      add_entry = &new_table.TableEntry32[r];

      CopyMemory(add_entry + 1, &raw_entry[r],
        sizeof(INVERTED_FUNCTION_TABLE_ENTRY32) * (raw_table->TableCount - r));
      break;
    }
  }

  if (!add_entry) {
    CopyMemory(&new_table,
      raw_table,
      FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry32[raw_table->TableCount]));
    add_entry = &new_table.TableEntry32[raw_table->TableCount];
  }

  add_entry->BaseImageAddress = (ULONG)(ULONG_PTR)DllBase;
  add_entry->SizeOfImage = Size;

  __if_exists(SYMBOL_ANY(safe_se_handler_count)) {
    add_entry->SEHandlerCount = (ULONG)(ULONG_PTR)&SYMBOL_ANY(safe_se_handler_count);
    constexpr int Proc[] = {RA('RtlE'), RA('ncod'), RA('eSys'), RA('temP'), RA('oint'), RA('er')};

    auto decode = (ULONG(__stdcall*)(ULONG Val))GetProcAddressUser(NtDll, (const char*)Proc);
    add_entry->SEHandlerTable = decode((ULONG)(ULONG_PTR)SYMBOL_ANY(safe_se_handler_table));
  }
  __if_not_exists(__safe_se_handler_count) {
    add_entry->SEHandlerTable = (ULONG)-1;
    add_entry->SEHandlerCount = (ULONG)-1;
  }

  if (raw_table->TableCount + 1 != ++new_table.TableCount) {
    return FALSE;
  }

  {
    DWORD old = 0;
    Size =  FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry32[new_table.TableCount]);
    BOOL bl = VirtualProtect(raw_table, Size, PAGE_WRITECOPY, &old);
    if (!bl) VirtualProtect(raw_table, Size, PAGE_READWRITE, &old);

    // (*LdrpMrdataUnprotected)++;
    CopyMemory(raw_table, &new_table, Size);
    // (*LdrpMrdataUnprotected)--;
    VirtualProtect(raw_table, Size, old, &old);
  }
#endif // __FULL_COUNT__
  return TRUE;
}

BOOLEAN WINAPI CancelInjectDllSEHInternal(
  __in PVOID NtDll,
  __in PVOID DllBase) {
  //PULONG LdrpMrdataUnprotected = nullptr;
  PLDR_INVERTED_FUNCTION_TABLE raw_table = (PLDR_INVERTED_FUNCTION_TABLE)
    GetMrdataInvertedFunctionTable(NtDll, nullptr);//&LdrpMrdataUnprotected);
#ifdef __FULL_COUNT__
   if (!raw_table) {
     raw_table = (PLDR_INVERTED_FUNCTION_TABLE)GetMrdataInvertedFunctionTableWin7x86(NtDll, nullptr);
     if (raw_table) {
        DWORD old = 0;
        DWORD Size =  FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry32[raw_table->TableCount]);
        BOOL bl = VirtualProtect(raw_table, Size, PAGE_WRITECOPY, &old);
        if (!bl) VirtualProtect(raw_table, Size, PAGE_READWRITE, &old);
        ((CHAR*)&raw_table->AllTableCount)[0] = raw_table->TableCount == raw_table->MaxEntryCount;
        // (*LdrpMrdataUnprotected)++;
        VirtualProtect(raw_table, Size, old, &old);
     }
   }
#endif // __FULL_COUNT__
  if (!raw_table) {
#ifdef _DEBUG
    DebugBreak();
#endif // _DEBUG
    return FALSE;
  }
#ifdef __FULL_COUNT__
  DBG_UNREFERENCED_PARAMETER(DllBase);
  {
    DWORD old = 0;
    DWORD Size =  FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry32[raw_table->TableCount]);
    BOOL bl = VirtualProtect(raw_table, Size, PAGE_WRITECOPY, &old);
    if (!bl) VirtualProtect(raw_table, Size, PAGE_READWRITE, &old);
    raw_table->TableFull = raw_table->TableCount == raw_table->MaxEntryCount;
    // (*LdrpMrdataUnprotected)++;
    VirtualProtect(raw_table, Size, old, &old);
    // (*LdrpMrdataUnprotected)--;
  }
#else
  LDR_INVERTED_FUNCTION_TABLE new_table;
  // C4701
  new_table.TableCount = 0;

  PINVERTED_FUNCTION_TABLE_ENTRY32 raw_entry = raw_table->TableEntry32;
  PINVERTED_FUNCTION_TABLE_ENTRY32 del_entry = nullptr;

  // 需要保护
  for (ULONG r = 1; r < raw_table->TableCount; r++) {
    if (DllBase == (PVOID)raw_entry[r].BaseImageAddress) {
      CopyMemory(&new_table, raw_table, FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry32[r]));
      del_entry = &raw_table->TableEntry32[r];

      CopyMemory(&new_table.TableEntry32[r], del_entry + 1,
        sizeof(INVERTED_FUNCTION_TABLE_ENTRY32) * (raw_table->TableCount - (r + 1)));

      //ZeroMemory(&new_table.TableEntry32[raw_table->TableCount - 1], sizeof(INVERTED_FUNCTION_TABLE_ENTRY32));
      break;
    }
  }

  if (!del_entry) return TRUE;

  if (raw_table->TableCount - 1 != --new_table.TableCount) {
    return FALSE;
  }

  {
    DWORD old = 0;
    DWORD Size =  FIELD_OFFSET(LDR_INVERTED_FUNCTION_TABLE, TableEntry32[raw_table->TableCount]);
    BOOL bl = VirtualProtect(raw_table, Size, PAGE_WRITECOPY, &old);
    if (!bl) VirtualProtect(raw_table, Size, PAGE_READWRITE, &old);
    // (*LdrpMrdataUnprotected)++;
    CopyMemory(raw_table, &new_table, Size);
    VirtualProtect(raw_table, Size, old, &old);
    // (*LdrpMrdataUnprotected)--;
  }
#endif // __FULL_COUNT__
  return TRUE;
}
#endif // _M_IX86

BOOLEAN WINAPI ApplyInjectDllSEH(
  __in PVOID NtDll,
  __in PVOID DllBase) {
  NtDll, DllBase;
  // 暂时不提供外部调用，所以通过宏隔离即可
#ifdef _M_X64
  // 64位下貌似存在所有image放在低地址空间的特性
//  if (((ULONG_PTR)NtDll | (ULONG_PTR)DllBase) & 0xffffffff00000000ULL) {
    auto dir = GetImageDataDirectoryArray(DllBase);
    if (!dir) return FALSE;

    if (dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == 0) return FALSE;

    auto FunctionTable = RVA_DECODE(PRUNTIME_FUNCTION,
      DllBase,
      dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

    return RtlAddFunctionTable(FunctionTable, dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION), (DWORD64)DllBase);
//  }
#elif _M_IX86
  return ApplyInjectDllSEHInternal(NtDll, DllBase);
#endif // _M_X64
}

BOOLEAN WINAPI CancelInjectDllSEH(
  __in PVOID NtDll,
  __in PVOID DllBase) {
  NtDll, DllBase;
#ifdef _M_X64
//  if (((ULONG_PTR)NtDll | (ULONG_PTR)DllBase) & 0xffffffff00000000ULL) {
    auto dir = GetImageDataDirectoryArray(DllBase);
    if (!dir) return FALSE;

    if (dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == 0) return FALSE;

    auto FunctionTable = RVA_DECODE(PRUNTIME_FUNCTION,
      DllBase,
      dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

    return RtlDeleteFunctionTable(FunctionTable);
//  }
#elif _M_IX86
  return CancelInjectDllSEHInternal(NtDll, DllBase);
#endif // _M_X64
}
#endif
