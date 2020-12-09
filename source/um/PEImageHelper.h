#ifndef __PE_IMAGE_HELPER_H__
#define __PE_IMAGE_HELPER_H__

#ifdef _M_X64
#define SYMBOL_ANY(name)        _##name
#define IMPORT_DESC(name)       __IMPORT_DESCRIPTOR_##name
#define IMPORT_PROC(name)       __imp_##name
#else
#define SYMBOL_ANY(name)        __##name
#define IMPORT_DESC(name)       _IMPORT_DESCRIPTOR_##name
#define IMPORT_PROC(name)       _imp__##name
#endif // _M_X64

#define DEF_SYMBOL_ANY(type, name)    EXTERN_C type SYMBOL_ANY(name)

#define DEF_IMPORT_DESC(name)   EXTERN_C IMAGE_IMPORT_DESCRIPTOR IMPORT_DESC(name)
#define DEF_IMPORT_PROC(name)   EXTERN_C decltype(name) IMPORT_PROC(name)


#define RVA_DECODE(type, base, offset)    ((type)((CHAR*)(base) + (offset)))

#define IMPORT_PROC_NAME(base, name)      RVA_DECODE(PIMAGE_IMPORT_BY_NAME, (base), *(PULONG_PTR)IMPORT_PROC(name))->Name

#define IMPORT_DESC_NAME(base, name)      RVA_DECODE(CONST CHAR*, (base), IMPORT_DESC(name).Name)
#ifndef __ONLY_MACRO__

BOOLEAN StringEqual(PCSTR Str1, PCSTR Str2, BOOLEAN CaseSensitive);

PVOID GetProcAddressUser(CONST VOID* ModuleBaseAddress, PCSTR ProcName);

PVOID FoundImageFileBaseAddress(CONST VOID* AddressInImage, PCSTR DllName = nullptr);

PVOID GetDllBaseAddress(CONST VOID* NtdllBaseAddress, CONST VOID* GetDllBaseAddress, CONST VOID* RawNameInBaseAddress, CONST CHAR* Name);

PVOID GetKernel32DllBaseAddress(CONST VOID* ProcessSectionBaseAddress, PCSTR Kernel32Dll);

VOID RelocLibraryRelocEntry(__in CONST VOID* Kernel32,
  __in CONST VOID* DllBase, __in CONST VOID* RawDllBase,
  __in ULONG_PTR Diff);

VOID FreeLibraryImportEntry(__in PVOID DllBase);

BOOLEAN WINAPI RelocLibraryImportEntry(
  __in PVOID Kernel32,
  __in PVOID DllBase);

BOOLEAN WINAPI InitializeDataSection(
  __in PVOID DllBase);

BOOLEAN WINAPI ApplyInjectDllSEH(
  __in PVOID NtDll,
  __in PVOID DllBase);

BOOLEAN WINAPI CancelInjectDllSEH(
  __in PVOID NtDll,
  __in PVOID DllBase);

#endif // !__ONLY_MACRO__

#endif // !__PE_IMAGE_HELPER_H__