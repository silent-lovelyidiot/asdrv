#ifndef __IMAGE_HELPER_H__
#define __IMAGE_HELPER_H__

#define RVA_DECODE(type, base, offset)    ((type)((CHAR*)(base) + (offset)))

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

typedef struct _IMAGE_HELPER_CONTEXT* PIMAGE_HELPER_CONTEXT;

PIMAGE_HELPER_CONTEXT InitializeImageHelperContext(PVOID ImageBaseAddress);

PVOID FoundImageBaseAddress(PVOID AddressInImage, PCSTR DllName);

PVOID GetImageBaseAddressDefault(PIMAGE_HELPER_CONTEXT Context);

PVOID GetImageBaseAddress(PIMAGE_HELPER_CONTEXT Context);

PCSTR GetImageInternalName(PIMAGE_HELPER_CONTEXT Context);

PVOID GetProcAddressMine(PIMAGE_HELPER_CONTEXT Context, PCSTR ProcName);

BOOLEAN RelocationImageRelocEntry(PIMAGE_HELPER_CONTEXT Context,
  PVOID Ntdll, ULONG_PTR Diff);

BOOLEAN RelocationImageImportEntry(PIMAGE_HELPER_CONTEXT Context,
  PVOID Kernel32, BOOLEAN HideFuncName);

PVOID GetCurrentProcessPeb(PIMAGE_HELPER_CONTEXT Context, PVOID Ntdll);

PVOID GetImageBaseAddressFromPeb(PIMAGE_HELPER_CONTEXT Context, PVOID Ntdll, PCSTR ImageName);

VOID FreeLibraryImportEntry(PIMAGE_HELPER_CONTEXT Context);

BOOLEAN InitializeDataSection(PIMAGE_HELPER_CONTEXT Context);

BOOLEAN WINAPI ApplyInjectDllSEH(PIMAGE_HELPER_CONTEXT Context, PVOID NtDll);

BOOLEAN WINAPI CancelInjectDllSEH(PIMAGE_HELPER_CONTEXT Context, PVOID NtDll);

#endif // !__ONLY_MACRO__
#endif // !__IMAGE_HELPER_H__
