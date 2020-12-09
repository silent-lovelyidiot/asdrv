#include <ntifs.h>

#include <ntddk.h>
#include <Ntstrsafe.h>
#include <minwindef.h>
#include <intrin.h>

#include <ntimage.h>

#include "MmProbeHelper.h"
#include "macro.h"

#include "UndocumentedApi.h"

#include "log.h"

#include "DllInject.h"

extern "C" POBJECT_TYPE *MmSectionObjectType;

#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct _POOL_HEADER {
  union {
    struct {
#ifdef _M_X64
      ULONG PreviousSize : 8;
      ULONG PoolIndex : 8;
      ULONG BlockSize : 8;
      ULONG PoolType : 8;
#else
      USHORT PreviousSize : 9;
      USHORT PoolIndex : 7;
      USHORT BlockSize : 9;
      USHORT PoolType : 7;
#endif // _M_X64
    };
    ULONG Ulong1;                       // used for InterlockedCompareExchange required by Alpha
  };
#ifdef _M_X64
  ULONG PoolTag;
#endif // _M_X64
  union {
#ifdef _M_X64
    PEPROCESS ProcessBilled;
#else
    ULONG PoolTag;
#endif // _M_X64
    struct {
      USHORT AllocatorBackTraceIndex;
      USHORT PoolTagHash;
    } NoUsed;
  };
} POOL_HEADER, *PPOOL_HEADER;
#pragma warning(pop)

constexpr ULONG_PTR BlockSizeMultiple = sizeof(ULONG_PTR) * 2;

#ifdef _M_X64
static_assert(sizeof(POOL_HEADER) == 0x10, "");
#else
static_assert(sizeof(POOL_HEADER) == 0x08, "");
#endif // _M_X64
typedef struct _OBJECT_HEADER {
  ULONG_PTR       PointerCount;
  union {
    ULONG_PTR     HandleCount;
    PVOID         NextToFree;
  };

  EX_PUSH_LOCK    Lock;
  UCHAR           TypeIndex;
  UCHAR           TraceFlags;
  UCHAR           InfoMask;
  UCHAR           Flags;

  union {
    PVOID         ObjectCreateInfo;
    PVOID         QuotaBlockCharged;
  };
  PVOID           SecurityDescriptor;
  _QUAD           Body;
} OBJECT_HEADER, *POBJECT_HEADER;

#ifdef _M_X64
static_assert(FIELD_OFFSET(OBJECT_HEADER, Body) == 0x30, "");
#else
static_assert(FIELD_OFFSET(OBJECT_HEADER, Body) == 0x18, "");
#endif // _M_X64

PPOOL_HEADER GetPoolBlockByObjectPointer(PVOID ObjectPointer, ULONG PoolTag) {
  if ((ULONG_PTR)ObjectPointer & (sizeof(ULONG_PTR) - 1)) return nullptr;
  PULONG_PTR Ptr = (PULONG_PTR)((ULONG_PTR)ObjectPointer & ~(BlockSizeMultiple - 1));

  int offset = -24;
  if (((ULONG_PTR)&Ptr[offset] & (PAGE_SIZE - 1)) > ((ULONG_PTR)Ptr & (PAGE_SIZE - 1))) {
    offset = 0 - (((ULONG_PTR)Ptr & (PAGE_SIZE - 1)) / sizeof(ULONG_PTR));
    ASSERT(((ULONG_PTR)&Ptr[offset] & (PAGE_SIZE - 1)) == 0);
  }

  if (!MmProbeForReadKernel(&Ptr[offset], -offset * sizeof(ULONG_PTR), BlockSizeMultiple)) {
    ASSERT(0);
    return nullptr;
  }

  PPOOL_HEADER PoolHeader;
  for (int i = 0 - (int)((BlockSizeMultiple / sizeof(ULONG_PTR))); i >= offset; i -= BlockSizeMultiple / sizeof(ULONG_PTR)) {
    PoolHeader = (PPOOL_HEADER)&Ptr[i];
    if (PoolTag != (PoolHeader->PoolTag & 0x7fffffff)) continue;
    if (!MmProbeForWriteKernel(PoolHeader, PoolHeader->BlockSize * BlockSizeMultiple, BlockSizeMultiple)) {
      ASSERT(0);
      continue;
    }
    return PoolHeader;
  }

  return nullptr;
}

PVOID SearchSectionInfoOnStack(PVOID Info, SIZE_T Length) {
  PULONG_PTR r = (PULONG_PTR)_AddressOfReturnAddress();

  PVOID Initialize = IoGetInitialStack();
  LONG_PTR ToReadLength = (ULONG_PTR)Initialize - (ULONG_PTR)r - Length;
  if (!MmProbeForReadKernel(r, ToReadLength, sizeof(ULONG_PTR))) return nullptr;
  ToReadLength /= sizeof(ULONG_PTR);
  for (LONG_PTR i = ToReadLength; i >= 0; i--) {
    if (&r[i] == Info) break;
    if (r[i] != ((PULONG_PTR)Info)[0]) continue;
    if (memcmp(&r[i], Info, Length) == 0)
      return &r[i];
  }

  return nullptr;
}

inline BOOLEAN IsLikeKernelHandle(HANDLE Handle) {
  ULONG_PTR h = (ULONG_PTR)Handle;

  if ((h & 3)) return FALSE;
#ifdef _M_X64
  BOOLEAN bl = (h & 0xFFFFFFFF8FFF0000ULL) == 0xFFFFFFFF80000000ULL && h <= 0xFFFFFFFFFFFFFFFDULL;
#else
  BOOLEAN bl = (h & 0x8FFF0000) == 0x80000000 && h != -2 && h != -1;
#endif // _M_X64
  return bl;
}

inline BOOLEAN IsPointerOnStack(PVOID Pointer, PVOID Initialize) {
  ULONG_PTR Limit = ((ULONG_PTR)_AddressOfReturnAddress()) & ~(PAGE_SIZE - 1);
  ULONG_PTR Base = (((ULONG_PTR)Initialize) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

  return Limit <= (ULONG_PTR)Pointer && (ULONG_PTR)Pointer < Base;
}

inline BOOLEAN IsLikeKernelPointerInPool(PVOID Pointer, PVOID Initialize) {
  if (Pointer >= MM_SYSTEM_RANGE_START && !((ULONG_PTR)Pointer & (sizeof(ULONG_PTR) - 1))
    && !IsPointerOnStack(Pointer, Initialize)) {
    return TRUE;
  }

  return FALSE;
}

PVOID* GetProcessBaseSectionObject(PEPROCESS Process) {
  static ULONG_PTR offset = 0;

  if (offset) {
    return (PVOID*)((CHAR*)Process + offset);
  }

  PVOID BaseAddress = PsGetProcessSectionBaseAddress(Process);

  PPOOL_HEADER Header = GetPoolBlockByObjectPointer(Process, 'corP');
  if (!Header) return nullptr;

  for (ULONG_PTR i = 1; i < (Header->BlockSize * BlockSizeMultiple - ((ULONG_PTR)Process - (ULONG_PTR)Header)) / sizeof(PVOID); i++) {
    if (((PVOID*)Process)[i] == BaseAddress) {
      offset = (i - 1) * sizeof(PVOID);
      return &((PVOID*)Process)[i - 1];
    }
  }
  ASSERT(0);
  return nullptr;
}

PVOID* SearchIncertainSectionObjectOnStack(PVOID Initialize, ULONG_PTR Length,
  PCUNICODE_STRING* TargetProcessFullPath) {
  PULONG_PTR Low = (PULONG_PTR)((ULONG_PTR)Initialize - Length);

  if (!MmProbeForReadKernel((PVOID)Low, Length, sizeof(ULONG_PTR))) {
    ASSERT(0);
    return nullptr;
  }
  Length /= sizeof(ULONG_PTR);
  // FileHandle FileObject
  // SectionHandle IFEOKeyHandle
  // SectionObject UserParameter
  // Unknown Unknown
  // FileNtNameUnicodeString
  for (auto i = Length - 1; i >= 10; i--) {
    if (Low[i + 3] == 0
      && Low[i + 6] == Low[i + 7]
      && Low[i + 6] == 0
      && IsLikeKernelHandle((HANDLE)Low[i])
      && IsLikeKernelHandle((HANDLE)Low[i + 2])
      && IsLikeKernelPointerInPool((PVOID)Low[i + 1], Initialize)
      && IsLikeKernelPointerInPool((PVOID)Low[i + 4], Initialize)) {
      // UNICODE_STRING ¶ÔÆë
      for (ULONG ii = 8; ii <= 9; ii++) {
        ULONG_PTR PtrAlign = (ULONG_PTR)&Low[i + ii];
        if (((USHORT*)PtrAlign)[0] == ((USHORT*)PtrAlign)[1] && ((USHORT*)PtrAlign)[0]
          && IsLikeKernelPointerInPool((PVOID)(((PULONG_PTR)PtrAlign)[1]), Initialize)) {
          Log("UserParameter %d, %p, %p", ii, &Low[i + 5], (PVOID)Low[i + 5]);
          if (TargetProcessFullPath) {
            *TargetProcessFullPath = (PCUNICODE_STRING)PtrAlign;
          }
          return (PVOID*)&Low[i + 4];
        }
      }
    }
  }
  return nullptr;
}

#ifdef _M_X64
constexpr size_t RealPointerCountMask = 0x8000;
#else
constexpr size_t RealPointerCountMask = 0x0020;
#endif // _M_X64


#define REAL_POINTER_COUNT(PointerCount)  ((PointerCount & ~RealPointerCountMask) + !!(PointerCount & RealPointerCountMask))

BOOLEAN VerifyObjectInPool(PVOID CertainObject, ULONG PoolTag, ULONG HandleCount, ULONG PointerCount, PVOID IncertainObject) {
  PPOOL_HEADER CertainObjectPoolHeader = GetPoolBlockByObjectPointer(CertainObject, PoolTag);
  ASSERT(CertainObjectPoolHeader);
  if (!CertainObjectPoolHeader) {
    return FALSE;
  }

  POBJECT_HEADER CertainObjectObjectHeader = CONTAINING_RECORD(CertainObject, OBJECT_HEADER, Body);
  Log("CertainObject %d, %d", REAL_POINTER_COUNT(CertainObjectObjectHeader->PointerCount), CertainObjectObjectHeader->HandleCount);

  if (REAL_POINTER_COUNT(CertainObjectObjectHeader->PointerCount) != PointerCount
    || CertainObjectObjectHeader->HandleCount != HandleCount) {
    return FALSE;
  }

  ULONG_PTR Offset = (ULONG_PTR)CertainObject - (ULONG_PTR)CertainObjectPoolHeader;
  PPOOL_HEADER IncertainObjectPoolHeader = (PPOOL_HEADER)((ULONG_PTR)IncertainObject - Offset);
  if (!MmProbeForWriteKernel(IncertainObjectPoolHeader, CertainObjectPoolHeader->BlockSize * BlockSizeMultiple, BlockSizeMultiple))
    return FALSE;

  if (CertainObjectPoolHeader->BlockSize != IncertainObjectPoolHeader->BlockSize
    || CertainObjectPoolHeader->PoolTag != IncertainObjectPoolHeader->PoolTag) {
    return FALSE;
  }

  POBJECT_HEADER IncertainObjectObjectHeader = CONTAINING_RECORD(IncertainObject, OBJECT_HEADER, Body);
  return CertainObjectObjectHeader->InfoMask == IncertainObjectObjectHeader->InfoMask;
}

BOOLEAN SwapObjectInPoolByTag(PVOID Object1, PVOID Object2, ULONG PoolTag) {
  Log("Swap Object %p, %p", Object1, Object2);
  PPOOL_HEADER PoolHeader1 = GetPoolBlockByObjectPointer(Object1, PoolTag);
  PPOOL_HEADER PoolHeader2 = GetPoolBlockByObjectPointer(Object2, PoolTag);

  if (!PoolHeader1 || !PoolHeader2) {
    return FALSE;
  }

#ifdef DBG
  POBJECT_HEADER ObjectHeader1 = CONTAINING_RECORD(Object1, OBJECT_HEADER, Body);
  POBJECT_HEADER ObjectHeader2 = CONTAINING_RECORD(Object2, OBJECT_HEADER, Body);

  Log("before swap raw %d, %d => new %d, %d", REAL_POINTER_COUNT(ObjectHeader1->PointerCount), ObjectHeader1->HandleCount,
    REAL_POINTER_COUNT(ObjectHeader2->PointerCount), ObjectHeader2->HandleCount);
#endif // DBG


  UCHAR Buffer[0x110];
  ULONG Length = (ULONG)(PoolHeader1->BlockSize * BlockSizeMultiple - ((CHAR*)Object1 - (CHAR*)PoolHeader1));
#ifdef DBG
  ULONG LengthVerify = (ULONG)(PoolHeader2->BlockSize * BlockSizeMultiple - ((CHAR*)Object2 - (CHAR*)PoolHeader2));
  ASSERT(Length == LengthVerify);
#endif // DBG
  if (Length > sizeof(Buffer)) {
    ASSERT(0);
    return FALSE;
  }

  RtlMoveMemory(Buffer, Object1, Length);
  RtlMoveMemory(Object1, Object2, Length);
  RtlMoveMemory(Object2, Buffer, Length);

  //ObjectHeader1->TypeIndex ^= ObjectHeader2->TypeIndex;
  //ObjectHeader2->TypeIndex ^= ObjectHeader1->TypeIndex;
  //ObjectHeader1->TypeIndex ^= ObjectHeader2->TypeIndex;

  //ObjectHeader2->PointerCount ^= ObjectHeader1->PointerCount;
  //ObjectHeader1->PointerCount ^= ObjectHeader2->PointerCount;
  //ObjectHeader2->PointerCount ^= ObjectHeader1->PointerCount;

  //ObjectHeader2->HandleCount ^= ObjectHeader1->HandleCount;
  //ObjectHeader1->HandleCount ^= ObjectHeader2->HandleCount;
  //ObjectHeader2->HandleCount ^= ObjectHeader1->HandleCount;

  Log("behand swap raw %d, %d => new %d, %d", REAL_POINTER_COUNT(ObjectHeader1->PointerCount), ObjectHeader1->HandleCount,
    REAL_POINTER_COUNT(ObjectHeader2->PointerCount), ObjectHeader2->HandleCount);
  return TRUE;
}

#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct _SECTION_IMAGE_INFORMATION {
  PVOID       TransferAddress;
  ULONG       ZeroBits;
  ULONG_PTR   MaximumStackSize;
  ULONG_PTR   CommittedStackSize;
  ULONG       SubSystemType;
  USHORT      SubSystemMinorVersion;
  USHORT      SubSystemMajorVersion;
  union {
    ULONG     SubSystemVersion;
    struct {
      USHORT  MajorOperatingSystemVersion;
      USHORT  MinorOperatingSystemVersion;
    };
  };
  union {
    ULONG     OperatingSystemVersion;
      struct {
      USHORT  ImageCharacteristics;
      USHORT  DllCharacteristics;
    };
  };
  USHORT      Machine;
  UCHAR       ImageContainsCode;
  union {
    UCHAR     ImageFlags;
    struct {
      UCHAR   ComPlusNativeReady : 1;
      UCHAR   ComPlusILOnly : 1;
      UCHAR   ImageDynamicallyRelocated : 1;
      UCHAR   ImageMappedFlat : 1;
      UCHAR   BaseBelow4gb : 1;
      UCHAR   ComPlusPrefer32bit : 1;
      UCHAR   Reserved : 2;
    };
  };
  ULONG       LoaderFlags;
  ULONG       ImageFileSize;
  ULONG       CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

#ifdef _M_X64
static_assert(FIELD_OFFSET(SECTION_IMAGE_INFORMATION, Machine) == 0x30, "");
#else
static_assert(FIELD_OFFSET(SECTION_IMAGE_INFORMATION, Machine) == 0x20, "");
#endif // _M_X64
#pragma warning(pop)

typedef BOOLEAN (*IsRedirectNtCreateUserProcessCallback)(PCUNICODE_STRING TargetProcessFullPath, ULONGLONG ParentProcessHash);

BOOLEAN RedirectNtCreateUserProcess(
  IsRedirectNtCreateUserProcessCallback Callback,
  ULONGLONG ParentProcessHash,
  PVOID* FinalTargetSectionObject,
  HANDLE ImageFileHandle86
#ifdef _M_X64
  , HANDLE ImageFileHandle64
#endif // _M_X64
) {
  NTSTATUS st = STATUS_SUCCESS;
  BOOLEAN bl = FALSE;

  if (KeGetCurrentIrql() != PASSIVE_LEVEL) return bl;

  constexpr ULONG SectionObjectPoolTag = 'tceS';
  PCUNICODE_STRING TargetProcessFullPath = nullptr;

  PVOID* TargetSectionObjectPointer = SearchIncertainSectionObjectOnStack(IoGetInitialStack(), PAGE_SIZE, &TargetProcessFullPath);
  if (!TargetSectionObjectPointer || !(*TargetSectionObjectPointer)) return bl;

  if (Callback) {
    if (!MmProbeForReadKernel(TargetProcessFullPath->Buffer, TargetProcessFullPath->Length, sizeof(wchar_t))) {
      return FALSE;
    }
    Log("Target Process Full Path %wZ", TargetProcessFullPath);
    if (!Callback(TargetProcessFullPath, ParentProcessHash)) {
      return FALSE;
    }
  }
  PVOID TargetSectionObject = *TargetSectionObjectPointer;
  HANDLE ImageFileHandle = ImageFileHandle86;

  PVOID ImageSectionObject = nullptr;
  HANDLE ImageSectionHandle = nullptr;

#ifdef _M_X64
  {
    PVOID* IncertainSectionObject = GetProcessBaseSectionObject(IoGetCurrentProcess());
    if (!IncertainSectionObject || !*IncertainSectionObject) {
      ASSERT(0);
      return FALSE;
    }

    PPOOL_HEADER Header = GetPoolBlockByObjectPointer(*IncertainSectionObject, SectionObjectPoolTag);
    if (!Header) {
      ASSERT(0);
      return FALSE;
    }

    if (!VerifyObjectInPool(*IncertainSectionObject, SectionObjectPoolTag, 0, 1, TargetSectionObject)) {
      ASSERT(0);
      return FALSE;
    }
  }
#else
  ImageSectionHandle = CreateInjectDllHandle(ImageFileHandle);
  if (!ImageSectionHandle) return bl;

  st = ObReferenceObjectByHandle(ImageSectionHandle, GENERIC_ALL, *MmSectionObjectType, KernelMode, &ImageSectionObject, nullptr);
  if (!NT_SUCCESS(st)) goto clean;

  if (!VerifyObjectInPool(ImageSectionObject, SectionObjectPoolTag, 1, 2, TargetSectionObject))
    goto clean;
#endif // _M_X64

  {
    POBJECT_HEADER IncertainObjectObjectHeader = CONTAINING_RECORD(TargetSectionObject, OBJECT_HEADER, Body);
    if (IncertainObjectObjectHeader->HandleCount != 1 || REAL_POINTER_COUNT(IncertainObjectObjectHeader->PointerCount) != 3)
      goto clean;
  }

  SECTION_IMAGE_INFORMATION sii;
  SIZE_T Length = 0;

  {
    HANDLE Handle = nullptr;
    st = ObOpenObjectByPointer(TargetSectionObject, OBJ_KERNEL_HANDLE, nullptr, GENERIC_ALL, *MmSectionObjectType, KernelMode, &Handle);
    if (!NT_SUCCESS(st)) goto clean;

    st = ZwQuerySection(Handle, SectionImageInformation, &sii, sizeof(sii), &Length);
    ASSERT(Length == sizeof(sii));
    ZwClose(Handle);
    if (!NT_SUCCESS(st)) goto clean;
  }
#ifdef _M_X64
  {
    if (sii.Machine == IMAGE_FILE_MACHINE_AMD64) {
      ImageFileHandle = ImageFileHandle64;
    } else if (sii.Machine != IMAGE_FILE_MACHINE_I386 && sii.Machine != IMAGE_FILE_MACHINE_HYBRID_X86) {
      ASSERT(0);
      goto clean;
    }
  }

  ImageSectionHandle = CreateInjectDllHandle(ImageFileHandle);
  if (!ImageSectionHandle) return bl;

  st = ObReferenceObjectByHandle(ImageSectionHandle, GENERIC_ALL, *MmSectionObjectType, KernelMode, &ImageSectionObject, nullptr);
  if (!NT_SUCCESS(st)) goto clean;

  if (!VerifyObjectInPool(ImageSectionObject, SectionObjectPoolTag, 1, 2, TargetSectionObject))
    goto clean;

#endif // _M_X64
  PVOID RawSectionInfo = SearchSectionInfoOnStack(&sii, Length);
  if (!RawSectionInfo) goto clean;
  st = ZwQuerySection(ImageSectionHandle, SectionImageInformation, RawSectionInfo, Length, &Length);
  if (!NT_SUCCESS(st)) goto clean;

  if (!SwapObjectInPoolByTag(TargetSectionObject, ImageSectionObject, SectionObjectPoolTag)) {
    ASSERT(0);
    RtlCopyMemory(RawSectionInfo, &sii, Length);
  } else {
    *FinalTargetSectionObject = TargetSectionObject;
    bl = TRUE;
  }
clean:
  if (ImageSectionObject) {
    ObDereferenceObject(ImageSectionObject);
  }

  if (ImageSectionHandle) {
    ZwClose(ImageSectionHandle);
  }

  return bl;
}
