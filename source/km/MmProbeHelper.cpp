#include <ntddk.h>
#include <Wdm.h>
#include "log.h"

BOOLEAN MmProbeForRead(
  _In_ PVOID  Address,
  _In_ SIZE_T Length,
  _In_ ULONG  Alignment,
  _In_ BOOLEAN Kernel) {
  if (Kernel && Address >= MM_SYSTEM_RANGE_START) {
    Length += (Alignment - 1);
    Length &= (ULONG)(~(Alignment - 1));
    Length += (PAGE_SIZE - 1);
    Length &= ~(PAGE_SIZE - 1);

    for (ULONG i = 0; i < Length; i += PAGE_SIZE) {
      if (!MmIsAddressValid((CHAR*)Address + i)) return FALSE;
    }
    return TRUE;
  }

  if (Address >= MM_SYSTEM_RANGE_START) return TRUE;
  ASSERT(Kernel == FALSE);

  BOOLEAN bl = FALSE;
  __try {
    ProbeForRead(Address, Length, Alignment);
    bl = TRUE;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    Log("ProbeForRead Failed! %p, %d, %d", Address, Length, Alignment);
    ASSERT(0);
  }
  return bl;
}

BOOLEAN MmProbeForWrite(
  _In_ PVOID  Address,
  _In_ SIZE_T Length,
  _In_ ULONG  Alignment,
  _In_ BOOLEAN Kernel) {
  if (Kernel && Address >= MM_SYSTEM_RANGE_START) {
    Length += (Alignment - 1);
    Length &= (ULONG)(~(Alignment - 1));
    Length += (PAGE_SIZE - 1);
    Length &= ~(PAGE_SIZE - 1);

    for (ULONG i = 0; i < Length; i += PAGE_SIZE) {
      if (!MmIsAddressValid((CHAR*)Address + i)) return FALSE;
    }
    return TRUE;
  }

  if (Address >= MM_SYSTEM_RANGE_START) return TRUE;
  ASSERT(Kernel == FALSE);

  BOOLEAN bl = FALSE;
  __try {
    ProbeForWrite(Address, Length, Alignment);
    bl = TRUE;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    Log("ProbeForWrite Failed! %p, %d, %d", Address, Length, Alignment);
    ASSERT(0);
  }
  return bl;
}
