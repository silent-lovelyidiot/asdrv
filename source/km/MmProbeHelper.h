#ifndef __MM_PROBE_HELPER_H__
#define __MM_PROBE_HELPER_H__

BOOLEAN MmProbeForRead(
  _In_ PVOID  Address,
  _In_ SIZE_T Length,
  _In_ ULONG  Alignment,
  _In_ BOOLEAN Kernel);

BOOLEAN MmProbeForWrite(
  _In_ PVOID  Address,
  _In_ SIZE_T Length,
  _In_ ULONG  Alignment,
  _In_ BOOLEAN Kernel);

#define MmProbeForReadKernel(Address, Length, Aligment)     MmProbeForRead(Address, Length, Aligment, TRUE)
#define MmProbeForWriteKernel(Address, Length, Aligment)    MmProbeForWrite(Address, Length, Aligment, TRUE)

#define MmProbeForReadUser(Address, Length, Aligment)       MmProbeForRead(Address, Length, Aligment, FALSE)
#define MmProbeForWriteUser(Address, Length, Aligment)       MmProbeForWrite(Address, Length, Aligment, FALSE)

#endif // !__MM_PROBE_HELPER_H__