#ifndef __DLL_INJECT_H__
#define __DLL_INJECT_H__

HANDLE CreateInjectDllHandle(HANDLE RootDirectory, PCUNICODE_STRING FileName);

PVOID MapInjectDll(HANDLE Process, HANDLE SectionHandle, PSIZE_T ViewSize = nullptr);

PVOID MapInjectDllMemory(PVOID Memory, ULONG Length, PMDL* UpdateMdl);

HANDLE CreateInjectDllHandle(HANDLE FileHandle, PLARGE_INTEGER li = nullptr);

BOOLEAN CallUserApcRoutine(PVOID Base,
  KKERNEL_ROUTINE KernelApcRoutine,
  KRUNDOWN_ROUTINE RundownApcRoutine,
  ULONG Routine,
  __in_opt PVOID SystemArgument1,
  __in_opt PVOID SystemArgument2);

BOOLEAN InsertUserApcToCurrentThread(KKERNEL_ROUTINE KernelApcRoutine,
  KRUNDOWN_ROUTINE RundownApcRoutine,
  PKNORMAL_ROUTINE UserApcRoutine,
  PVOID NormalContext,
  PVOID SystemArgument1,
  PVOID SystemArgument2);

#endif // !__DLL_INJECT_H__
