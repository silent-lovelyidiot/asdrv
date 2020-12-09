#include <Windows.h>
#include <intrin.h>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

#pragma comment(lib, "ntdll.lib")

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

#pragma inline_depth(0)

// ULONG_PTR RawReturnAddress;

#ifdef _M_X64
#pragma code_seg(".text")
// OR  @RCX, 0FFFFFFFFFFFFFFFFh
// MOV @RDX, QWORD PTR [rsp]
// SUB @RSP, 18h
// RET
__declspec(allocate(".text")) UCHAR StackBalanceCodeForUnmap[] = {
  0x48, 0x83, 0xc9, 0xff,
  0x48, 0x8B, 0x14, 0x24,
  0x48, 0x83, 0xec, 0x18,
  0xc3,
};

// ret to raw proc address
// ret to NtUnmapViewOfSection

void UnmapViewOfSectionFromApcInternalForUnmap() {
  PULONG_PTR ra = (PULONG_PTR)_AddressOfReturnAddress();
  ra[0] = (ULONG_PTR)StackBalanceCodeForUnmap;

  ra[-1] = ra[-4];
  ra[-2] = ra[-5];// (ULONG_PTR)NtUnmapViewOfSection;

  // ZwUnmapViewOfSection BaseAddress
  ra[1] = (ULONG_PTR)&__ImageBase;
}

// 
void UnmapViewOfSectionFromApc(PVOID, PVOID AddressOfReturnAddress, PVOID UnmapViewOfSection) {
  PULONG_PTR ra = (PULONG_PTR)AddressOfReturnAddress;

  ra[-3] = ra[0];
  ra[-4] = (ULONG_PTR)UnmapViewOfSection;
  ra[0] = (ULONG_PTR)UnmapViewOfSectionFromApcInternalForUnmap;
}

// 需要无hook保证
// OR  @RCX, 0FFFFFFFFFFFFFFFFh
// MOV @R9D, 0x8000
// MOV @RDX, @RSP
// PUSH 0
// MOV @R8,  @RSP
// SUB @RSP, 10h
// RET
__declspec(allocate(".text")) UCHAR StackBalanceCodeForFree[] = {
  0x48, 0x83, 0xc9, 0xff,
  0x41, 0xb9, 0x00, 0x80, 0x00, 0x00,
  0x48, 0x8b, 0xd4,
  0x6a, 0x00,
  0x4c, 0x8b, 0xc4,
  0x48, 0x83, 0xec, 0x10,
  0xc3,
};

// apc是包含3个参数的
void FreeVirtualMemoryFromApcInternalForFree() {
  PULONG_PTR ra = (PULONG_PTR)_AddressOfReturnAddress();
  ra[2] = 0;
  ra[1] = (ULONG_PTR)&__ImageBase;
  ra[0] = (ULONG_PTR)StackBalanceCodeForFree;

  ra[-1] = ra[-4];// RawReturnAddress;
  ra[-2] = ra[-5];// (ULONG_PTR)NtFreeVirtualMemory;
}

void FreeVirtualMemoryFromApc(PVOID, PVOID AddressOfReturnAddress, PVOID FreeVirtualMemory) {
  PULONG_PTR ra = (PULONG_PTR)AddressOfReturnAddress;

  //RawReturnAddress = ra[0];
  ra[-3] = ra[0];
  ra[-4] = (ULONG_PTR)FreeVirtualMemory;
  ra[0] = (ULONG_PTR)FreeVirtualMemoryFromApcInternalForFree;
}

#else

__declspec(naked) void StackBalanceCodeForUnmap() {
  __asm {
    sub esp, 0x0c;
    mov eax, 0xffffffff;
    xchg eax, [esp + 4];
    jmp eax;
  }
}

// APC 有3个参数
void UnmapViewOfSectionFromApc(PVOID ImageBaseAddress, PVOID AddressOfReturnAddress, PVOID UnmapViewOfSection) {
  PULONG_PTR ra = (PULONG_PTR)AddressOfReturnAddress;
  //RawReturnAddress = ra[0];
  ra[3] = (ULONG_PTR)ImageBaseAddress;
  ra[2] = (ULONG_PTR)UnmapViewOfSection;
  ra[1] = ra[0];
  ra[0] = (ULONG_PTR)ImageBaseAddress + ((ULONG_PTR)&StackBalanceCodeForUnmap - (ULONG_PTR)&__ImageBase);
}


__declspec(naked) void StackBalanceCodeForFree() {
  __asm {
    mov edx, 0x00008000;
    xchg [esp - 4], edx;

    lea eax, [esp - 0x1c];
    sub esp, 8;
    xchg eax, [esp];

    mov ecx, eax; // FreeVirtualMemory

    lea eax, [esp - 0x18];
    sub esp, 4;
    xchg eax, [esp];

    push -1;
    push eax; // ret address

    push 0;
    push 0;
    push edx;

    call balance;

    jmp ecx;
balance:
    ret 12;
  }
}

void FreeVirtualMemoryFromApc(PVOID ImageBaseAddress, PVOID AddressOfReturnAddress, PVOID FreeVirtualMemory) {
  PULONG_PTR ra = (PULONG_PTR)AddressOfReturnAddress;
  ra[3] = (ULONG_PTR)ImageBaseAddress;
  ra[2] = (ULONG_PTR)FreeVirtualMemory;
  ra[1] = ra[0];
  ra[0] = (ULONG_PTR)ImageBaseAddress + ((ULONG_PTR)&StackBalanceCodeForFree - (ULONG_PTR)&__ImageBase);
}

#endif // _M_X64