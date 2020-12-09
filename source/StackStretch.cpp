#include <ntdef.h>
#include <intrin.h>

#include "StackStretch.h"

#ifdef _M_IX86
__declspec(naked) ULONG_PTR __stdcall MoveStackStd(ULONG_PTR NewStack) {
  __asm {
    push ebp;
    mov ebp, esp;
    // 切换栈
    mov esp, NewStack;
    // 参数n
    // 参数n - 1
    // ...
    // 参数0
    // 调用函数
    pop eax;
    call eax;
    // 恢复栈
    mov esp, ebp;
    // 恢复ebp
    pop ebp;
    ret 4;
  }
}

DefMoveStack MoveStack = (DefMoveStack)MoveStackStd;
#else
#pragma code_seg(push)
#pragma code_seg(".text")
__declspec(allocate(".text")) UCHAR MoveStackCode[] = {
  0x55,
  0x48, 0x8b, 0xec,
  0x48, 0x8b, 0xe1,
  0x58,
  0x48, 0x8b, 0x0c, 0x24,
  0x48, 0x8b, 0x54, 0x24, 0x08,
  0x4c, 0x8b, 0x44, 0x24, 0x10,
  0x4c, 0x8b, 0x4c, 0x24, 0x18,
  0xff, 0xd0,
  0x48, 0x8b, 0xe5,
  0x5d,
  0xc3
};
#pragma code_seg(pop)

DefMoveStack MoveStack = (DefMoveStack)&MoveStackCode;
#endif // _M_IX86


