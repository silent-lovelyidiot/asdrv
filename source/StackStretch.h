#ifndef __STACK_STRETCH_H__
#define __STACK_STRETCH_H__


typedef ULONG_PTR (__stdcall *DefMoveStack)(ULONG_PTR);
extern DefMoveStack MoveStack;

template<LONG N, typename T>
VOID CopyParameter(PULONG_PTR Ptr, ULONG Offset, const T& Val) {
  Ptr[Offset] = (ULONG_PTR)Val;
}

template<LONG N, typename T, typename... To>
VOID CopyParameter(PULONG_PTR Ptr, ULONG Offset, const T& Val, To... Parameter) {
  Ptr[Offset] = (ULONG_PTR)Val;
  CopyParameter<N - 1, To...>(Ptr, Offset + 1, Parameter...);
}

template<typename R, typename... T>
R StackStretch(PVOID NewStack, ULONG Size, R (*Func)(T...), T... Parameter) {
  PULONG_PTR Stack = (PULONG_PTR)((CHAR*)NewStack + Size);

  LONG Offset = -1;
  LONG N = sizeof...(Parameter);

  Offset = -N;
  CopyParameter<sizeof...(Parameter), T...>(&Stack[Offset], 0, Parameter...);

  Offset -= 1;
  Stack[Offset] = (ULONG_PTR)(PULONG_PTR)Func;

  return (R)MoveStack((ULONG_PTR)&Stack[Offset]);
}

#endif // !__STACK_STRETCH_H__