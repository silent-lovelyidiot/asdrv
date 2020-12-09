#ifndef __UNMAP_VIEW_OF_SECTION_H__
#define __UNMAP_VIEW_OF_SECTION_H__

void UnmapViewOfSectionFromApc(PVOID ImageBaseAddress, PVOID AddressOfReturnAddress, PVOID UnmapViewOfSection);
void FreeVirtualMemoryFromApc(PVOID ImageBaseAddress, PVOID AddressOfReturnAddress, PVOID FreeVirtualMemory);

#endif // !__UNMAP_VIEW_OF_SECTION_H__