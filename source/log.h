#ifndef __LOG_H__
#define __LOG_H__

#if DBG
#ifndef _NTDDK_
#define Log(fmt, ...)   do { wchar_t logbuff[512]; wsprintfW(logbuff, L"user %-27.27s\t" L##fmt L"\n", __FUNCTIONW__, __VA_ARGS__); OutputDebugStringW(logbuff);} while (0)
#else
#define Log(fmt, ...)   DbgPrintEx(DPFLTR_SE_ID, DPFLTR_TRACE_LEVEL | DPFLTR_MASK, "kernel %-26.26s\t" fmt "\n", __FUNCTION__, __VA_ARGS__)
#endif // _DLL
#else
#define Log(...)    0
#endif // DBG

#endif // !__LOG_H__