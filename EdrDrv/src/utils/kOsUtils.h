#pragma once
#include "commons.h"

inline UINT64 getTickCount64();

NTSTATUS
KDeviceIoControl(
	PDEVICE_OBJECT pDeviceObject,
	ULONG IoControlCode,
	PVOID pInputBuffer,
	ULONG InputBufferLength,
	PVOID pOutputBuffer,
	ULONG OutputBufferLength
);

LARGE_INTEGER
GetCurrentTimeStamp();