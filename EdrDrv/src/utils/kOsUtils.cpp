#include "kOsUtils.h"

inline UINT64 getTickCount64()
{
	const ULONG64 nTime = KeQueryInterruptTime();
	return nTime / ((ULONG64)10 /*100 nano*/ * (ULONG64)1000 /*micro*/);
}


NTSTATUS
KDeviceIoControl(
	PDEVICE_OBJECT pDeviceObject,
	ULONG IoControlCode,
	PVOID pInputBuffer,
	ULONG InputBufferLength,
	PVOID pOutputBuffer,
	ULONG OutputBufferLength
)
{
	KEVENT kEvent;
	KeInitializeEvent(&kEvent, NotificationEvent, FALSE);

	IO_STATUS_BLOCK IoStatusBlock = {};

	// Build the IRP for the device I/O control request
	PIRP pIrp = IoBuildDeviceIoControlRequest(
		IoControlCode,
		pDeviceObject,
		pInputBuffer,
		InputBufferLength,
		pOutputBuffer,
		OutputBufferLength,
		FALSE,
		&kEvent,
		&IoStatusBlock);

	if (pIrp == NULL)
	{
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	// Call the driver with the IRP
	NTSTATUS Status = IoCallDriver(pDeviceObject, pIrp);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	// Wait for the I/O operation to complete
	if(Status == STATUS_PENDING)
	{
		Status = KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, NULL);
	}

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	return IoStatusBlock.Status;
}

LARGE_INTEGER
GetCurrentTimeStamp()
{
	LARGE_INTEGER ts;
	KeQuerySystemTimePrecise(&ts);
	return ts;
}