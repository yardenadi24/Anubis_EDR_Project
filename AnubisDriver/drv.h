#pragma once
#include "commons.h"

#include <ntifs.h>
#include <ntdef.h>
#include <ntimage.h>

#define DEVICE_NAME L"\\Device\\AnubisEdrDevice"
#define SYMLINK_NAME L"\\??\\AnubisEdrDevice"

extern "C"
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath);

VOID
DriverUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS
DriverInitialize(PUNICODE_STRING RegistryPath);

NTSTATUS
CompleteIrp(
	PIRP Irp,
	NTSTATUS Status = STATUS_SUCCESS,
	ULONG Information = 0);

NTSTATUS DispatchDeviceControl(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp
);

NTSTATUS
DispatchCreateClose(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp);

NTSTATUS
ProcessMonitorDispatchDeviceControl
(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp,
	ULONG IoCode,
	ULONG& written
);

NTSTATUS
FilesystemMonitorDispatchDeviceControl
(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp,
	ULONG IoCode,
	ULONG& written
);