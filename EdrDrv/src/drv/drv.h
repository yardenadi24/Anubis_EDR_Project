#pragma once
#include "../commons/commons.h"

#include <ntifs.h>
#include <ntdef.h>
#include <ntimage.h>

extern "C"
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject, 
	PUNICODE_STRING RegistryPath);

VOID 
DriverUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS 
DriverInitialize();

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