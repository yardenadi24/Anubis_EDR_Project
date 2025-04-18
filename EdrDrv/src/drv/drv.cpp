#include "drv.h"
#include "../process_monitor/ProcessMonitor.h"

#define DEVICE_NAME L"\\Device\\AnubisEdrDevice"
#define SYMLINK_NAME L"\\??\\AnubisEdrDevice"

PDEVICE_OBJECT g_pDeviceObject = NULL;

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pDriverObject);
    UNREFERENCED_PARAMETER(pRegistryPath);

    DbgInfo("Driver load (0x%p, %wZ)", pDriverObject, pRegistryPath);

	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(SYMLINK_NAME);


	do 
	{

		Status = IoCreateDevice(
			pDriverObject,
			0,
			&DeviceName,
			FILE_DEVICE_UNKNOWN,
			0,
			FALSE,
			&g_pDeviceObject);

		if (!NT_SUCCESS(Status))
		{
			DbgError("Failed to create device object");
			break;
		}

		g_pDeviceObject->Flags |= DO_BUFFERED_IO;

		Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("Failed creating symbolic link 0x%u\n", Status);
			break;
		}


	} while (FALSE);
	
	// Check for issues
	if (!NT_SUCCESS(Status))
	{
		if (g_pDeviceObject)
		{
			IoDeleteDevice(g_pDeviceObject);
			g_pDeviceObject = NULL;
		}

		IoDeleteSymbolicLink(&SymLinkName);

		DbgError("Failed to create device object, status: 0x%X", Status);
		
		return Status;
	}

	// Initialize the driver object
	pDriverObject->DriverExtension->AddDevice = NULL;
	pDriverObject->DriverUnload = NULL;

	// Set mj functions
	pDriverObject->DriverUnload = DriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;

    Status = DriverInitialize();

	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(g_pDeviceObject);
		IoDeleteSymbolicLink(&SymLinkName);
		DbgPrint("Failed register for process creation 0x%u\n", Status);
	}

    return Status;
}


NTSTATUS
DriverInitialize()
{
    NTSTATUS Status = STATUS_SUCCESS;
    DbgInfo("Initializing driver");
	g_pProcMonitor = InitializeProcessMonitor();
    if (!NT_SUCCESS(Status))
    {
        DbgError("Failed to initialize process monitor");
    }
    return Status;
}

NTSTATUS DispatchDeviceControl(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp
)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG IoCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	ULONG Written = 0;
	switch (IoCode)
	{
	case IOCTL_START_MONITORING:
	{
		DbgInfo("IOCTL_START_MONITORING\n");

		if (g_pProcMonitor->g_Monitor)
		{
			Status = CompleteIrp(pIrp, Status, Written);
			return Status;
		}

		g_pProcMonitor->g_Monitor = TRUE;
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_STOP_MONITORING:
	{
		DbgInfo("IOCTL_STOP_MONITORING\n");

		if (!g_pProcMonitor->g_Monitor)
		{
			Status = CompleteIrp(pIrp, Status, Written);
			return Status;
		}

		g_pProcMonitor->g_Monitor = FALSE;
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_GET_PROCESS_EVENT:
	{
		DbgInfo("IOCTL_GET_PROCESS_EVENT\n");

		if(!g_pProcMonitor->g_Monitor)
		{
			Status = CompleteIrp(pIrp, Status, Written);
			return Status;
		}

		BOOLEAN Found = FALSE;

		// Handle the IOCTL_GET_PROCESS_EVENT
		PAGENT_PROCESS_EVENT pAgentProcEvent = (PAGENT_PROCESS_EVENT)pIrp->AssociatedIrp.SystemBuffer;
		if (pAgentProcEvent == NULL)
		{
			DbgError("Invalid buffer for IOCTL_GET_PROCESS_EVENT\n");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		KeAcquireSpinLock(&g_pProcMonitor->g_ProcMonLock, &g_pProcMonitor->oldIrql);

		// Check there is available pending process event to process
		if (IsListEmpty(&g_pProcMonitor->g_ProcMonList))
		{
			DbgInfo("No pending process events\n");
			Status = STATUS_NO_MORE_ENTRIES;
			KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, g_pProcMonitor->oldIrql);
			break;
		}

		PLIST_ENTRY pEntry = g_pProcMonitor->g_ProcMonList.Flink;
		// Get first pending process event
		while (pEntry != &g_pProcMonitor->g_ProcMonList)
		{
			// Get the proc event
			PPROCESS_EVENT pProcEvent = CONTAINING_RECORD(pEntry, PROCESS_EVENT, ListEntry);

			if (pProcEvent == NULL)
			{
				DbgError("Got NULL from CONTAINING_RECORD");
				break;
			}

			// Check if this is the process we're looking for
			if (pProcEvent->ProcessState == PROCESS_PENDING)
			{
				// Copy the process event data to user buffer
				pAgentProcEvent->ProcessId = pProcEvent->ProcessId;
				RtlCopyMemory(pAgentProcEvent->ImageFileName, pProcEvent->pImageFileName, pProcEvent->cbImageFileName);
				pProcEvent->ProcessState = PROCESS_IN_PROGRESS;
				Found = TRUE;
				break;
			}

			// Move to next entry
			pEntry = pEntry->Flink;

		}

		KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, g_pProcMonitor->oldIrql);

		if (Found)
		{
			Written = sizeof(AGENT_PROCESS_EVENT);
			Status = STATUS_SUCCESS;
		}
		else
		{
			DbgInfo("No pending process events\n");
			Status = STATUS_NO_MORE_ENTRIES;
		}
		break;
	}
	case IOCTL_POST_PROCESS_VERDICT:
	{
		DbgInfo("IOCTL_POST_PROCESS_VERDICT\n");

		if (!g_pProcMonitor->g_Monitor)
		{
			Status = CompleteIrp(pIrp, Status, Written);
			return Status;
		}

		PAGENT_PROCESS_EVENT pAgentProcEvent = (PAGENT_PROCESS_EVENT)pIrp->AssociatedIrp.SystemBuffer;

		DbgInfo("Received process verdict from agent: %ws [PID: %lu]",
			pAgentProcEvent->ImageFileName,
			pAgentProcEvent->ProcessId);

		PPROCESS_EVENT pProcEvent = FindProcessSafe(pAgentProcEvent->ProcessId); // Find the process in the list

		if (pProcEvent == NULL)
		{
			DbgError("Process not found in list [PID: %lu]", pAgentProcEvent->ProcessId);
			Status = STATUS_NOT_FOUND;
			break;
		}

		// Update the process event with the verdict
		pProcEvent->AllowProcess = pAgentProcEvent->AllowProcess;
		pProcEvent->ProcessState = PROCESS_PROCESSED;

		Status = STATUS_SUCCESS;

		KeSetEvent(&pProcEvent->Event, IO_NO_INCREMENT, FALSE);
		break;
	}

	default:
	{
		DbgError("Unknown IOCTL: %lu\n", IoCode);
		Status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	}

	// Complete the IRP
	Status = CompleteIrp(pIrp, Status, Written);

	return Status;
}

NTSTATUS
CompleteIrp(
    PIRP Irp,
    NTSTATUS Status,
    ULONG Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;

    // Complete the IRP
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
DispatchCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteIrp(Irp);
}

VOID
DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
	UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(SYMLINK_NAME);
	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(g_pDeviceObject);
    UnInitializeProcessMonitor();
}