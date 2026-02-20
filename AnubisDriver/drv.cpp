#include "drv.h"
#include <ntstrsafe.h>

#include "process_monitor.h"
#include "filesystem_monitor.h"
#include "network_monitor.h"

static PDRIVER_OBJECT g_pDriverObject = NULL;
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
		// Create device object
		g_pDriverObject = pDriverObject;
		Status = IoCreateDevice(
			pDriverObject,
			0,
			&DeviceName,
			FILE_DEVICE_UNKNOWN,
			0,
			FALSE,
			&g_pDeviceObject);
		// Check status
		if (!NT_SUCCESS(Status))
		{
			DbgError("Failed to create device object");
			break;
		}

		// Set device flags
		g_pDeviceObject->Flags |= DO_BUFFERED_IO;

		// Create symbolic link
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

	// Initialize driver 
	// In all its monitors
	Status = DriverInitialize(pRegistryPath);

	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(g_pDeviceObject);
		IoDeleteSymbolicLink(&SymLinkName);
		DbgPrint("Failed register for process creation 0x%u\n", Status);
	}

	return Status;
}

static NTSTATUS
RegisterMinifilterInstance(PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status;
	HANDLE hInstances = NULL, hDefaultInst = NULL;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING subKey, valueName, valueData;

	// Create "Instances" subkey
	WCHAR instancesPath[512];
	RtlStringCbPrintfW(instancesPath, sizeof(instancesPath), L"%wZ\\Instances", RegistryPath);
	RtlInitUnicodeString(&subKey, instancesPath);

	InitializeObjectAttributes(&oa, &subKey, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	Status = ZwCreateKey(&hInstances, KEY_ALL_ACCESS, &oa, 0, NULL, 0, NULL);
	if (!NT_SUCCESS(Status)) return Status;

	// Set "DefaultInstance" value
	RtlInitUnicodeString(&valueName, L"DefaultInstance");
	RtlInitUnicodeString(&valueData, L"AnubisEdr Instance");
	ZwSetValueKey(hInstances, &valueName, 0, REG_SZ,
		valueData.Buffer, valueData.Length + sizeof(WCHAR));

	// Create the instance subkey
	WCHAR defaultInstPath[512];
	RtlStringCbPrintfW(defaultInstPath, sizeof(defaultInstPath), L"%wZ\\Instances\\AnubisEdr Instance", RegistryPath);
	RtlInitUnicodeString(&subKey, defaultInstPath);

	InitializeObjectAttributes(&oa, &subKey, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	Status = ZwCreateKey(&hDefaultInst, KEY_ALL_ACCESS, &oa, 0, NULL, 0, NULL);
	if (!NT_SUCCESS(Status)) { ZwClose(hInstances); return Status; }

	// Set "Altitude"
	RtlInitUnicodeString(&valueName, L"Altitude");
	RtlInitUnicodeString(&valueData, FS_MONITOR_ALTITUDE);
	ZwSetValueKey(hDefaultInst, &valueName, 0, REG_SZ,
		valueData.Buffer, valueData.Length + sizeof(WCHAR));

	// Set "Flags" = 0
	RtlInitUnicodeString(&valueName, L"Flags");
	ULONG flags = 0;
	ZwSetValueKey(hDefaultInst, &valueName, 0, REG_DWORD, &flags, sizeof(ULONG));

	ZwClose(hDefaultInst);
	ZwClose(hInstances);
	return STATUS_SUCCESS;
}

NTSTATUS
DriverInitialize(PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	DbgInfo("Initializing Edr driver and its components");
	
	g_pProcMonitor = InitializeProcessMonitor();
	if (g_pProcMonitor == NULL)
	{
		DbgError("Failed to initialize process monitor");
		Status = STATUS_INSUFFICIENT_RESOURCES;
	}

	// Initialize filesystem monitor (minifilter)
	RegisterMinifilterInstance(RegistryPath);  // create keys if missing
	g_pFsMonitor = InitializeFilesystemMonitor(g_pDriverObject);
	if (g_pFsMonitor == NULL)
	{
		DbgError("Failed to initialize filesystem monitor");
		// Non-fatal: process monitor can still work without filesystem monitor
		// Log the error but continue
	}

	g_pNetMonitor = InitializeNetworkMonitor(g_pDeviceObject);
	if (g_pNetMonitor == NULL)
	{
		DbgError("Failed to initialize network monitor");
		// Non-fatal
	}

	return Status;
}

NTSTATUS DispatchDeviceControl(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG IoCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	ULONG Written = 0;
	switch (IoCode)
	{
		case IOCTL_SET_AGENT_PID:
		{
			PAGENT_PID_INFO pPidInfo = (PAGENT_PID_INFO)pIrp->AssociatedIrp.SystemBuffer;
			if (pPidInfo == NULL) { Status = STATUS_INVALID_PARAMETER; break; }
			if (g_pProcMonitor) g_pProcMonitor->g_AgentPID = (LONG)pPidInfo->ProcessId;
			if (g_pFsMonitor) g_pFsMonitor->g_AgentPID = (LONG)pPidInfo->ProcessId;
			Status = STATUS_SUCCESS;
			break;
		}
		case IOCTL_START_PROCESS_MONITORING:
		case IOCTL_STOP_PROCESS_MONITORING:
		case IOCTL_GET_PROCESS_EVENT:
		case IOCTL_POST_PROCESS_VERDICT:
			Status = ProcessMonitorDispatchDeviceControl(pDeviceObject, pIrp, IoCode, Written);
			break;
		case IOCTL_START_FS_MONITORING:
		case IOCTL_STOP_FS_MONITORING:
		case IOCTL_GET_FS_EVENT:
		case IOCTL_POST_FS_VERDICT:
			Status = FilesystemMonitorDispatchDeviceControl(pDeviceObject, pIrp, IoCode, Written);
			break;
		case IOCTL_START_NET_MONITORING:
		case IOCTL_STOP_NET_MONITORING:
		case IOCTL_GET_NET_EVENT:
			Status = NetworkMonitorDispatchDeviceControl(pDeviceObject, pIrp, IoCode, Written);
			break;
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
ProcessMonitorDispatchDeviceControl
(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp,
	ULONG IoCode,
	ULONG& Written
)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	NTSTATUS Status = STATUS_SUCCESS;

	if (g_pProcMonitor == NULL)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	switch (IoCode)
	{
	case IOCTL_START_PROCESS_MONITORING:
	{
		DbgInfo("IOCTL_START_MONITORING\n");

		if (g_pProcMonitor->g_Monitor)
		{
			return Status;
		}

		g_pProcMonitor->g_Monitor = TRUE;
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_STOP_PROCESS_MONITORING:
	{
		DbgInfo("IOCTL_STOP_MONITORING\n");

		if (!g_pProcMonitor->g_Monitor)
		{
			return Status;
		}

		g_pProcMonitor->g_Monitor = FALSE;
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_GET_PROCESS_EVENT:
	{
		DbgInfo("IOCTL_GET_PROCESS_EVENT\n");

		if (!g_pProcMonitor->g_Monitor)
		{
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
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_pProcMonitor->g_ProcMonLock, &oldIrql);

		// Check there is available pending process event to process
		if (IsListEmpty(&g_pProcMonitor->g_ProcMonList))
		{
			DbgInfo("No pending process events\n");
			Status = STATUS_NO_MORE_ENTRIES;
			KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, oldIrql);
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
				ULONG copyLen = min(pProcEvent->cbImageFileName, (MAX_PATH - 1) * sizeof(WCHAR));
				RtlCopyMemory(pAgentProcEvent->ImageFileName, pProcEvent->pImageFileName, copyLen);
				pAgentProcEvent->ImageFileName[copyLen / sizeof(WCHAR)] = L'\0';
				pProcEvent->ProcessState = PROCESS_IN_PROGRESS;
				Found = TRUE;
				break;
			}

			// Move to next entry
			pEntry = pEntry->Flink;

		}

		KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, oldIrql);

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
			return Status;
		}

		PAGENT_PROCESS_EVENT pAgentProcEvent = (PAGENT_PROCESS_EVENT)pIrp->AssociatedIrp.SystemBuffer;

		DbgInfo("Received process verdict from agent: %ws [PID: %lu]",
			pAgentProcEvent->ImageFileName,
			pAgentProcEvent->ProcessId);

		KIRQL oldIrql;
		KeAcquireSpinLock(&g_pProcMonitor->g_ProcMonLock, &oldIrql);
		PPROCESS_EVENT pProcEvent = FindProcessUnSafe(pAgentProcEvent->ProcessId);
		if (pProcEvent == NULL) 
		{
			KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, oldIrql);
			Status = STATUS_NOT_FOUND;
			break;
		}
		pProcEvent->AllowProcess = pAgentProcEvent->AllowProcess;
		pProcEvent->ProcessState = PROCESS_PROCESSED;
		KeSetEvent(&pProcEvent->Event, IO_NO_INCREMENT, FALSE);
		KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, oldIrql);
		Status = STATUS_SUCCESS;
		break;
	}
	}
	return Status;
}

NTSTATUS
FilesystemMonitorDispatchDeviceControl
(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp,
	ULONG IoCode,
	ULONG& Written
)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	NTSTATUS Status = STATUS_SUCCESS;

	if (g_pFsMonitor == NULL)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	switch (IoCode)
	{
	case IOCTL_START_FS_MONITORING:
	{
		DbgInfo("IOCTL_START_FS_MONITORING");

		if (g_pFsMonitor->g_Monitor)
		{
			return Status;
		}

		g_pFsMonitor->g_Monitor = TRUE;
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_STOP_FS_MONITORING:
	{
		DbgInfo("IOCTL_STOP_FS_MONITORING");

		if (!g_pFsMonitor->g_Monitor)
		{
			return Status;
		}

		g_pFsMonitor->g_Monitor = FALSE;
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_GET_FS_EVENT:
	{
		DbgInfo("IOCTL_GET_FS_EVENT");

		if (!g_pFsMonitor->g_Monitor)
		{
			Status = STATUS_NO_MORE_ENTRIES;
			break;
		}

		BOOLEAN Found = FALSE;

		PAGENT_FS_EVENT pAgentFsEvent = (PAGENT_FS_EVENT)pIrp->AssociatedIrp.SystemBuffer;
		if (pAgentFsEvent == NULL)
		{
			DbgError("Invalid buffer for IOCTL_GET_FS_EVENT");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_pFsMonitor->g_FsMonLock, &oldIrql);
		if (IsListEmpty(&g_pFsMonitor->g_FsMonList))
		{
			DbgInfo("No pending FS events");
			Status = STATUS_NO_MORE_ENTRIES;
			KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);
			break;
		}

		PLIST_ENTRY pEntry = g_pFsMonitor->g_FsMonList.Flink;

		while (pEntry != &g_pFsMonitor->g_FsMonList)
		{
			PFS_EVENT pFsEvent = CONTAINING_RECORD(pEntry, FS_EVENT, ListEntry);

			if (pFsEvent == NULL)
			{
				DbgError("Got NULL from CONTAINING_RECORD for FS event");
				break;
			}

			if (pFsEvent->EventState == FS_EVENT_PENDING)
			{
				// Copy event data to user buffer
				RtlZeroMemory(pAgentFsEvent, sizeof(AGENT_FS_EVENT));

				pAgentFsEvent->ProcessId = pFsEvent->ProcessId;
				pAgentFsEvent->Operation = pFsEvent->Operation;
				pAgentFsEvent->FileSize = pFsEvent->FileSize;
				pAgentFsEvent->IsDirectory = pFsEvent->IsDirectory;
				pAgentFsEvent->AllowOperation = pFsEvent->AllowOperation;

				// Copy file path
				if (pFsEvent->pFilePath != NULL)
				{
					ULONG copyLen = min(pFsEvent->cbFilePath, (MAX_PATH - 1) * sizeof(WCHAR));
					RtlCopyMemory(pAgentFsEvent->FilePath, pFsEvent->pFilePath, copyLen);
					pAgentFsEvent->FilePath[copyLen / sizeof(WCHAR)] = L'\0';
				}

				// Copy new file path (for rename)
				if (pFsEvent->pNewFilePath != NULL)
				{
					ULONG copyLen = min(pFsEvent->cbNewFilePath, (MAX_PATH - 1) * sizeof(WCHAR));
					RtlCopyMemory(pAgentFsEvent->NewFilePath, pFsEvent->pNewFilePath, copyLen);
					pAgentFsEvent->NewFilePath[copyLen / sizeof(WCHAR)] = L'\0';
				}

				pFsEvent->EventState = FS_EVENT_IN_PROGRESS;
				Found = TRUE;
				break;
			}

			pEntry = pEntry->Flink;
		}

		KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);

		if (Found)
		{
			Written = sizeof(AGENT_FS_EVENT);
			Status = STATUS_SUCCESS;
		}
		else
		{
			DbgInfo("No pending FS events");
			Status = STATUS_NO_MORE_ENTRIES;
		}
		break;
	}
	case IOCTL_POST_FS_VERDICT:
	{
		DbgInfo("IOCTL_POST_FS_VERDICT");

		if (!g_pFsMonitor->g_Monitor)
		{
			return Status;
		}

		PAGENT_FS_EVENT pAgentFsEvent = (PAGENT_FS_EVENT)pIrp->AssociatedIrp.SystemBuffer;
		if (pAgentFsEvent == NULL)
		{
			DbgError("Invalid buffer for IOCTL_POST_FS_VERDICT");
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		DbgInfo("Received FS verdict: Op=%lu, File=%ws, PID=%lu, Allow=%d",
			pAgentFsEvent->Operation,
			pAgentFsEvent->FilePath,
			pAgentFsEvent->ProcessId,
			pAgentFsEvent->AllowOperation);

		// Find the matching event in the list
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_pFsMonitor->g_FsMonLock, &oldIrql);
		PFS_EVENT pFsEvent = FindFsEventUnSafe(pAgentFsEvent->ProcessId, pAgentFsEvent->FilePath);
		if (pFsEvent == NULL) {
			KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);
			Status = STATUS_NOT_FOUND;
			break;
		}
		pFsEvent->AllowOperation = pAgentFsEvent->AllowOperation;
		pFsEvent->EventState = FS_EVENT_PROCESSED;
		if (pFsEvent->NeedsVerdict) {
			KeSetEvent(&pFsEvent->Event, IO_NO_INCREMENT, FALSE);
			KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);
		} else {
			RemoveEntryList(&pFsEvent->ListEntry);
			KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);
			ReleaseFsEvent(pFsEvent);
		}

		Status = STATUS_SUCCESS;
		break;
	}
	}
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
	// Cleanup monitors
	UnInitializeFilesystemMonitor();
	UnInitializeProcessMonitor();
	UninitializeNetworkMonitor();
	DbgInfo("Driver unloaded");
}
