#include "filesystem_monitor.h"
#pragma warning(disable : 4996)

PFILESYSTEM_MONITOR g_pFsMonitor = NULL;

// Minifilter operation callbacks
CONST FLT_OPERATION_REGISTRATION g_FltCallbacks[] = {
	{
		IRP_MJ_CREATE,
		0,
		FsPreCreateCallback,
		NULL    // No post-operation callback needed
	},
	{
		IRP_MJ_SET_INFORMATION,
		0,
		FsPreSetInformationCallback,
		NULL
	},
	{ IRP_MJ_OPERATION_END }
};

// Minifilter registration structure
CONST FLT_REGISTRATION g_FltRegistration = {
	sizeof(FLT_REGISTRATION),           // Size
	FLT_REGISTRATION_VERSION,           // Version
	0,                                   // Flags
	NULL,                                // Context registration
	g_FltCallbacks,                      // Operation callbacks
	FsFilterUnload,                      // FilterUnload
	NULL,                                // InstanceSetup
	NULL,                                // InstanceQueryTeardown
	NULL,                                // InstanceTeardownStart
	NULL,                                // InstanceTeardownComplete
	NULL,                                // GenerateFileName
	NULL,                                // NormalizeNameComponent
	NULL                                 // NormalizeContextCleanup
};

PFILESYSTEM_MONITOR
InitializeFilesystemMonitor(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	NTSTATUS Status = STATUS_SUCCESS;

	g_pFsMonitor = (PFILESYSTEM_MONITOR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
		sizeof(FILESYSTEM_MONITOR),
		EDR_MEMORY_TAG);

	if (g_pFsMonitor == NULL)
	{
		DbgError("Failed to allocate filesystem monitor struct");
		return NULL;
	}

	RtlZeroMemory(g_pFsMonitor, sizeof(FILESYSTEM_MONITOR));

	g_pFsMonitor->g_AgentPID = INVALIDE_PROCESS_ID;
	g_pFsMonitor->g_Monitor = FALSE;
	g_pFsMonitor->g_FilterHandle = NULL;

	// Initialize list head and spin lock
	InitializeListHead(&(g_pFsMonitor->g_FsMonList));
	KeInitializeSpinLock(&(g_pFsMonitor->g_FsMonLock));

	// Register the minifilter
	Status = FltRegisterFilter(
		DriverObject,
		&g_FltRegistration,
		&g_pFsMonitor->g_FilterHandle);

	if (!NT_SUCCESS(Status))
	{
		DbgError("Failed to register minifilter, status: 0x%X", Status);
		ExFreePoolWithTag(g_pFsMonitor, EDR_MEMORY_TAG);
		g_pFsMonitor = NULL;
		return NULL;
	}

	// Start filtering
	Status = FltStartFiltering(g_pFsMonitor->g_FilterHandle);

	if (!NT_SUCCESS(Status))
	{
		DbgError("Failed to start filtering, status: 0x%X", Status);
		FltUnregisterFilter(g_pFsMonitor->g_FilterHandle);
		ExFreePoolWithTag(g_pFsMonitor, EDR_MEMORY_TAG);
		g_pFsMonitor = NULL;
		return NULL;
	}

	DbgInfo("Filesystem monitor initialized successfully");
	return g_pFsMonitor;
}

VOID
UnInitializeFilesystemMonitor()
{
	if (g_pFsMonitor == NULL)
	{
		return;
	}

	g_pFsMonitor->g_Monitor = FALSE;

	// Unregister the minifilter
	if (g_pFsMonitor->g_FilterHandle != NULL)
	{
		FltUnregisterFilter(g_pFsMonitor->g_FilterHandle);
		g_pFsMonitor->g_FilterHandle = NULL;
	}

	// Clean filesystem event queue
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_pFsMonitor->g_FsMonLock, &oldIrql);
	while (!IsListEmpty(&g_pFsMonitor->g_FsMonList))
	{
		PLIST_ENTRY pEntry = RemoveHeadList(&g_pFsMonitor->g_FsMonList);
		PFS_EVENT pItem = CONTAINING_RECORD(pEntry, FS_EVENT, ListEntry);

		// Signal any waiting threads so they don't hang
		if (pItem->NeedsVerdict && pItem->EventState != FS_EVENT_PROCESSED)
		{
			pItem->AllowOperation = TRUE; // Allow on cleanup
			KeSetEvent(&pItem->Event, IO_NO_INCREMENT, FALSE);
		}

		ReleaseFsEvent(pItem);
	}
	KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);

	ExFreePoolWithTag(g_pFsMonitor, EDR_MEMORY_TAG);
	g_pFsMonitor = NULL;

	DbgInfo("Filesystem monitor uninitialized");
}

NTSTATUS
FsFilterUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);
	DbgInfo("Minifilter unload requested");
	// Actual cleanup is done in UnInitializeFilesystemMonitor
	return STATUS_SUCCESS;
}

PFS_EVENT FindFsEventSafe(
	ULONG ProcessId,
	PWCHAR FilePath
)
{
	PFS_EVENT FoundEvent = NULL;
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_pFsMonitor->g_FsMonLock, &oldIrql);
	FoundEvent = FindFsEventUnSafe(ProcessId, FilePath);
	KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);

	return FoundEvent;
}

PFS_EVENT FindFsEventUnSafe(
	ULONG ProcessId,
	PWCHAR FilePath
)
{
	PLIST_ENTRY CurrentEntry;
	PFS_EVENT CurrentEvent;

	CurrentEntry = g_pFsMonitor->g_FsMonList.Flink;

	while (CurrentEntry != &g_pFsMonitor->g_FsMonList)
	{
		CurrentEvent = CONTAINING_RECORD(CurrentEntry, FS_EVENT, ListEntry);

		if (CurrentEvent->ProcessId == ProcessId &&
			CurrentEvent->pFilePath != NULL &&
			FilePath != NULL &&
			_wcsicmp(CurrentEvent->pFilePath, FilePath) == 0)
		{
			return CurrentEvent;
		}

		CurrentEntry = CurrentEntry->Flink;
	}

	return NULL;
}

VOID ReleaseFsEvent(
	PFS_EVENT pFsEvent
)
{
	if (pFsEvent != NULL)
	{
		if (pFsEvent->pFilePath != NULL)
		{
			ExFreePoolWithTag(pFsEvent->pFilePath, EDR_MEMORY_TAG);
		}
		if (pFsEvent->pNewFilePath != NULL)
		{
			ExFreePoolWithTag(pFsEvent->pNewFilePath, EDR_MEMORY_TAG);
		}
		ExFreePoolWithTag(pFsEvent, EDR_MEMORY_TAG);
	}
}

static BOOLEAN
ShouldSkipFile(
	_In_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	if (g_pFsMonitor == NULL || g_pFsMonitor->g_Monitor == FALSE)
	{
		return TRUE;
	}

	if (Data->RequestorMode == KernelMode)
	{
		return TRUE;
	}


	ULONG currentPid = HandleToULong(PsGetCurrentProcessId());

	// Skip agent
	if ((LONG)currentPid == g_pFsMonitor->g_AgentPID)
	{
		return TRUE;
	}

	// Skip System (PID 0 and 4)
	if (currentPid == 0 || currentPid == 4)
	{
		return TRUE;
	}

	return FALSE;
}

static NTSTATUS
GetFileName(
	_In_ PFLT_CALLBACK_DATA Data,
	_Out_ PFLT_FILE_NAME_INFORMATION* NameInfo
)
{
	NTSTATUS Status;

	Status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		NameInfo);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	Status = FltParseFileNameInformation(*NameInfo);
	if (!NT_SUCCESS(Status))
	{
		FltReleaseFileNameInformation(*NameInfo);
		*NameInfo = NULL;
		return Status;
	}

	return STATUS_SUCCESS;
}

static PWCHAR
AllocCopyWideString(
	_In_ PCUNICODE_STRING Source,
	_Out_ PULONG OutByteLength
)
{
	if (Source == NULL || Source->Length == 0 || Source->Buffer == NULL)
	{
		*OutByteLength = 0;
		return NULL;
	}

	ULONG allocSize = Source->Length + sizeof(WCHAR); // +null terminator
	PWCHAR pCopy = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, EDR_MEMORY_TAG);

	if (pCopy == NULL)
	{
		*OutByteLength = 0;
		return NULL;
	}

	RtlCopyMemory(pCopy, Source->Buffer, Source->Length);
	pCopy[Source->Length / sizeof(WCHAR)] = L'\0';
	*OutByteLength = Source->Length;

	return pCopy;
}

static PFS_EVENT
QueueFsEvent(
	_In_ ULONG ProcessId,
	_In_ ULONG Operation,
	_In_ PUNICODE_STRING FilePath,
	_In_opt_ PUNICODE_STRING NewFilePath,
	_In_ BOOLEAN IsDirectory,
	_In_ BOOLEAN NeedsVerdict
)
{
	PFS_EVENT pFsEvent = (PFS_EVENT)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(FS_EVENT),
		EDR_MEMORY_TAG);

	if (pFsEvent == NULL)
	{
		DbgError("Failed to allocate FS event");
		return NULL;
	}

	RtlZeroMemory(pFsEvent, sizeof(FS_EVENT));

	pFsEvent->ProcessId = ProcessId;
	pFsEvent->Operation = Operation;
	pFsEvent->IsDirectory = IsDirectory;
	pFsEvent->NeedsVerdict = NeedsVerdict;
	pFsEvent->AllowOperation = TRUE; // Default allow
	pFsEvent->EventState = FS_EVENT_PENDING;
	pFsEvent->FileSize = 0;

	// Copy file path
	pFsEvent->pFilePath = AllocCopyWideString(FilePath, &pFsEvent->cbFilePath);
	if (pFsEvent->pFilePath == NULL && FilePath->Length > 0)
	{
		DbgError("Failed to allocate file path for FS event");
		ExFreePoolWithTag(pFsEvent, EDR_MEMORY_TAG);
		return NULL;
	}

	// Copy new file path (for rename)
	if (NewFilePath != NULL && NewFilePath->Length > 0)
	{
		pFsEvent->pNewFilePath = AllocCopyWideString(NewFilePath, &pFsEvent->cbNewFilePath);
	}

	// Initialize synchronization event (used only if NeedsVerdict)
	if (NeedsVerdict)
	{
		KeInitializeEvent(&pFsEvent->Event, NotificationEvent, FALSE);
	}

	// Insert into the list
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_pFsMonitor->g_FsMonLock, &oldIrql);
	DbgInfo("Inserting FS event: Op=%lu, File=%ws, PID=%lu, NeedsVerdict=%d",
		Operation,
		pFsEvent->pFilePath ? pFsEvent->pFilePath : L"(null)",
		ProcessId,
		NeedsVerdict);
	InsertTailList(&g_pFsMonitor->g_FsMonList, &pFsEvent->ListEntry);
	KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);

	return pFsEvent;
}

FLT_PREOP_CALLBACK_STATUS
FsPreCreateCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	if (ShouldSkipFile(Data, FltObjects))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// We only care about new file creations, not opens of existing files
	ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

	// FILE_CREATE = create new only (fail if exists)
	// FILE_SUPERSEDE = create or replace
	// FILE_OVERWRITE_IF = open or create (overwrite if exists)
	// FILE_OPEN_IF = open or create
	if (createDisposition != FILE_CREATE &&
		createDisposition != FILE_SUPERSEDE &&
		createDisposition != FILE_OVERWRITE_IF &&
		createDisposition != FILE_OPEN_IF)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Check for DELETE_ON_CLOSE flag - treat as delete operation instead
	ULONG createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
	if (createOptions & FILE_DELETE_ON_CLOSE)
	{
		// This will be handled as a delete - log only, don't block
		PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
		NTSTATUS Status = GetFileName(Data, &nameInfo);
		if (NT_SUCCESS(Status) && nameInfo != NULL)
		{
			ULONG pid = HandleToULong(PsGetCurrentProcessId());
			BOOLEAN isDir = BooleanFlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE);

			DbgInfo("DELETE_ON_CLOSE detected: %wZ [PID: %lu]", &nameInfo->Name, pid);

			// Queue as delete - log only, no verdict needed
			PFS_EVENT pEvent = QueueFsEvent(
				pid,
				FS_OPERATION_DELETE,
				&nameInfo->Name,
				NULL,
				isDir,
				FALSE   // No verdict needed for deletes
			);

			UNREFERENCED_PARAMETER(pEvent);

			FltReleaseFileNameInformation(nameInfo);
		}

		return FLT_PREOP_SUCCESS_NO_CALLBACK; // Don't block deletes
	}

	// Get the file name
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	NTSTATUS Status = GetFileName(Data, &nameInfo);

	if (!NT_SUCCESS(Status) || nameInfo == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	ULONG pid = HandleToULong(PsGetCurrentProcessId());
	BOOLEAN isDir = BooleanFlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE);

	DbgInfo("File create intercepted: %wZ [PID: %lu, Disposition: 0x%X]",
		&nameInfo->Name, pid, createDisposition);

	// Queue the event and WAIT for verdict (blocking for creates)
	PFS_EVENT pFsEvent = QueueFsEvent(
		pid,
		FS_OPERATION_CREATE,
		&nameInfo->Name,
		NULL,
		isDir,
		TRUE    // Needs verdict - block until agent responds
	);

	FltReleaseFileNameInformation(nameInfo);

	if (pFsEvent == NULL)
	{
		// Failed to queue, allow by default
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Wait for agent verdict
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10 * 1000 * 1000 * 10; // 10 seconds (100-nanosecond intervals, negative = relative)

	Status = KeWaitForSingleObject(
		&pFsEvent->Event,
		Executive,
		KernelMode,
		FALSE,
		&Timeout
	);

	if (Status == STATUS_TIMEOUT)
	{
		DbgError("FS create verdict timed out: PID=%lu", pid);
		pFsEvent->AllowOperation = TRUE; // Allow on timeout
	}
	else if (!NT_SUCCESS(Status))
	{
		DbgError("Failed to wait for FS event, status: 0x%X", Status);
		pFsEvent->AllowOperation = TRUE; // Allow on error
	}
	else if (pFsEvent->EventState != FS_EVENT_PROCESSED)
	{
		DbgError("FS event was not properly processed");
		pFsEvent->AllowOperation = TRUE;
	}
	else
	{
		DbgInfo("FS create verdict received: %s, PID=%lu",
			pFsEvent->AllowOperation ? "ALLOWED" : "BLOCKED", pid);
	}

	// Apply verdict
	FLT_PREOP_CALLBACK_STATUS callbackStatus;
	if (pFsEvent->AllowOperation)
	{
		callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	else
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		callbackStatus = FLT_PREOP_COMPLETE;
	}

	// Remove event from list and free it
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_pFsMonitor->g_FsMonLock, &oldIrql);
	RemoveEntryList(&pFsEvent->ListEntry);
	KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);
	ReleaseFsEvent(pFsEvent);

	return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS
FsPreSetInformationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	if (ShouldSkipFile(Data, FltObjects))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FILE_INFORMATION_CLASS fileInfoClass =
		Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

	ULONG operation = 0;

	// Determine operation type
	switch (fileInfoClass)
	{
	case FileRenameInformation:
	case FileRenameInformationEx:
		operation = FS_OPERATION_RENAME;
		break;

	case FileDispositionInformation:
	case FileDispositionInformationEx:
		operation = FS_OPERATION_DELETE;
		break;

	default:
		// Not an operation we care about
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// For delete via FileDispositionInformation, verify it's actually setting delete
	if (operation == FS_OPERATION_DELETE)
	{
		if (fileInfoClass == FileDispositionInformation)
		{
			PFILE_DISPOSITION_INFORMATION dispInfo =
				(PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

			if (dispInfo == NULL || !dispInfo->DeleteFile)
			{
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}
		else if (fileInfoClass == FileDispositionInformationEx)
		{
			PFILE_DISPOSITION_INFORMATION_EX dispInfoEx =
				(PFILE_DISPOSITION_INFORMATION_EX)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

			if (dispInfoEx == NULL ||
				!(dispInfoEx->Flags & FILE_DISPOSITION_DELETE))
			{
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}
	}

	// Get file name
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	NTSTATUS Status = GetFileName(Data, &nameInfo);

	if (!NT_SUCCESS(Status) || nameInfo == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	ULONG pid = HandleToULong(PsGetCurrentProcessId());
	BOOLEAN isDir = FALSE;

	// Try to determine if target is a directory
	FILE_STANDARD_INFORMATION fileStdInfo;
	Status = FltQueryInformationFile(
		FltObjects->Instance,
		FltObjects->FileObject,
		&fileStdInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation,
		NULL);

	if (NT_SUCCESS(Status))
	{
		isDir = fileStdInfo.Directory;
	}

	// Handle rename - extract new name
	UNICODE_STRING newName = { 0 };
	if (operation == FS_OPERATION_RENAME)
	{
		PFILE_RENAME_INFORMATION renameInfo =
			(PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

		if (renameInfo != NULL && renameInfo->FileNameLength > 0)
		{
			newName.Buffer = renameInfo->FileName;
			newName.Length = (USHORT)renameInfo->FileNameLength;
			newName.MaximumLength = (USHORT)renameInfo->FileNameLength;
		}

		DbgInfo("File rename intercepted: %wZ -> %wZ [PID: %lu]",
			&nameInfo->Name, &newName, pid);
	}
	else
	{
		DbgInfo("File delete intercepted: %wZ [PID: %lu]",
			&nameInfo->Name, pid);
	}

	BOOLEAN needsVerdict = (operation == FS_OPERATION_DELETE) ? TRUE : FALSE;

	PFS_EVENT pFsEvent = QueueFsEvent(
		pid, operation, &nameInfo->Name,
		(operation == FS_OPERATION_RENAME) ? &newName : NULL,
		isDir,
		needsVerdict
	);

	FltReleaseFileNameInformation(nameInfo);

	if (!needsVerdict || pFsEvent == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Wait for verdict (same pattern as FsPreCreateCallback)
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10 * 1000 * 1000 * 10; // 10 seconds

	NTSTATUS WaitStatus = KeWaitForSingleObject(
		&pFsEvent->Event, Executive, KernelMode, FALSE, &Timeout);

	if (WaitStatus == STATUS_TIMEOUT || !NT_SUCCESS(WaitStatus) ||
		pFsEvent->EventState != FS_EVENT_PROCESSED)
	{
		pFsEvent->AllowOperation = TRUE; // Allow on timeout/error
	}

	FLT_PREOP_CALLBACK_STATUS callbackStatus;
	if (pFsEvent->AllowOperation)
	{
		callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	else
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		callbackStatus = FLT_PREOP_COMPLETE;
	}

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_pFsMonitor->g_FsMonLock, &oldIrql);
	RemoveEntryList(&pFsEvent->ListEntry);
	KeReleaseSpinLock(&g_pFsMonitor->g_FsMonLock, oldIrql);
	ReleaseFsEvent(pFsEvent);

	return callbackStatus;
}