#include "process_monitor.h"
#pragma warning(disable : 4996)

PPROCESS_MONITOR g_pProcMonitor = NULL;

PPROCESS_MONITOR
InitializeProcessMonitor()
{
	NTSTATUS Status = STATUS_SUCCESS;

	g_pProcMonitor = (PPROCESS_MONITOR)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_MONITOR), EDR_MEMORY_TAG);

	if (g_pProcMonitor == NULL)
	{
		DbgError("Failed to create process monitor struct");
		UnInitializeProcessMonitor();
		return NULL;
	}

	g_pProcMonitor->g_AgentPID = INVALIDE_PROCESS_ID;
	g_pProcMonitor->g_Monitor = FALSE;

	// Initialize list head and mutex
	InitializeListHead(&(g_pProcMonitor->g_ProcMonList));
	KeInitializeSpinLock(&(g_pProcMonitor->g_ProcMonLock));

	// Register for process creation
	Status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);

	if (!NT_SUCCESS(Status))
	{
		DbgError("Failed to register for process creation notifications");
		UnInitializeProcessMonitor();
		return NULL;
	}

	return g_pProcMonitor;
}

VOID
UnInitializeProcessMonitor()
{
	g_pProcMonitor->g_Monitor = FALSE;

	// Unregister from process creation callback
	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);

	// Clean process queue
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_pProcMonitor->g_ProcMonLock, &oldIrql);
	while (!IsListEmpty(&g_pProcMonitor->g_ProcMonList))
	{
		PLIST_ENTRY pEntry = RemoveHeadList(&g_pProcMonitor->g_ProcMonList);
		PPROCESS_EVENT pItem = CONTAINING_RECORD(pEntry, PROCESS_EVENT, ListEntry);
		ExFreePool(pItem);

	}
	KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, oldIrql);
}

PPROCESS_EVENT FindProcessSafe(
	ULONG ProcessIdToFind
)
{
	PPROCESS_EVENT FoundProcess = NULL;
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_pProcMonitor->g_ProcMonLock, &oldIrql);
	FoundProcess = FindProcessUnSafe(ProcessIdToFind);
	KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, oldIrql);
	if (FoundProcess == NULL)
	{
		DbgInfo("Process not found [PID:%lu]", ProcessIdToFind);
	}
	return FoundProcess;
}

PPROCESS_EVENT FindProcessUnSafe(
	ULONG ProcessIdToFind
)
{
	PLIST_ENTRY CurrentEntry;
	PPROCESS_EVENT CurrentProcess;

	// Start from the first entry
	CurrentEntry = g_pProcMonitor->g_ProcMonList.Flink;

	// Traverse the list
	while (CurrentEntry != &g_pProcMonitor->g_ProcMonList) {
		// Get the PROCCESS_EVENT structure containing this entry
		CurrentProcess = CONTAINING_RECORD(CurrentEntry, PROCESS_EVENT, ListEntry);

		// Check if this is the process we're looking for
		if (CurrentProcess->ProcessId == ProcessIdToFind) {
			return CurrentProcess;
		}

		// Move to next entry
		CurrentEntry = CurrentEntry->Flink;
	}

	// Process not found
	return NULL;
}


VOID ReleaseProcessEvent(
	PPROCESS_EVENT pProcessEvent
)
{
	if (pProcessEvent != NULL) {
		if (pProcessEvent->pImageFileName != NULL) {
			ExFreePoolWithTag(pProcessEvent->pImageFileName, EDR_MEMORY_TAG);
		}
		ExFreePoolWithTag(pProcessEvent, EDR_MEMORY_TAG);
	}
}

VOID ProcessNotifyCallback(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(Process);

	if (!CreateInfo) {
		DbgInfo("Process terminated : %lu\n", HandleToULong(ProcessId));
		if (g_pProcMonitor == NULL || g_pProcMonitor->g_Monitor == FALSE)
		{
			DbgInfo("Monitoring is off");
			return;
		}

		ULONG pid = HandleToULong(ProcessId);
		if (pid == 0 || pid == 4)
		{
			return;
		}

		KIRQL oldIrql;
		KeAcquireSpinLock(&g_pProcMonitor->g_ProcMonLock, &oldIrql);
		PPROCESS_EVENT pProcessEventToRemove = FindProcessUnSafe(HandleToULong(ProcessId));
		if (pProcessEventToRemove)
		{
			RemoveEntryList(&pProcessEventToRemove->ListEntry);
		}
		KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, oldIrql);
		if (pProcessEventToRemove)
		{
			ReleaseProcessEvent(pProcessEventToRemove);
		}
		
		return;
	}

	// New process creation
	DbgInfo("New process creation [PID: %lu]: %wZ\n",
		HandleToULong(ProcessId),
		CreateInfo->ImageFileName);

	if (g_pProcMonitor == NULL ||
		g_pProcMonitor->g_Monitor == FALSE)
	{
		DbgInfo("Monitoring is off");
		return;
	}

	// Add to list
	PPROCESS_EVENT pProcEvent =
		(PPROCESS_EVENT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_EVENT), EDR_MEMORY_TAG);
	if (!pProcEvent) {
		DbgError("Failed to allocate process event\n");
		return;
	}
	RtlZeroMemory(pProcEvent, sizeof(PROCESS_EVENT));

	// Copy relevant info
	pProcEvent->ProcessId = HandleToULong(ProcessId);
	pProcEvent->cbImageFileName = CreateInfo->ImageFileName->Length;
	pProcEvent->pImageFileName = pProcEvent->pImageFileName = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
		pProcEvent->cbImageFileName + 2/*2 bytes for wide char null terminate*/,
		EDR_MEMORY_TAG);

	if (pProcEvent->pImageFileName != NULL) {
		// Copy the image file name
		RtlCopyMemory(pProcEvent->pImageFileName,
			CreateInfo->ImageFileName->Buffer,
			CreateInfo->ImageFileName->Length);

		// Null terminate the string
		pProcEvent->pImageFileName[CreateInfo->ImageFileName->Length / sizeof(WCHAR)] = L'\0';
	}

	// Initialize syncronization event
	KeInitializeEvent(&pProcEvent->Event, NotificationEvent, FALSE);

	// Add Process event in pending state
	pProcEvent->ProcessState = PROCESS_PENDING;
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_pProcMonitor->g_ProcMonLock, &oldIrql);
	DbgPrint("Inserting process to queue: %ws \n[PID: %lu]\n",
		pProcEvent->pImageFileName,
		pProcEvent->ProcessId);
	InsertTailList(&g_pProcMonitor->g_ProcMonList, &pProcEvent->ListEntry);
	KeReleaseSpinLock(&g_pProcMonitor->g_ProcMonLock, oldIrql);

	// Wait for agent verdict
	LARGE_INTEGER Timeout;
	// 10 '100-nanosecond' intervals = 1 microsecond
	// 1000 microseconds = 1 millisecond
	// 1000 milliseconds = 1 second
	Timeout.QuadPart = -10 * 1000 * 1000 * 10; // 10 seconds timeout (100-nanosecond intervals, negative to indicate a relative timeout)
	NTSTATUS Status = KeWaitForSingleObject(
		&pProcEvent->Event,
		Executive,
		KernelMode,
		FALSE,
		&Timeout
	);

	if (Status == STATUS_TIMEOUT)
	{
		DbgError("Process verdict timed out: %wZ, PID: %lu\n",
			CreateInfo->ImageFileName,
			HandleToULong(ProcessId));

		// For now , allow the processes that timed out
		pProcEvent->AllowProcess = TRUE;
	}
	else if (!NT_SUCCESS(Status))
	{
		DbgError("Failed to wait for process event: %wZ, PID: %lu\n",
			CreateInfo->ImageFileName,
			HandleToULong(ProcessId));
	}
	else if (pProcEvent->ProcessState != PROCESS_PROCESSED) {
		DbgError("Process failed to processed: %wZ, PID: %lu\n",
			CreateInfo->ImageFileName,
			HandleToULong(ProcessId));
	}
	else {
		DbgInfo("Process verdict received: %wZ, PID: %lu\n",
			CreateInfo->ImageFileName,
			HandleToULong(ProcessId));
	}

	if (pProcEvent->AllowProcess == TRUE)
	{
		DbgInfo("Allowing process: %wZ, PID: %lu\n",
			CreateInfo->ImageFileName,
			HandleToULong(ProcessId));
		CreateInfo->CreationStatus = STATUS_SUCCESS;
	}
	else
	{
		DbgError("Denying process: %wZ, PID: %lu\n",
			CreateInfo->ImageFileName,
			HandleToULong(ProcessId));
		CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
	}
}