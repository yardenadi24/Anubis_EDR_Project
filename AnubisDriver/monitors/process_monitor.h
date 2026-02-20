#pragma once
#include "commons.h"

// Globals
typedef struct _PROCESS_MONITOR {
	LIST_ENTRY g_ProcMonList;
	KSPIN_LOCK g_ProcMonLock;
	BOOLEAN g_Monitor;
	LONG g_AgentPID;
}PROCESS_MONITOR, * PPROCESS_MONITOR;

extern PPROCESS_MONITOR g_pProcMonitor;

enum PROCESS_STATE {
	PROCESS_PENDING = 0,
	PROCESS_IN_PROGRESS = 1,
	PROCESS_PROCESSED = 2
};

typedef struct _PROCESS_EVENT {
	LIST_ENTRY ListEntry;
	ULONG ProcessId;
	PWCHAR pImageFileName;
	ULONG cbImageFileName;
	KEVENT Event;
	BOOLEAN AllowProcess;
	PROCESS_STATE ProcessState;
}PROCESS_EVENT, * PPROCESS_EVENT;

// Initialize process monitor
PPROCESS_MONITOR
InitializeProcessMonitor();

// Uninitialized process monitor
VOID
UnInitializeProcessMonitor();

// Process notification callback
VOID ProcessNotifyCallback(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
);

// Find process in list
PPROCESS_EVENT FindProcessUnSafe(
	ULONG ProcessIdToFind
);

// Find process in list (safe)
PPROCESS_EVENT FindProcessSafe(
	ULONG ProcessIdToFind
);

VOID ReleaseProcessEvent(
	PPROCESS_EVENT pProcessEvent
);