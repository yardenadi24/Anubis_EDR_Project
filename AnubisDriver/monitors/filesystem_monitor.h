#pragma once
#include "commons.h"

#include <fltKernel.h>

// Minifilter altitude - must be unique, using a value in the FSFilter Anti-Virus range (320000-329999)
#define FS_MONITOR_ALTITUDE L"324242"

// Globals
typedef struct _FILESYSTEM_MONITOR {
	LIST_ENTRY g_FsMonList;
	KSPIN_LOCK g_FsMonLock;
	BOOLEAN g_Monitor;
	LONG g_AgentPID;
	PFLT_FILTER g_FilterHandle;
}FILESYSTEM_MONITOR, * PFILESYSTEM_MONITOR;

extern PFILESYSTEM_MONITOR g_pFsMonitor;

enum FS_EVENT_STATE {
	FS_EVENT_PENDING = 0,
	FS_EVENT_IN_PROGRESS = 1,
	FS_EVENT_PROCESSED = 2
};

typedef struct _FS_EVENT {
	LIST_ENTRY ListEntry;
	ULONG ProcessId;
	ULONG Operation;                // FS_OPERATION_CREATE, FS_OPERATION_RENAME, FS_OPERATION_DELETE
	PWCHAR pFilePath;
	ULONG cbFilePath;
	PWCHAR pNewFilePath;            // Used for rename operations
	ULONG cbNewFilePath;
	ULONG FileSize;
	BOOLEAN IsDirectory;
	KEVENT Event;                   // Synchronization event (used only for blocking operations)
	BOOLEAN AllowOperation;
	FS_EVENT_STATE EventState;
	BOOLEAN NeedsVerdict;           // TRUE for create (blockable), FALSE for delete/rename (log-only)
}FS_EVENT, * PFS_EVENT;

// Initialize filesystem monitor (registers minifilter)
PFILESYSTEM_MONITOR
InitializeFilesystemMonitor(
	_In_ PDRIVER_OBJECT DriverObject
);

// Uninitialize filesystem monitor (unregisters minifilter)
VOID
UnInitializeFilesystemMonitor();

// Minifilter callbacks
FLT_PREOP_CALLBACK_STATUS
FsPreCreateCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
FsPreSetInformationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

// Minifilter unload callback
NTSTATUS
FsFilterUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

// Find FS event in list (thread-safe)
PFS_EVENT FindFsEventSafe(
	ULONG ProcessId,
	PWCHAR FilePath
);

// Find FS event in list (unsafe - caller must hold lock)
PFS_EVENT FindFsEventUnSafe(
	ULONG ProcessId,
	PWCHAR FilePath
);

// Release FS event memory
VOID ReleaseFsEvent(
	PFS_EVENT pFsEvent
);