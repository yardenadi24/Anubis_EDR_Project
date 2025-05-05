#pragma once
#include <fltKernel.h>
#include "../Commons/commons.h"

// File event types
typedef enum _FILE_EVENT_TYPE {
    FileEventCreate = 0,
    FileEventWrite = 1,
    FileEventRead = 2,
    FileEventDelete = 3,
    FileEventRename = 4,
    FileEventClose = 5
} FILE_EVENT_TYPE;

// File operation state
typedef enum _FILE_OPERATION_STATE {
    FileOperationPending = 0,
    FileOperationInProgress = 1,
    FileOperationProcessed = 2
} FILE_OPERATION_STATE;

// File event structure
typedef struct _FILE_MONITOR_EVENT {
    ULONG ProcessId;
    WCHAR ProcessName[MAX_PATH];
    WCHAR FilePath[MAX_PATH];
    FILE_EVENT_TYPE EventType;
    BOOLEAN IsDirectory;
    LONGLONG FileSize;
    LARGE_INTEGER Timestamp;
    BOOLEAN AllowOperation;         // Verdict from user mode
    FILE_OPERATION_STATE State;     // Current state of operation
    KEVENT CompletionEvent;         // Event for synchronization
    LIST_ENTRY ListEntry;           // For maintaining pending operations list

    // Write operation specific fields
    ULONG WriteOffset;              // Offset where write will occur
    ULONG WriteLength;              // Length of data to be written
    PVOID WriteBuffer;              // Pointer to write data (if small enough)
    ULONG WriteBufferSize;          // Size of captured write data
    UCHAR WriteData[1024];          // First 1KB of write data for analysis
} FILE_MONITOR_EVENT, * PFILE_MONITOR_EVENT;

// Communication port name
#define ANUBIS_PORT_NAME L"\\AnubisFileMonitorPort"

// Context structure for file operations
typedef struct _FILE_CONTEXT {
    BOOLEAN IsMonitored;
    WCHAR FilePath[MAX_PATH];
    LONGLONG FileSize;
} FILE_CONTEXT, * PFILE_CONTEXT;

// Global filter data
typedef struct _FILTER_DATA {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    BOOLEAN Monitoring;
    LIST_ENTRY PendingOperationsList;  // List of operations waiting for verdict
    KSPIN_LOCK OperationsListLock;     // Spin lock for list protection
    KEVENT ShutdownEvent;              // Event for shutdown synchronization
} FILTER_DATA, * PFILTER_DATA;


extern FILTER_DATA g_FilterData;

// Prototypes
NTSTATUS
FileMonitorFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
FileMonitorInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
FileMonitorInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
FileMonitorInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
FileMonitorInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// Communication functions
NTSTATUS
FileMonitorConnect(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_ PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
);

VOID
FileMonitorDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS
FileMonitorMessage(
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
);

// Helper functions
NTSTATUS
SendFileEventToUser(
    _In_ PFILE_MONITOR_EVENT FileEvent
);

NTSTATUS
GetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_ PWCHAR ProcessName,
    _In_ ULONG ProcessNameLength
);

VOID
GetFilePath(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PWCHAR FilePath,
    _In_ ULONG FilePathLength
);

BOOLEAN
ShouldMonitorFile(
    _In_ PCWSTR FilePath
);