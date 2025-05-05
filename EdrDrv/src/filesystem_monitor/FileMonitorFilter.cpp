#include "FileMonitorFilter.h"
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>

#pragma warning(disable: 4996) 
#pragma warning(disable: 4100) 
#pragma comment(lib, "FltMgr.lib")

FILTER_DATA g_FilterData = { 0 };

// Define constant FLT_REGISTRATION for this filter
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PreCreate,
      PostCreate },

    { IRP_MJ_WRITE,
      0,
      PreWrite,
      PostWrite },

    { IRP_MJ_READ,
      0,
      PreRead,
      PostRead },

    { IRP_MJ_SET_INFORMATION,
      0,
      PreSetInformation,
      PostSetInformation },

    { IRP_MJ_CLEANUP,
      0,
      PreCleanup,
      PostCleanup },

    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_FILE_CONTEXT,
      0,
      NULL,
      sizeof(FILE_CONTEXT),
      'XCTF' },

    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    ContextRegistration,                // Context registration
    Callbacks,                          // Operation callbacks
    FileMonitorFilterUnload,            // FilterUnload
    FileMonitorInstanceSetup,           // InstanceSetup
    FileMonitorInstanceQueryTeardown,   // InstanceQueryTeardown
    FileMonitorInstanceTeardownStart,   // InstanceTeardownStart
    FileMonitorInstanceTeardownComplete // InstanceTeardownComplete
};

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;

    DbgInfo("Anubis file monitor driver starting");

    // Register the minifilter
    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &g_FilterData.Filter
    );

    if (!NT_SUCCESS(status)) {
        DbgError("Failed to register filter: 0x%X", status);
        return status;
    }

    // Set up a communication port for user-mode interaction
    RtlInitUnicodeString(&portName, ANUBIS_PORT_NAME);

    // Create security descriptor for the port
    status = FltBuildDefaultSecurityDescriptor(
        &securityDescriptor,
        FLT_PORT_ALL_ACCESS
    );

    if (!NT_SUCCESS(status)) {
        DbgError("Failed to build security descriptor: 0x%X", status);
        FltUnregisterFilter(g_FilterData.Filter);
        return status;
    }

    // Initialize object attributes for the port
    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor
    );

    // Create the communication port
    status = FltCreateCommunicationPort(
        g_FilterData.Filter,
        &g_FilterData.ServerPort,
        &objectAttributes,
        NULL,                   // ServerPortCookie
        FileMonitorConnect,     // ConnectNotifyCallback
        FileMonitorDisconnect,  // DisconnectNotifyCallback
        FileMonitorMessage,     // MessageNotifyCallback
        1                       // MaxConnections
    );

    // Free the security descriptor since it's no longer needed
    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        DbgError("Failed to create communication port: 0x%X", status);
        FltUnregisterFilter(g_FilterData.Filter);
        return status;
    }

    // Start filtering I/O
    status = FltStartFiltering(g_FilterData.Filter);

    if (!NT_SUCCESS(status)) {
        DbgError("Failed to start filtering: 0x%X", status);
        FltCloseCommunicationPort(g_FilterData.ServerPort);
        FltUnregisterFilter(g_FilterData.Filter);
        return status;
    }

    g_FilterData.Monitoring = TRUE;
    DbgInfo("Anubis file monitor driver successfully started");

    return STATUS_SUCCESS;
}

NTSTATUS
FileMonitorFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    DbgInfo("Anubis file monitor driver unloading");

    // Close the communication port if it exists
    if (g_FilterData.ServerPort) {
        FltCloseCommunicationPort(g_FilterData.ServerPort);
    }

    // Unregister the filter
    if (g_FilterData.Filter) {
        FltUnregisterFilter(g_FilterData.Filter);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
FileMonitorInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(FltObjects);

    // Only filter supported file systems
    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        DbgInfo("Ignoring network file system");
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    // Only monitor standard file systems 
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
        VolumeFilesystemType != FLT_FSTYPE_FAT &&
        VolumeFilesystemType != FLT_FSTYPE_EXFAT) {
        DbgInfo("Ignoring unsupported file system type: %d", VolumeFilesystemType);
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    DbgInfo("Attached to volume (FsType: %d)", VolumeFilesystemType);
    return STATUS_SUCCESS;
}

VOID
FileMonitorInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    DbgInfo("Instance teardown starting");
}

VOID
FileMonitorInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    DbgInfo("Instance teardown complete");
}

NTSTATUS
FileMonitorInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    DbgInfo("Instance query teardown");

    // Allow teardown to proceed
    return STATUS_SUCCESS;
}


// Pre and Post-operation Callbacks

FLT_PREOP_CALLBACK_STATUS
PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only handle if monitoring is enabled
    if (!g_FilterData.Monitoring || !g_FilterData.ClientPort) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check if this is a file deletion attempt (via CREATE)
    // When FILE_DELETE_ON_CLOSE is set, the file will be deleted when the handle is closed
    BOOLEAN isDeleteOperation = (Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE) != 0;

    // Check if this is a write attempt
    BOOLEAN isWriteOperation = (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
        (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)) != 0;

    // Get file path
    WCHAR filePath[MAX_PATH] = { 0 };
    GetFilePath(Data, FltObjects, filePath, MAX_PATH);

    if (!ShouldMonitorFile(filePath)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // For dangerous operations (write, delete), we need to analyze before allowing
    if (isWriteOperation || isDeleteOperation) {
        // Allocate file event structure
        PFILE_MONITOR_EVENT fileEvent = (PFILE_MONITOR_EVENT)ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(FILE_MONITOR_EVENT),
            'EVFS'
        );

        if (!fileEvent) {
            DbgError("Failed to allocate file event");
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        RtlZeroMemory(fileEvent, sizeof(FILE_MONITOR_EVENT));

        // Fill event details
        fileEvent->ProcessId = FltGetRequestorProcessId(Data);
        fileEvent->EventType = isDeleteOperation ? FileEventDelete : FileEventCreate;
        fileEvent->State = FileOperationPending;

        // Get process name
        GetProcessImageName(
            (HANDLE)fileEvent->ProcessId,
            fileEvent->ProcessName,
            MAX_PATH
        );

        // Copy file path
        RtlCopyMemory(fileEvent->FilePath, filePath, sizeof(WCHAR) * MAX_PATH);

        // Get file info
        FILE_STANDARD_INFORMATION standardInfo = { 0 };
        ULONG bytesReturned = 0;
        NTSTATUS status = FltQueryInformationFile(
            FltObjects->Instance,
            FltObjects->FileObject,
            &standardInfo,
            sizeof(FILE_STANDARD_INFORMATION),
            FileStandardInformation,
            &bytesReturned
        );

        if (NT_SUCCESS(status)) {
            fileEvent->IsDirectory = standardInfo.Directory;
            fileEvent->FileSize = standardInfo.EndOfFile.QuadPart;
        }

        // Set timestamp
        KeQuerySystemTime(&fileEvent->Timestamp);

        // Initialize synchronization event
        KeInitializeEvent(&fileEvent->CompletionEvent, NotificationEvent, FALSE);

        // Add to pending operations list
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_FilterData.OperationsListLock, &oldIrql);
        InsertTailList(&g_FilterData.PendingOperationsList, &fileEvent->ListEntry);
        KeReleaseSpinLock(&g_FilterData.OperationsListLock, oldIrql);

        // Send event to user mode for analysis
        status = SendFileEventToUser(fileEvent);
        if (!NT_SUCCESS(status)) {
            DbgError("Failed to send create/delete event to user mode: 0x%X", status);

            // Remove from pending list since we couldn't send it
            KeAcquireSpinLock(&g_FilterData.OperationsListLock, &oldIrql);
            RemoveEntryList(&fileEvent->ListEntry);
            KeReleaseSpinLock(&g_FilterData.OperationsListLock, oldIrql);

            // Free the event structure
            ExFreePoolWithTag(fileEvent, 'EVFS');

            // Allow the operation to proceed by default
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        // Wait for verdict with timeout
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10 * 1000 * 1000 * 10; // 10 seconds timeout

        status = KeWaitForSingleObject(
            &fileEvent->CompletionEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );

        if (status == STATUS_TIMEOUT) {
            DbgError("File operation verdict timed out for: %ws", fileEvent->FilePath);
            fileEvent->AllowOperation = TRUE; // Default to allow on timeout
        }
        else if (!NT_SUCCESS(status)) {
            DbgError("Failed to wait for file event: %ws", fileEvent->FilePath);
            fileEvent->AllowOperation = TRUE; // Default to allow on error
        }

        // Remove from pending list
        KeAcquireSpinLock(&g_FilterData.OperationsListLock, &oldIrql);
        RemoveEntryList(&fileEvent->ListEntry);
        KeReleaseSpinLock(&g_FilterData.OperationsListLock, oldIrql);

        // Apply verdict
        if (!fileEvent->AllowOperation) {
            DbgInfo("Blocking file operation for: %ws", fileEvent->FilePath);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            // Free the event structure
            ExFreePoolWithTag(fileEvent, 'EVFS');

            return FLT_PREOP_COMPLETE;
        }

        DbgInfo("Allowing file operation for: %ws", fileEvent->FilePath);

        // Free the event structure
        ExFreePoolWithTag(fileEvent, 'EVFS');
    }

    // For read operations, we can monitor in post-callback
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);  
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only handle if monitoring is enabled
    if (!g_FilterData.Monitoring || !g_FilterData.ClientPort) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get file context to check if we should monitor this file
    PFILE_CONTEXT fileContext = NULL;
    NTSTATUS status = FltGetFileContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&fileContext
    );

    if (!NT_SUCCESS(status) || !fileContext || !fileContext->IsMonitored) {
        if (fileContext) FltReleaseContext(fileContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // For write operations, we need to analyze before allowing
    PFILE_MONITOR_EVENT fileEvent = (PFILE_MONITOR_EVENT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(FILE_MONITOR_EVENT),
        'EVFS'
    );

    if (!fileEvent) {
        DbgError("Failed to allocate file event");
        FltReleaseContext(fileContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(fileEvent, sizeof(FILE_MONITOR_EVENT));

    // Fill event details
    fileEvent->ProcessId = FltGetRequestorProcessId(Data);
    fileEvent->EventType = FileEventWrite;
    fileEvent->State = FileOperationPending;

    // Get process name
    GetProcessImageName(
        (HANDLE)fileEvent->ProcessId,
        fileEvent->ProcessName,
        MAX_PATH
    );

    // Copy file path from context
    RtlCopyMemory(fileEvent->FilePath, fileContext->FilePath, sizeof(WCHAR) * MAX_PATH);
    fileEvent->IsDirectory = FALSE;
    fileEvent->FileSize = fileContext->FileSize;

    // Get write operation details
    fileEvent->WriteOffset = Data->Iopb->Parameters.Write.ByteOffset.LowPart;
    fileEvent->WriteLength = Data->Iopb->Parameters.Write.Length;

    // Capture write buffer data for analysis (up to 1KB)
    if (Data->Iopb->Parameters.Write.Length > 0) {
        PVOID writeBuffer = Data->Iopb->Parameters.Write.WriteBuffer;

        if (writeBuffer != NULL) {
            // Determine how much data to capture (max 1KB)
            ULONG captureSize = min(Data->Iopb->Parameters.Write.Length, sizeof(fileEvent->WriteData));

            // Safely copy the data
            __try {
                // Check if the buffer is from user mode and handle accordingly
                if (Data->RequestorMode == UserMode) {
                    // User mode buffer - probe it first
                    ProbeForRead(writeBuffer, captureSize, sizeof(UCHAR));
                }

                // Copy the data
                RtlCopyMemory(fileEvent->WriteData, writeBuffer, captureSize);
                fileEvent->WriteBufferSize = captureSize;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgError("Exception while capturing write buffer");
                fileEvent->WriteBufferSize = 0;
            }
        }
    }

    // Set timestamp
    KeQuerySystemTime(&fileEvent->Timestamp);

    // Release file context as we don't need it anymore
    FltReleaseContext(fileContext);

    // Initialize synchronization event
    KeInitializeEvent(&fileEvent->CompletionEvent, NotificationEvent, FALSE);

    // Add to pending operations list
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FilterData.OperationsListLock, &oldIrql);
    InsertTailList(&g_FilterData.PendingOperationsList, &fileEvent->ListEntry);
    KeReleaseSpinLock(&g_FilterData.OperationsListLock, oldIrql);

    // Send event to user mode for analysis
    status = SendFileEventToUser(fileEvent);
    if (!NT_SUCCESS(status)) {
        DbgError("Failed to send write event to user mode: 0x%X", status);

        // Remove from pending list since we couldn't send it
        KeAcquireSpinLock(&g_FilterData.OperationsListLock, &oldIrql);
        RemoveEntryList(&fileEvent->ListEntry);
        KeReleaseSpinLock(&g_FilterData.OperationsListLock, oldIrql);

        // Free the event structure
        ExFreePoolWithTag(fileEvent, 'EVFS');

        // Allow the operation to proceed by default
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Wait for verdict with timeout
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10 * 1000 * 1000 * 10; // 10 seconds timeout

    status = KeWaitForSingleObject(
        &fileEvent->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    if (status == STATUS_TIMEOUT) {
        DbgError("Write operation verdict timed out for: %ws", fileEvent->FilePath);
        fileEvent->AllowOperation = TRUE; // Default to allow on timeout
    }
    else if (!NT_SUCCESS(status)) {
        DbgError("Failed to wait for write event: %ws", fileEvent->FilePath);
        fileEvent->AllowOperation = TRUE; // Default to allow on error
    }

    // Remove from pending list
    KeAcquireSpinLock(&g_FilterData.OperationsListLock, &oldIrql);
    RemoveEntryList(&fileEvent->ListEntry);
    KeReleaseSpinLock(&g_FilterData.OperationsListLock, oldIrql);

    // Apply verdict
    if (!fileEvent->AllowOperation) {
        DbgInfo("Blocking write operation for: %ws (offset: %lu, length: %lu)",
            fileEvent->FilePath, fileEvent->WriteOffset, fileEvent->WriteLength);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        // Free the event structure
        ExFreePoolWithTag(fileEvent, 'EVFS');

        return FLT_PREOP_COMPLETE;
    }

    DbgInfo("Allowing write operation for: %ws (offset: %lu, length: %lu)",
        fileEvent->FilePath, fileEvent->WriteOffset, fileEvent->WriteLength);

    // Free the event structure
    ExFreePoolWithTag(fileEvent, 'EVFS');

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(CompletionContext);

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only handle if monitoring is enabled
    if (!g_FilterData.Monitoring || !g_FilterData.ClientPort) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Only interested in delete and rename operations
    FILE_INFORMATION_CLASS fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (fileInfoClass != FileDispositionInformation &&
        fileInfoClass != FileDispositionInformationEx &&
        fileInfoClass != FileRenameInformation &&
        fileInfoClass != FileRenameInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get file context
    PFILE_CONTEXT fileContext = NULL;
    NTSTATUS status = FltGetFileContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&fileContext
    );

    if (!NT_SUCCESS(status) || !fileContext || !fileContext->IsMonitored) {
        if (fileContext) FltReleaseContext(fileContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // For delete and rename operations, we need to analyze before allowing
    PFILE_MONITOR_EVENT fileEvent = (PFILE_MONITOR_EVENT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(FILE_MONITOR_EVENT),
        'EVFS'
    );

    if (!fileEvent) {
        DbgError("Failed to allocate file event");
        FltReleaseContext(fileContext);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(fileEvent, sizeof(FILE_MONITOR_EVENT));

    // Fill event details
    fileEvent->ProcessId = FltGetRequestorProcessId(Data);

    // Determine the event type
    if (fileInfoClass == FileDispositionInformation ||
        fileInfoClass == FileDispositionInformationEx) {

        // Check if this is actually a delete operation
        BOOLEAN deleteFile = FALSE;

        if (fileInfoClass == FileDispositionInformation) {
            FILE_DISPOSITION_INFORMATION* dispInfo =
                (FILE_DISPOSITION_INFORMATION*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            deleteFile = dispInfo->DeleteFile;
        }
        else {
            FILE_DISPOSITION_INFORMATION_EX* dispInfoEx =
                (FILE_DISPOSITION_INFORMATION_EX*)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            deleteFile = (dispInfoEx->Flags & FILE_DISPOSITION_DELETE) != 0;
        }

        if (!deleteFile) {
            // Not actually deleting, allow it
            ExFreePoolWithTag(fileEvent, 'EVFS');
            FltReleaseContext(fileContext);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        fileEvent->EventType = FileEventDelete;
    }
    else {
        fileEvent->EventType = FileEventRename;
    }

    fileEvent->State = FileOperationPending;

    // Get process name
    GetProcessImageName(
        (HANDLE)fileEvent->ProcessId,
        fileEvent->ProcessName,
        MAX_PATH
    );

    // Copy file path from context
    RtlCopyMemory(fileEvent->FilePath, fileContext->FilePath, sizeof(WCHAR) * MAX_PATH);
    fileEvent->IsDirectory = fileContext->IsMonitored;
    fileEvent->FileSize = fileContext->FileSize;

    // Set timestamp
    KeQuerySystemTime(&fileEvent->Timestamp);

    // Release file context as we don't need it anymore
    FltReleaseContext(fileContext);

    // Initialize synchronization event
    KeInitializeEvent(&fileEvent->CompletionEvent, NotificationEvent, FALSE);

    // Add to pending operations list
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FilterData.OperationsListLock, &oldIrql);
    InsertTailList(&g_FilterData.PendingOperationsList, &fileEvent->ListEntry);
    KeReleaseSpinLock(&g_FilterData.OperationsListLock, oldIrql);

    // Send event to user mode for analysis
    status = SendFileEventToUser(fileEvent);
    if (!NT_SUCCESS(status)) {
        DbgError("Failed to send setinfo event to user mode: 0x%X", status);

        // Remove from pending list since we couldn't send it
        KeAcquireSpinLock(&g_FilterData.OperationsListLock, &oldIrql);
        RemoveEntryList(&fileEvent->ListEntry);
        KeReleaseSpinLock(&g_FilterData.OperationsListLock, oldIrql);

        // Free the event structure
        ExFreePoolWithTag(fileEvent, 'EVFS');

        // Allow the operation to proceed by default
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Wait for verdict with timeout
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10 * 1000 * 1000 * 10; // 10 seconds timeout

    status = KeWaitForSingleObject(
        &fileEvent->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    if (status == STATUS_TIMEOUT) {
        DbgError("SetInfo operation verdict timed out for: %ws", fileEvent->FilePath);
        fileEvent->AllowOperation = TRUE; // Default to allow on timeout
    }
    else if (!NT_SUCCESS(status)) {
        DbgError("Failed to wait for setinfo event: %ws", fileEvent->FilePath);
        fileEvent->AllowOperation = TRUE; // Default to allow on error
    }

    // Remove from pending list
    KeAcquireSpinLock(&g_FilterData.OperationsListLock, &oldIrql);
    RemoveEntryList(&fileEvent->ListEntry);
    KeReleaseSpinLock(&g_FilterData.OperationsListLock, oldIrql);

    // Apply verdict
    if (!fileEvent->AllowOperation) {
        DbgInfo("Blocking setinfo operation for: %ws", fileEvent->FilePath);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        // Free the event structure
        ExFreePoolWithTag(fileEvent, 'EVFS');

        return FLT_PREOP_COMPLETE;
    }

    DbgInfo("Allowing setinfo operation for: %ws", fileEvent->FilePath);

    // Free the event structure
    ExFreePoolWithTag(fileEvent, 'EVFS');

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



FLT_POSTOP_CALLBACK_STATUS
PostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}



NTSTATUS
SendFileEventToUser(
    _In_ PFILE_MONITOR_EVENT FileEvent
)
{
    // Check if client port is available
    if (!g_FilterData.ClientPort) {
        return STATUS_PORT_DISCONNECTED;
    }

    NTSTATUS status;
    ULONG replyLength = 0;

    // Send the message to user mode
    status = FltSendMessage(
        g_FilterData.Filter,
        &g_FilterData.ClientPort,
        FileEvent,
        sizeof(FILE_MONITOR_EVENT),
        NULL,
        &replyLength,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgError("Failed to send file event to user mode: 0x%X", status);
    }

    return status;
}

NTSTATUS
GetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_ PWCHAR ProcessName,
    _In_ ULONG ProcessNameLength
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS process = NULL;
    PUNICODE_STRING processImageName = NULL;

    // Clear the output buffer
    RtlZeroMemory(ProcessName, ProcessNameLength * sizeof(WCHAR));

    // Get the EPROCESS pointer for the process
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Get the image name
    processImageName = PsGetProcessImageFileName(process);
    if (processImageName) {
        // Convert to wide string and copy to output buffer
        // Note: This is simplified and doesn't handle ANSI to Unicode properly
        // A real implementation would use proper conversion functions
        ANSI_STRING ansiString;
        RtlInitAnsiString(&ansiString, (PCHAR)processImageName);

        UNICODE_STRING unicodeString;
        status = RtlAnsiStringToUnicodeString(&unicodeString, &ansiString, TRUE);

        if (NT_SUCCESS(status)) {
            // Copy the name (ensuring we don't overflow)
            ULONG copyLength = min(ProcessNameLength, unicodeString.Length / sizeof(WCHAR));
            RtlCopyMemory(ProcessName, unicodeString.Buffer, copyLength * sizeof(WCHAR));
            ProcessName[copyLength] = L'\0';

            // Free the Unicode string
            RtlFreeUnicodeString(&unicodeString);
        }
    }

    // Dereference the process
    ObDereferenceObject(process);
    return status;
}

VOID
GetFilePath(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PWCHAR FilePath,
    _In_ ULONG FilePathLength
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;

    // Clear the output buffer
    RtlZeroMemory(FilePath, FilePathLength * sizeof(WCHAR));

    // Get the file name information
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (NT_SUCCESS(status)) {
        // Parse the file name information
        status = FltParseFileNameInformation(nameInfo);

        if (NT_SUCCESS(status)) {
            // Copy the name (ensuring we don't overflow)
            ULONG copyLength = min(FilePathLength - 1, nameInfo->Name.Length / sizeof(WCHAR));
            RtlCopyMemory(FilePath, nameInfo->Name.Buffer, copyLength * sizeof(WCHAR));
            FilePath[copyLength] = L'\0';
        }

        // Release the file name information
        FltReleaseFileNameInformation(nameInfo);
    }
    else {
        // Failed to get file name, try to get it from the FileObject
        if (FltObjects && FltObjects->FileObject && FltObjects->FileObject->FileName.Length > 0) {
            ULONG copyLength = min(FilePathLength - 1, FltObjects->FileObject->FileName.Length / sizeof(WCHAR));
            RtlCopyMemory(FilePath, FltObjects->FileObject->FileName.Buffer, copyLength * sizeof(WCHAR));
            FilePath[copyLength] = L'\0';
        }
        else {
            // Last resort, just put "Unknown"
            RtlCopyMemory(FilePath, L"Unknown", 7 * sizeof(WCHAR));
        }
    }
}

