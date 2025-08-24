#include "FileMonitorFilter.h"
#include "fltkernel.h"
#include "../utils/kStringUtils.h"
#include "../utils/kOsUtils.h"
#include "../utils/kDiskUtils.h"

//=============================================================================
// GLOBAL VARIABLES
//=============================================================================

PFLT_FILTER g_pFilter = NULL;
BOOLEAN g_Monitor = FALSE;
BOOLEAN g_PortInitialized = FALSE;
PFLT_PORT g_pServerPort = NULL;
PFLT_PORT g_pClientPort = NULL;
CONNECTION_CONTEXT g_ConnectionContext = { 0 };
EVENT_POOL g_EventPool = { 0 };

//=============================================================================
// CALLBACK REGISTRATION ARRAYS
//=============================================================================

CONST FLT_OPERATION_REGISTRATION c_Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, PostCreate },
    { IRP_MJ_CLEANUP, 0, PreCleanup, PostCleanup },
    { IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreSetFileInfo, PostSetFileInfo },
    { IRP_MJ_WRITE, 0, PreWrite, PostWrite },
    { IRP_MJ_READ, 0, PreRead, PostRead },
    { IRP_MJ_DIRECTORY_CONTROL, 0, PreDirectoryControl, PostDirectoryControl },
    { IRP_MJ_QUERY_INFORMATION, 0, PreQueryInformation, PostQueryInformation },
    { IRP_MJ_SET_SECURITY, 0, PreSetSecurity, PostSetSecurity },
    { IRP_MJ_QUERY_SECURITY, 0, PreQuerySecurity, PostQuerySecurity },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_CONTEXT_REGISTRATION c_ContextRegistration[] = {
    { FLT_INSTANCE_CONTEXT, 0, CleanUpInstanceContext, sizeof(INSTANCE_CONTEXT), EDR_MEMORY_TAG },
    { FLT_STREAMHANDLE_CONTEXT, 0, STREAM_HANDLE_CONTEXT::CleanUp, sizeof(STREAM_HANDLE_CONTEXT), EDR_MEMORY_TAG },
    { FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION c_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    c_ContextRegistration,
    c_Callbacks,
    UnloadFilter,
    SetupInstance,
    QueryInstanceTeardown,
    StartInstanceTeardown,
    CompleteInstanceTeardown,
    NULL,
    NULL,
    NULL
};


//=============================================================================
// FILTER LIFECYCLE FUNCTIONS
//=============================================================================

NTSTATUS
Initialize(
    PDRIVER_OBJECT pDriverObj
)
{
    BOOLEAN fSuccess = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    __try
    {
        // Initialize event pool
        Status = InitializeEventPool(&g_EventPool);
        if (!NT_SUCCESS(Status))
        {
            DbgError("Failed to initialize event pool: 0x%x", Status);
            return Status;
        }

        // Register filter
        Status = FltRegisterFilter(pDriverObj, &c_FilterRegistration, &g_pFilter);
        if (!NT_SUCCESS(Status)) {
            DbgError("Failed to register filter: 0x%x", Status);
            return Status;
        }

        // Initialize communication port
        Status = InitializeCommunicationPort();
        if (!NT_SUCCESS(Status)) {
            DbgError("Failed to initialize communication port: 0x%x", Status);
            return Status;
        }

        // Start filtering
        Status = FltStartFiltering(g_pFilter);
        if (!NT_SUCCESS(Status)) {
            DbgError("Failed to start filtering: 0x%x", Status);
            return Status;
        }

        g_Monitor = TRUE;
        fSuccess = TRUE;
        DbgInfo("EDR File System Monitor initialized successfully");

    }
    __finally {
        if (!fSuccess) {
            Finalize();
        }
    }

    return Status;
}



VOID 
Finalize() 
{
    g_Monitor = FALSE;

    if (g_pFilter != NULL) {
        FltUnregisterFilter(g_pFilter);
        g_pFilter = NULL;
    }

    CleanupCommunicationPort();
    CleanupEventPool(&g_EventPool);

    DbgInfo("EDR File System Monitor finalized");
}

NTSTATUS UnloadFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    DbgInfo("Unloading filter");
    Finalize();
    return STATUS_SUCCESS;
}

BOOLEAN ShouldReportFileEvent(_In_ PFILE_SYSTEM_EVENT Event) {
    // Always report high-risk operations
    if (Event->Flags & FILE_EVENT_FLAG_HIGH_RISK_OPERATION)
        return TRUE;

    // Always report operations on system/executable files
    if (Event->Flags & (FILE_EVENT_FLAG_SYSTEM_FILE | FILE_EVENT_FLAG_EXECUTABLE))
        return TRUE;

    // Report operations from untrusted processes
    if (Event->Flags & FILE_EVENT_FLAG_PROCESS_UNTRUSTED)
        return TRUE;

    // Apply rate limiting for noisy operations
    return ApplyRateLimit(Event);
}

//=============================================================================
// INSTANCE MANAGEMENT FUNCTIONS
//=============================================================================

NTSTATUS SetupInstance(
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS eFlags,
    _In_ DEVICE_TYPE eVolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE eVolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(eFlags);
    UNREFERENCED_PARAMETER(eVolumeFilesystemType);

    PINSTANCE_CONTEXT pInstCtx = NULL;
    PFLT_VOLUME_PROPERTIES  pVolumeProperties = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    __try
    {
        // Allocate instance context
        Status = FltAllocateContext(
            pFltObjects->Filter,
            FLT_INSTANCE_CONTEXT,
            sizeof(INSTANCE_CONTEXT),
            NonPagedPool,
            (PFLT_CONTEXT*)&pInstCtx);

        if (!NT_SUCCESS(Status)) {
            return Status;
        }

        RtlZeroMemory(pInstCtx, sizeof(INSTANCE_CONTEXT));
        pInstCtx->pInstance = pFltObjects->Instance;
        
        // Get volume properties
        ULONG nRetLength = 0;
        Status = FltGetVolumeProperties(
            pFltObjects->Volume,
            pVolumeProperties,
            0,
            &nRetLength);

        if (nRetLength > 0) {
            pVolumeProperties = (PFLT_VOLUME_PROPERTIES)ExAllocatePoolWithTag(
                NonPagedPool,
                nRetLength,
                EDR_MEMORY_TAG);

            if (pVolumeProperties != NULL) {
                Status = FltGetVolumeProperties(
                    pFltObjects->Volume,
                    pVolumeProperties,
                    nRetLength,
                    &nRetLength);
            }
        }

        // Set sector size
        if (pVolumeProperties != NULL) {
            pInstCtx->SectorSize = (USHORT)max(pVolumeProperties->SectorSize, c_MinSectorSize);
        }
        else {
            pInstCtx->SectorSize = c_MinSectorSize;
        }

        // Check for network filesystem
        if (eVolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
            pInstCtx->fIsNetworkFS = TRUE;

            STATIC_UNICODE_STRING(usDeviceMup, L"\\device\\mup");
            if (pVolumeProperties != NULL &&
                RtlEqualUnicodeString(&pVolumeProperties->RealDeviceName, &usDeviceMup, TRUE)) {
                pInstCtx->fIsMup = TRUE;
            }
        }

        // Collect USB information for disk filesystems
        if (eVolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM) {
            Status = CollectUsbInfo(pFltObjects, pInstCtx);
        }

        // Determine if this is a fixed drive
        if (pVolumeProperties != NULL) {
            pInstCtx->fIsFixed = !BooleanFlagOn(
                pVolumeProperties->DeviceCharacteristics,
                FILE_REMOVABLE_MEDIA | FILE_FLOPPY_DISKETTE | FILE_REMOTE_DEVICE | FILE_PORTABLE_DEVICE);
        }
        else {
            pInstCtx->fIsFixed = (eVolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM && !pInstCtx->fIsUsb);
        }

        // Get volume GUID
        ULONG nBufferSizeNeeded = 0;
        pInstCtx->usVolumeGuid.Buffer = pInstCtx->pVolumeGuidBuffer;
        pInstCtx->usVolumeGuid.MaximumLength = sizeof(pInstCtx->pVolumeGuidBuffer);

        Status = FltGetVolumeGuidName(pFltObjects->Volume, &pInstCtx->usVolumeGuid, &nBufferSizeNeeded);
        if (!NT_SUCCESS(Status)) {
            pInstCtx->usVolumeGuid.Length = 0;
        }

        // Set driver type
        if (pInstCtx->fIsNetworkFS) {
            pInstCtx->DriverType = VOLUME_DRIVER_TYPE::NETWORK;
        }
        else if (pVolumeProperties != NULL) {
            if (BooleanFlagOn(pVolumeProperties->DeviceCharacteristics, FILE_REMOVABLE_MEDIA)) {
                pInstCtx->DriverType = VOLUME_DRIVER_TYPE::REMOVABLE;
            }
            else {
                pInstCtx->DriverType = VOLUME_DRIVER_TYPE::FIXED;
            }
        }
        else {
            pInstCtx->DriverType = pInstCtx->fIsFixed ? VOLUME_DRIVER_TYPE::FIXED : VOLUME_DRIVER_TYPE::REMOVABLE;
        }

        // Set context
        Status = FltSetInstanceContext(pFltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, pInstCtx, NULL);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }

        pInstCtx->fSetupIsFinished = TRUE;
        DbgInfo("Instance setup completed for volume type %d", eVolumeDeviceType);


    }
    __finally
    {
        if (pInstCtx != NULL) {
            FltReleaseContext(pInstCtx);
        }
        if (pVolumeProperties != NULL) {
            ExFreePoolWithTag(pVolumeProperties, EDR_MEMORY_TAG);
        }
    }

    return STATUS_SUCCESS;
}

// Teardown routines

NTSTATUS QueryInstanceTeardown(
    PCFLT_RELATED_OBJECTS pFltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS eFlags
) {
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(eFlags);
    return STATUS_SUCCESS;
}

VOID StartInstanceTeardown(
    PCFLT_RELATED_OBJECTS pFltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS eFlags
) {
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(eFlags);
}

VOID CompleteInstanceTeardown(
    PCFLT_RELATED_OBJECTS pFltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS eFlags
) {
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(eFlags);
}

VOID CleanUpInstanceContext(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE ContextType) {
    UNREFERENCED_PARAMETER(ContextType);

    PINSTANCE_CONTEXT pInstCtx = (PINSTANCE_CONTEXT)Context;
    if (pInstCtx != NULL) {
        // Context cleanup is handled by the system
    }
}

//=============================================================================
// FILE OPERATION CALLBACKS - CREATE
//=============================================================================

FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreate(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
)
{
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor || KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Quick filtering
    //if (!ShouldMonitorCreate(pData, pFltObjects))
    //    return FLT_PREOP_SUCCESS_NO_CALLBACK;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostCreate(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor ||
        FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(pData->IoStatus.Status) ||
        pData->IoStatus.Status == STATUS_REPARSE)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
    PINSTANCE_CONTEXT pInstCtx = NULL;
    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    PFILE_SYSTEM_EVENT pEvent = NULL;

    __try
    {
        // Skip special file objects
        if (FlagOn(pFltObjects->FileObject->Flags, FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))
            return FLT_POSTOP_FINISHED_PROCESSING;

        ULONG processId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(pData);

        // Get file standard information
        FILE_STANDARD_INFORMATION fileStdInfo = { 0 };
        UINT64 nSizeAtCreation = c_nUnknownFileSize;
        BOOLEAN fIsDirectory = FALSE;
        ULONG nRetLength = 0;

        NTSTATUS status = FltQueryInformationFile(
            pFltObjects->Instance,
            pFltObjects->FileObject,
            &fileStdInfo,
            sizeof(FILE_STANDARD_INFORMATION),
            FileStandardInformation,
            &nRetLength);

        if (NT_SUCCESS(status)) {
            fIsDirectory = fileStdInfo.Directory;
            nSizeAtCreation = fileStdInfo.EndOfFile.QuadPart;
        }

        // Skip directories
        if (fIsDirectory)
            return FLT_POSTOP_FINISHED_PROCESSING;

        status = FltGetInstanceContext(pFltObjects->Instance, (PFLT_CONTEXT*)&pInstCtx);

        if (!NT_SUCCESS(status))
            return FLT_POSTOP_FINISHED_PROCESSING;

        // Get file name information
        status = FltGetFileNameInformation(
            pData,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &pNameInfo);

        if (!NT_SUCCESS(status) || pNameInfo == NULL)
            return FLT_POSTOP_FINISHED_PROCESSING;

        // Create and initialize stream handle context
        status = STREAM_HANDLE_CONTEXT::Initialize(&pStreamHandleCtx, pFltObjects);
        if (!NT_SUCCESS(status))
            return FLT_POSTOP_FINISHED_PROCESSING;

        FltReferenceFileNameInformation(pNameInfo);
        pStreamHandleCtx->pNameInfo = pNameInfo;
        pStreamHandleCtx->nOpeningProcessId = processId;
        pStreamHandleCtx->fIsDirectory = fIsDirectory;
        pStreamHandleCtx->nSizeAtCreation = nSizeAtCreation;

        FltReferenceContext(pInstCtx);
        pStreamHandleCtx->pInstCtx = pInstCtx;

        // Extract creation parameters
        ACCESS_MASK desiredAccess = pData->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        ULONG createOptions = pData->Iopb->Parameters.Create.Options & 0xFFFFFF;

        pStreamHandleCtx->fDeleteOnClose = BooleanFlagOn(createOptions, FILE_DELETE_ON_CLOSE);
        pStreamHandleCtx->fIsExecute =
            !FlagOn(createOptions, FILE_DIRECTORY_FILE) &&
            FlagOn(desiredAccess, FILE_EXECUTE) &&
            !FlagOn(desiredAccess, FILE_WRITE_DATA) &&
            !FlagOn(desiredAccess, FILE_READ_EA);

        // Initialize sequence detection
        if (nSizeAtCreation == 0) {
            pStreamHandleCtx->SequenceWriteInfo.fEnabled = TRUE;
        }

        pStreamHandleCtx->SequenceReadInfo.fEnabled = TRUE;

        // Create unified event
        pEvent = AllocateEventFromPool(&g_EventPool);

        if (pEvent != NULL) {

            status = CreateBaseFileEvent(pEvent, FILE_OP_CREATE, pData, pFltObjects, pNameInfo);

            if (NT_SUCCESS(status)) {

                // Fill create-specific data
                auto& createData = pEvent->OperationData.Create;

                createData.DesiredAccess = desiredAccess;
                createData.CreateOptions = createOptions;
                createData.ShareAccess = pData->Iopb->Parameters.Create.ShareAccess;
                createData.FileSize.QuadPart = nSizeAtCreation;
                createData.CreatedNewFile = (pData->IoStatus.Information == FILE_CREATED);
                createData.DeleteOnClose = pStreamHandleCtx->fDeleteOnClose;
                createData.IsExecute = pStreamHandleCtx->fIsExecute;

                // Send event
                if (ShouldReportFileEvent(pEvent)) {
                    SendFileSystemEvent(pEvent);
                }
            }
            FreeEventToPool(&g_EventPool, pEvent);
        }


    }
    __finally
    {
        if (pInstCtx != NULL)
            FltReleaseContext(pInstCtx);
        if (pStreamHandleCtx != NULL)
            FltReleaseContext(pStreamHandleCtx);
        if (pNameInfo != NULL)
            FltReleaseFileNameInformation(pNameInfo);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

//=============================================================================
// FILE OPERATION CALLBACKS - WRITE
//=============================================================================

FLT_PREOP_CALLBACK_STATUS FLTAPI PreWrite(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
)
{
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor || KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    NTSTATUS status = FltGetStreamContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);


    if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    BOOLEAN fShouldPost = FALSE;
    auto& writeParams = pData->Iopb->Parameters.Write;

    do {
        auto& info = pStreamHandleCtx->SequenceWriteInfo;

        if (!info.fEnabled || writeParams.Length == 0)
            break;

        UINT64 writePos = (writeParams.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION &&
            writeParams.ByteOffset.HighPart == -1) ?
            pFltObjects->FileObject->CurrentByteOffset.QuadPart :
            writeParams.ByteOffset.QuadPart;

        if (writePos != info.nNextPos) {
            info.fEnabled = FALSE;
            break;
        }

        fShouldPost = TRUE;

    } while (FALSE);

    if (!pStreamHandleCtx->fDirty)
        fShouldPost = TRUE;

    FltReleaseContext(pStreamHandleCtx);

    return fShouldPost ? FLT_PREOP_SYNCHRONIZE : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostWrite(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor ||
        FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(pData->IoStatus.Status))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
    PFILE_SYSTEM_EVENT pEvent = NULL;

    __try
    {
        NTSTATUS status = FltGetStreamContext(
            pFltObjects->Instance,
            pFltObjects->FileObject,
            (PFLT_CONTEXT*)&pStreamHandleCtx);

        if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
            return FLT_POSTOP_FINISHED_PROCESSING;

        auto& info = pStreamHandleCtx->SequenceWriteInfo;

        // Mark file as dirty and update sequence tracking
        if (NT_SUCCESS(pData->IoStatus.Status) && pData->IoStatus.Information > 0) {
            pStreamHandleCtx->fDirty = TRUE;
            info.fEnabled = TRUE;
            pStreamHandleCtx->SequenceReadInfo.fEnabled = FALSE;
        }

        // Update hash for sequence detection
        if (info.fEnabled && NT_SUCCESS(pData->IoStatus.Status)) {
            status = info.UpdateHashIoOperation(pData, SEQUENCE_TYPE::WRITE);
            if (!NT_SUCCESS(status)) {
                DbgError("Failed to update write hash: 0x%x", status);
            }
        }

        // Create and send event for significant writes
        if (pStreamHandleCtx->pNameInfo != NULL) {
            pEvent = AllocateEventFromPool(&g_EventPool);
            if (pEvent != NULL) {
                status = CreateBaseFileEvent(pEvent, FILE_OP_WRITE, pData, pFltObjects, pStreamHandleCtx->pNameInfo);
                if (NT_SUCCESS(status)) {

                    // Fill write-specific data
                    auto& ioData = pEvent->OperationData.IO;
                    ioData.ByteOffset = pData->Iopb->Parameters.Write.ByteOffset;
                    ioData.Length = pData->Iopb->Parameters.Write.Length;
                    ioData.ActualBytesTransferred = (ULONG)pData->IoStatus.Information;
                    ioData.IsSequential = info.fEnabled;

                    if (info.fHashFinalized) {
                        RtlCopyMemory(ioData.DataHash, info.FinalHash, sizeof(ioData.DataHash));
                        ioData.HasHash = TRUE;
                    }

                    // Send event
                    if (ShouldReportFileEvent(pEvent)) {
                        SendFileSystemEvent(pEvent);
                    }
                }
                FreeEventToPool(&g_EventPool, pEvent);
            }
        }

    }
    __finally
    {
        if (pStreamHandleCtx != NULL)
            FltReleaseContext(pStreamHandleCtx);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

//=============================================================================
// FILE OPERATION CALLBACKS - READ
//=============================================================================

FLT_PREOP_CALLBACK_STATUS FLTAPI PreRead(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
)
{
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor || KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Only monitor reads from untrusted processes or sensitive files
    ULONG processId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(pData);
    if (IsTrustedSystemProcess(processId))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    NTSTATUS status = FltGetStreamContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);

    if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    BOOLEAN fPostIsNecessary = FALSE;
    auto& readParams = pData->Iopb->Parameters.Read;

    do {
        auto& info = pStreamHandleCtx->SequenceReadInfo;

        if (!info.fEnabled || readParams.Length == 0)
            break;

        UINT64 nReadPos = (readParams.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION &&
            readParams.ByteOffset.HighPart == -1) ?
            pFltObjects->FileObject->CurrentByteOffset.QuadPart :
            readParams.ByteOffset.QuadPart;

        if (nReadPos != info.nNextPos) {
            info.fEnabled = FALSE;
            break;
        }

        fPostIsNecessary = TRUE;

    } while (FALSE);

    FltReleaseContext(pStreamHandleCtx);
    return fPostIsNecessary ? FLT_PREOP_SYNCHRONIZE : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostRead(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor ||
        FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(pData->IoStatus.Status) ||
        pData->IoStatus.Information == 0)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    PFILE_SYSTEM_EVENT pEvent = NULL;

    __try
    {
        NTSTATUS status = FltGetStreamHandleContext(
            pFltObjects->Instance,
            pFltObjects->FileObject,
            (PFLT_CONTEXT*)&pStreamHandleCtx);

        if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
            return FLT_POSTOP_FINISHED_PROCESSING;

        auto& info = pStreamHandleCtx->SequenceReadInfo;

        // Update hash for sequential reads
        if (info.fEnabled) {
            status = info.UpdateHashIoOperation(pData, SEQUENCE_TYPE::READ);
            if (!NT_SUCCESS(status)) {
                info.fEnabled = FALSE;
                DbgError("Failed to update read hash: 0x%x", status);
            }
        }

        // Only report reads of sensitive files
        if (pStreamHandleCtx->pNameInfo != NULL) {

            UNICODE_STRING filePath = pStreamHandleCtx->pNameInfo->Name;

            if (IsSensitiveFile(&filePath)
                || IsDocumentFile(&filePath)
                || IsExecutableFile(&filePath))
            {
                pEvent = AllocateEventFromPool(&g_EventPool);

                if (pEvent != NULL) {
                    
                    status = CreateBaseFileEvent(pEvent, FILE_OP_READ, pData, pFltObjects, pStreamHandleCtx->pNameInfo);
                    
                    if (NT_SUCCESS(status)) {
                        
                        // Fill read-specific data
                        auto& ioData = pEvent->OperationData.IO;
                        ioData.ByteOffset = pData->Iopb->Parameters.Read.ByteOffset;
                        ioData.Length = pData->Iopb->Parameters.Read.Length;
                        ioData.ActualBytesTransferred = (ULONG)pData->IoStatus.Information;
                        ioData.IsSequential = info.fEnabled;

                        if (info.fHashFinalized) {
                            RtlCopyMemory(ioData.DataHash, info.FinalHash, sizeof(ioData.DataHash));
                            ioData.HasHash = TRUE;
                        }

                        // Send event
                        if (ShouldReportFileEvent(pEvent)) {
                            SendFileSystemEvent(pEvent);
                        }
                    }
                    FreeEventToPool(&g_EventPool, pEvent);
                }
            }
        }

    }
    __finally {
        if (pStreamHandleCtx != NULL)
            FltReleaseContext(pStreamHandleCtx);
    }
}

//=============================================================================
// FILE OPERATION CALLBACKS - SET INFORMATION
//=============================================================================

FLT_PREOP_CALLBACK_STATUS FLTAPI PreSetFileInfo(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
) {
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor || KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS infoClass = pData->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // Only monitor security-relevant information classes
    switch (infoClass) {
    case FileDispositionInformation:
    case FileDispositionInformationEx:
    case FileRenameInformation:
    case FileRenameInformationEx:
    case FileMoveClusterInformation:
    case FileBasicInformation:
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostSetFileInfo(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor ||
        FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(pData->IoStatus.Status))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
    PFILE_SYSTEM_EVENT pEvent = NULL;
    FILE_INFORMATION_CLASS infoClass = pData->Iopb->Parameters.SetFileInformation.FileInformationClass;

    __try {
        NTSTATUS status = FltGetFileNameInformation(
            pData,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &pNameInfo);

        if (!NT_SUCCESS(status))
            return FLT_POSTOP_FINISHED_PROCESSING;

        // Determine operation type
        FILE_OPERATION_TYPE operation = FILE_OP_SET_INFO;
        if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
            operation = FILE_OP_RENAME;
        }
        else if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
            operation = FILE_OP_DELETE;
        }

        // Create unified event
        pEvent = AllocateEventFromPool(&g_EventPool);
        if (pEvent != NULL) {
            status = CreateBaseFileEvent(pEvent, operation, pData, pFltObjects, pNameInfo);
            if (NT_SUCCESS(status)) {
                // Fill operation-specific data
                switch (infoClass) {
                case FileRenameInformation:
                case FileRenameInformationEx: {
                    auto& renameData = pEvent->OperationData.Rename;
                    PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)pData->Iopb->Parameters.SetFileInformation.InfoBuffer;

                    if (renameInfo && renameInfo->FileNameLength > 0) {
                        RtlCopyMemory(renameData.TargetPath,
                            renameInfo->FileName,
                            min(renameInfo->FileNameLength, sizeof(renameData.TargetPath) - sizeof(WCHAR)));

                        renameData.ReplaceIfExists = renameInfo->ReplaceIfExists;

                        // Check for extension change
                        PWCHAR oldExt = wcsrchr(pEvent->FilePath, L'.');
                        PWCHAR newExt = wcsrchr(renameData.TargetPath, L'.');

                        if (oldExt && newExt) {
                            wcscpy_s(renameData.OldExtension, 16, oldExt);
                            wcscpy_s(renameData.NewExtension, 16, newExt);
                            renameData.ExtensionChanged = (_wcsicmp(oldExt, newExt) != 0);

                            if (renameData.ExtensionChanged) {
                                pEvent->Flags |= FILE_EVENT_FLAG_HIGH_RISK_OPERATION;
                            }
                        }
                    }
                    break;
                }

                case FileDispositionInformation:
                case FileDispositionInformationEx: {
                    auto& infoData = pEvent->OperationData.Info;
                    infoData.InformationClass = infoClass;

                    if (infoClass == FileDispositionInformation) {
                        PFILE_DISPOSITION_INFORMATION dispInfo = (PFILE_DISPOSITION_INFORMATION)pData->Iopb->Parameters.SetFileInformation.InfoBuffer;
                        if (dispInfo) {
                            infoData.DispositionInfo.DeleteFile = dispInfo->DeleteFile;
                        }
                    }
                    else {
                        PFILE_DISPOSITION_INFORMATION_EX dispInfoEx = (PFILE_DISPOSITION_INFORMATION_EX)pData->Iopb->Parameters.SetFileInformation.InfoBuffer;
                        if (dispInfoEx) {
                            infoData.DispositionInfo.DeleteFile = BooleanFlagOn(dispInfoEx->Flags, FILE_DISPOSITION_DELETE);
                        }
                    }

                    if (infoData.DispositionInfo.DeleteFile && (pEvent->Flags & FILE_EVENT_FLAG_SYSTEM_FILE)) {
                        pEvent->Flags |= FILE_EVENT_FLAG_HIGH_RISK_OPERATION;
                    }
                    break;
                }
                }

                // Send event
                if (ShouldReportFileEvent(pEvent)) {
                    SendFileSystemEvent(pEvent);
                }
            }
            FreeEventToPool(&g_EventPool, pEvent);
        }

    }
    __finally {
        if (pNameInfo)
            FltReleaseFileNameInformation(pNameInfo);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

//=============================================================================
// FILE OPERATION CALLBACKS - CLEANUP
//=============================================================================

FLT_PREOP_CALLBACK_STATUS FLTAPI PreCleanup(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
) {
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    NTSTATUS status = FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleCtx);

    if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    BOOLEAN fSkipItem = pStreamHandleCtx->fSkipItem;
    FltReleaseContext(pStreamHandleCtx);

    return fSkipItem ? FLT_PREOP_SUCCESS_NO_CALLBACK : FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostCleanup(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor ||
        FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(pData->IoStatus.Status))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    PFILE_SYSTEM_EVENT pEvent = NULL;

    __try {
        NTSTATUS status = FltGetStreamHandleContext(
            pFltObjects->Instance,
            pFltObjects->FileObject,
            (PFLT_CONTEXT*)&pStreamHandleCtx);

        if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
            return FLT_POSTOP_FINISHED_PROCESSING;

        // Only report if file was modified or is significant
        if (!pStreamHandleCtx->fDirty &&
            !(pStreamHandleCtx->SequenceWriteInfo.fEnabled || pStreamHandleCtx->SequenceReadInfo.fEnabled))
            return FLT_POSTOP_FINISHED_PROCESSING;

        // Create close event
        if (pStreamHandleCtx->pNameInfo != NULL) {
            pEvent = AllocateEventFromPool(&g_EventPool);
            if (pEvent != NULL) {
                status = CreateBaseFileEvent(pEvent, FILE_OP_CLOSE, pData, pFltObjects, pStreamHandleCtx->pNameInfo);
                if (NT_SUCCESS(status)) {
                    // Add summary information
                    if (pStreamHandleCtx->SequenceWriteInfo.fEnabled && pStreamHandleCtx->SequenceWriteInfo.fHashFinalized) {
                        auto& ioData = pEvent->OperationData.IO;
                        ioData.IsSequential = TRUE;
                        ioData.HasHash = TRUE;
                        RtlCopyMemory(ioData.DataHash,
                            pStreamHandleCtx->SequenceWriteInfo.FinalHash,
                            sizeof(ioData.DataHash));
                        ioData.ActualBytesTransferred = (ULONG)pStreamHandleCtx->SequenceWriteInfo.nTotalBytesProcessed;
                    }

                    // Flag if file was deleted
                    if (pStreamHandleCtx->fDeleteOnClose || pStreamHandleCtx->fDispositionDelete) {
                        pEvent->Flags |= FILE_EVENT_FLAG_HIGH_RISK_OPERATION;
                    }

                    // Send event
                    if (ShouldReportFileEvent(pEvent)) {
                        SendFileSystemEvent(pEvent);
                    }
                }
                FreeEventToPool(&g_EventPool, pEvent);
            }
        }

    }
    __finally {
        if (pStreamHandleCtx != NULL)
            FltReleaseContext(pStreamHandleCtx);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
