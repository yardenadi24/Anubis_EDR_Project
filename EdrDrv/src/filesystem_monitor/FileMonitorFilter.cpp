#include "FileMonitorFilter.h"
#include "kStringUtils.h"
#include "kOsUtils.h"
#include "kDiskUtils.h"

//=============================================================================
// GLOBAL VARIABLES
//=============================================================================

PFLT_FILTER g_pFilter = NULL;
BOOLEAN g_Monitor = FALSE;
BOOLEAN g_PortInitialized = FALSE;
PFLT_PORT g_pServerPort = NULL;
PFLT_PORT g_pClientPort = NULL;
CONNECTION_CONTEXT g_ConnectionContext = { 0 };

//=============================================================================
// CALLBACK REGISTRATION ARRAYS
//=============================================================================

CONST FLT_OPERATION_REGISTRATION c_Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, PostCreate },
    { IRP_MJ_CLEANUP, 0, PreCleanup, PostCleanup },
    { IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreSetFileInfo, PostSetFileInfo },
    { IRP_MJ_WRITE, 0, PreWrite, PostWrite },
    { IRP_MJ_READ, 0, PreRead, PostRead },
    //TODO::{ IRP_MJ_DIRECTORY_CONTROL, 0, PreDirectoryControl, PostDirectoryControl },
    //TODO::{ IRP_MJ_QUERY_INFORMATION, 0, PreQueryInformation, PostQueryInformation },
    //TODO::{ IRP_MJ_SET_SECURITY, 0, PreSetSecurity, PostSetSecurity },
    //TODO::{ IRP_MJ_QUERY_SECURITY, 0, PreQuerySecurity, PostQuerySecurity },
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
        // Register filter
        Status = FltRegisterFilter(
            pDriverObj, 
            &c_FilterRegistration, 
            &g_pFilter);

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
    DbgInfo("EDR File System Monitor finalized");
}

NTSTATUS UnloadFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    DbgInfo("Unloading filter");
    Finalize();
    return STATUS_SUCCESS;
}

BOOLEAN ShouldReportFileEvent(_In_ PFILE_SYSTEM_EVENT Event) {

    // High-priority file types
    if (IS_HIGH_PRIORITY_FILE(Event->Flags))
        return TRUE;

    // Risk indicators
    if (IS_HIGH_RISK_EVENT(Event->Flags))
        return TRUE;

    // Essential operations from suspicious paths
    if ((Event->Flags & FILE_EVENT_FLAG_SUSPICIOUS_PATH) &&
        IS_ESSENTIAL_OPERATION(Event->Operation))
        return TRUE;

    // Important operations on system files
    if ((Event->Flags & FILE_EVENT_FLAG_SYSTEM_FILE) &&
        IS_IMPORTANT_OPERATION(Event->Operation))
        return TRUE;

    // Skip noisy read operations on non-sensitive files
    if (Event->Operation == FILE_OP_READ &&
        !(Event->Flags & FILE_EVENT_FLAG_SENSITIVE))
        return FALSE;

    // Default: dont report
    return FALSE;
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

        // Check if network filesystem
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

        // Set driver type23
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

NTSTATUS InitializeCommunicationPort()
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR pSD = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING portName;

    // Create security descriptor that allows user-mode access
    Status = FltBuildDefaultSecurityDescriptor(&pSD, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(Status)) {
        DbgError("Failed to build security descriptor: 0x%x", Status);
        return Status;
    }

    RtlInitUnicodeString(&portName, FILTER_PORT_NAME); // L"\\AnubisFileMonitorPort"

    InitializeObjectAttributes(&objAttr,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        pSD);

    // Create the communication port
    Status = FltCreateCommunicationPort(
        g_pFilter,              // Filter handle
        &g_pServerPort,         // Server port handle
        &objAttr,               // Object attributes
        NULL,                   // Server port cookie
        FilterConnectNotify,    // Connect callback
        FilterDisconnectNotify, // Disconnect callback
        FilterMessageNotify,    // Message callback
        MAX_CONNECTIONS         // Max connections (typically 1)
    );

    if (NT_SUCCESS(Status)) {
        g_PortInitialized = TRUE;
        DbgInfo("Communication port created successfully");
    }
    else {
        DbgError("Failed to create communication port: 0x%x", Status);
    }

    FltFreeSecurityDescriptor(pSD);
    return Status;
}

VOID CleanupCommunicationPort()
{
    if (g_pServerPort != NULL) {
        FltCloseCommunicationPort(g_pServerPort);
        g_pServerPort = NULL;
    }

    if (g_pClientPort != NULL) {
        FltCloseClientPort(g_pFilter, &g_pClientPort);
        g_pClientPort = NULL;
    }

    g_PortInitialized = FALSE;
    DbgInfo("Communication port cleaned up");
}

NTSTATUS FLTAPI FilterConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    // Store the client port for sending messages
    g_pClientPort = ClientPort;
    g_ConnectionContext.IsConnected = TRUE;
    g_ConnectionContext.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    DbgInfo("Client connected from PID: %lu", g_ConnectionContext.ProcessId);
    return STATUS_SUCCESS;
}

VOID FLTAPI FilterDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    FltCloseClientPort(g_pFilter, &g_pClientPort);
    g_pClientPort = NULL;
    g_ConnectionContext.IsConnected = FALSE;

    DbgInfo("Client with PID: %lu, Disconnected", g_ConnectionContext.ProcessId);
}

NTSTATUS FLTAPI FilterMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;

    // Handle messages from user-mode if needed
    // For now, we only send events from kernel to user

    return STATUS_SUCCESS;
}

NTSTATUS SendFileSystemEvent(_In_ PFILE_SYSTEM_EVENT Event)
{
    if (!g_PortInitialized || !g_ConnectionContext.IsConnected || g_pClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    if (!ShouldReportFileEvent(Event)) {
        return STATUS_SUCCESS; // Event filtered out
    }

    ULONG replyLength = 0;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)c_nSendMsgTimeout * 10000); // Convert ms to 100ns units

    Event->Header.TimeStamp = getTickCount64();

    // Send the event to user-mode
    NTSTATUS Status = FltSendMessage(
        g_pFilter,
        &g_pClientPort,
        Event,
        sizeof(FILE_SYSTEM_EVENT),
        NULL,                    // No reply expected
        &replyLength,
        &timeout
    );

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_TIMEOUT) {
            DbgWarning("Timeout sending file event to user-mode");
        }
        else if (Status == STATUS_PORT_DISCONNECTED) {
            DbgWarning("Client disconnected while sending event");
            g_ConnectionContext.IsConnected = FALSE;
        }
        else {
            DbgError("Failed to send event: 0x%x", Status);
        }
    }

    return Status;
}

PFILE_SYSTEM_EVENT
AllocateEventFromPool()
{

    // Simple direct allocation - ignore the pool parameter
    PFILE_SYSTEM_EVENT pEvent = (PFILE_SYSTEM_EVENT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(FILE_SYSTEM_EVENT),
        EDR_MEMORY_TAG
    );

    if (pEvent) {
        RtlZeroMemory(pEvent, sizeof(FILE_SYSTEM_EVENT));
    }

    return pEvent;
}

VOID
FreeEventFromPool(
    PFILE_SYSTEM_EVENT pEvent
)
{
    if (pEvent) {
        ExFreePoolWithTag(pEvent, EDR_MEMORY_TAG);
    }
}


FLT_PREOP_CALLBACK_STATUS FLTAPI
PreDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
)
{
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // For now, pass through - can add directory enumeration monitoring later
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI
PostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pCompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    // Could monitor for reconnaissance activity here
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI
PreQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
)
{
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI
PostQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pCompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI
PreSetSecurity(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
)
{
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Could detect privilege escalation attempts here
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI
PostSetSecurity(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pCompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI
PreQuerySecurity(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
)
{
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pCompletionContext);

    if (!g_Monitor)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI
PostQuerySecurity(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pCompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN
IsTrustedSystemProcess(
    ULONG ProcessId
)
{
    // List of trusted system process IDs
    // PID 4 is System process
    // PID 0 is Idle process
    if (ProcessId == 0 || ProcessId == 4)
        return TRUE;

    // Additional trusted processes can be added here
    // Consider checking against a configurable whitelist

    return FALSE;
}

NTSTATUS
CollectUsbInfo(
    PCFLT_RELATED_OBJECTS pFltObjects,
    PINSTANCE_CONTEXT pInstCtx
)
{
    if (!pFltObjects || !pInstCtx)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_SUCCESS;

    __try {
        PDEVICE_OBJECT pDiskDeviceObject = NULL;

        status = FltGetDiskDeviceObject(pFltObjects->Volume, &pDiskDeviceObject);

        status = GetVolumeObject(
            pDiskDeviceObject,
            &pDiskDeviceObject
        );

        if (!NT_SUCCESS(status)) {
            pInstCtx->fIsUsb = FALSE;
            return STATUS_SUCCESS;
        }

        // Check if removable media
        if (pDiskDeviceObject->Characteristics & FILE_REMOVABLE_MEDIA) {
            pInstCtx->fIsUsb = TRUE;
        }
        else {
            pInstCtx->fIsUsb = FALSE;
        }

        if (pDiskDeviceObject) {
            ObDereferenceObject(pDiskDeviceObject);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        pInstCtx->fIsUsb = FALSE;
        status = STATUS_SUCCESS;
    }

    return status;
}


STREAM_HANDLE_CONTEXT::_STREAM_HANDLE_CONTEXT()
{
    nOpeningProcessId = 0;
    pNameInfo = NULL;
    pInstCtx = NULL;
    nSizeAtCreation = 0;
    eCreationStatus = FILE_CREATION_STATUS::NONE;
    fIsDirectory = FALSE;
    fIsExecute = FALSE;
    fDeleteOnClose = FALSE;
    fDispositionDelete = FALSE;
    fDirty = FALSE;
    fSkipItem = FALSE;

    RtlZeroMemory(&SequenceReadInfo, sizeof(SEQUENCE_ACTION));
    RtlZeroMemory(&SequenceWriteInfo, sizeof(SEQUENCE_ACTION));
}

NTSTATUS
SEQUENCE_ACTION::UpdateHash(
    PVOID Data,
    SIZE_T DataSize
)
{
    if (!fHashInitialized || fHashFinalized || !Data || DataSize == 0)
        return STATUS_SUCCESS;

    NTSTATUS status = BCryptHashData(
        hHash,
        (PUCHAR)Data,
        (ULONG)DataSize,
        0
    );

    if (!NT_SUCCESS(status)) {
        fEnabled = FALSE;
    }

    return status;
}

NTSTATUS
SEQUENCE_ACTION::FinalizeHash()
{
    if (!fHashInitialized || fHashFinalized)
        return STATUS_SUCCESS;

    NTSTATUS status = BCryptFinishHash(
        hHash,
        FinalHash,
        sizeof(FinalHash),
        0
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    fHashFinalized = TRUE;

    // Convert to hex string
    FillHashHexString();

    return STATUS_SUCCESS;
}

VOID
SEQUENCE_ACTION::FillHashHexString()
{
    if (!fHashFinalized)
        return;

    BytesToHexString(
        FinalHash,
        sizeof(FinalHash),
        FinalHexHash
    );
}

VOID
SEQUENCE_ACTION::CleanupHash()
{
    if (hHash) {
        BCryptDestroyHash(hHash);
        hHash = NULL;
    }

    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        hAlgorithm = NULL;
    }

    fHashInitialized = FALSE;
    fHashFinalized = FALSE;
}

VOID
SEQUENCE_ACTION::Reset()
{
    CleanupHash();

    fEnabled = FALSE;
    nNextPos = 0;
    nTotalBytesProcessed = 0;
    SequentialChunks = 0;

    RtlZeroMemory(FinalHash, sizeof(FinalHash));
    RtlZeroMemory(FinalHexHash, sizeof(FinalHexHash));
}

NTSTATUS
SEQUENCE_ACTION::ProcessBufferedIOForHash(
    PVOID pBuffer,
    SIZE_T DataSize
)
{
    if (!fEnabled || !fHashInitialized || fHashFinalized)
        return STATUS_SUCCESS;

    if (!pBuffer || DataSize == 0)
        return STATUS_SUCCESS;

    return UpdateHash(pBuffer, DataSize);
}

NTSTATUS
SEQUENCE_ACTION::ProcessDirectIOForHash(
    PMDL pMdlChain,
    SIZE_T TotalDataSize
)
{
    if (!fEnabled || !fHashInitialized || fHashFinalized)
        return STATUS_SUCCESS;

    if (!pMdlChain)
        return STATUS_SUCCESS;

    NTSTATUS status = STATUS_SUCCESS;
    PMDL pCurrentMdl = pMdlChain;
    SIZE_T remainingSize = TotalDataSize;

    while (pCurrentMdl != NULL && remainingSize > 0) {
        PVOID pBuffer = MmGetSystemAddressForMdlSafe(
            pCurrentMdl,
            NormalPagePriority | MdlMappingNoExecute
        );

        if (!pBuffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T mdlLength = MmGetMdlByteCount(pCurrentMdl);
        SIZE_T bytesToHash = min(mdlLength, remainingSize);

        status = UpdateHash(pBuffer, bytesToHash);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        remainingSize -= bytesToHash;
        pCurrentMdl = pCurrentMdl->Next;
    }

    return status;
}

NTSTATUS
SEQUENCE_ACTION::UpdateHashIoOperation(
    PFLT_CALLBACK_DATA pData,
    SEQUENCE_TYPE Type
)
{
    if (!fEnabled || !pData)
        return STATUS_SUCCESS;

    if (!fHashInitialized && !fHashFinalized) {
        NTSTATUS status = InitializeHash();
        if (!NT_SUCCESS(status)) {
            fEnabled = FALSE;
            return status;
        }
    }

    if (fHashFinalized)
        return STATUS_SUCCESS;

    NTSTATUS status = STATUS_SUCCESS;
    ULONG length = 0;

    __try {
        if (Type == SEQUENCE_TYPE::WRITE || pData->Iopb->MajorFunction == IRP_MJ_WRITE) {
            length = pData->Iopb->Parameters.Write.Length;

            if (length == 0)
                return STATUS_SUCCESS;

            if (pData->Iopb->Parameters.Write.MdlAddress) {
                status = ProcessDirectIOForHash(
                    pData->Iopb->Parameters.Write.MdlAddress,
                    length
                );
            }
            else if (pData->Iopb->Parameters.Write.WriteBuffer) {
                status = ProcessBufferedIOForHash(
                    pData->Iopb->Parameters.Write.WriteBuffer,
                    length
                );
            }
        }
        else if (Type == SEQUENCE_TYPE::READ || pData->Iopb->MajorFunction == IRP_MJ_READ) {
            length = pData->Iopb->Parameters.Read.Length;

            if (length == 0)
                return STATUS_SUCCESS;

            if (pData->Iopb->Parameters.Read.MdlAddress) {
                status = ProcessDirectIOForHash(
                    pData->Iopb->Parameters.Read.MdlAddress,
                    length
                );
            }
            else if (pData->Iopb->Parameters.Read.ReadBuffer) {
                status = ProcessBufferedIOForHash(
                    pData->Iopb->Parameters.Read.ReadBuffer,
                    length
                );
            }
        }

        if (NT_SUCCESS(status)) {
            nTotalBytesProcessed += length;
            nNextPos += length;
            SequentialChunks++;
        }
        else {
            fEnabled = FALSE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        fEnabled = FALSE;
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

NTSTATUS
SEQUENCE_ACTION::InitializeHash()
{
    if (fHashInitialized)
        return STATUS_SUCCESS;

    NTSTATUS status = STATUS_SUCCESS;

    // Open SHA256 algorithm provider
    status = BCryptOpenAlgorithmProvider(
        &hAlgorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Create hash object
    status = BCryptCreateHash(
        hAlgorithm,
        &hHash,
        NULL,
        0,
        NULL,
        0,
        0
    );

    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        hAlgorithm = NULL;
        return status;
    }

    fHashInitialized = TRUE;
    fHashFinalized = FALSE;
    nTotalBytesProcessed = 0;

    return STATUS_SUCCESS;
}

STREAM_HANDLE_CONTEXT::~_STREAM_HANDLE_CONTEXT()
{
    if (pNameInfo) {
        FltReleaseFileNameInformation(pNameInfo);
        pNameInfo = NULL;
    }

    if (pInstCtx) {
        FltReleaseContext(pInstCtx);
        pInstCtx = NULL;
    }

    SequenceReadInfo.CleanupHash();
    SequenceWriteInfo.CleanupHash();
}

NTSTATUS
STREAM_HANDLE_CONTEXT::Initialize(
    PSTREAM_HANDLE_CONTEXT* ppStreamCtx,
    PCFLT_RELATED_OBJECTS pFltObjects
)
{
    if (!ppStreamCtx || !pFltObjects)
        return STATUS_INVALID_PARAMETER;

    PSTREAM_HANDLE_CONTEXT pContext = NULL;

    NTSTATUS status = FltAllocateContext(
        pFltObjects->Filter,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(STREAM_HANDLE_CONTEXT),
        NonPagedPool,
        (PFLT_CONTEXT*)&pContext
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    *ppStreamCtx = pContext;
    return STATUS_SUCCESS;
}

VOID
STREAM_HANDLE_CONTEXT::CleanUp(
    PFLT_CONTEXT Context,
    FLT_CONTEXT_TYPE ContextType
)
{
    UNREFERENCED_PARAMETER(ContextType);

    if (!Context)
        return;

    PSTREAM_HANDLE_CONTEXT pStreamCtx = (PSTREAM_HANDLE_CONTEXT)Context;

    // Call destructor
    pStreamCtx->~STREAM_HANDLE_CONTEXT();
}


//=============================================================================
// FILE OPERATION CALLBACKS - CREATE
//=============================================================================

//
// Check selfprotection for specified process and file.
// Returns true if need to restrict access.
//
bool
isSelfProtected(
    PCUNICODE_STRING pusFileName, 
    ACCESS_MASK desiredAccess)
{
    // TODO
    return FALSE;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreate(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext
)
{
    UNREFERENCED_PARAMETER(pCompletionContext);
    UNREFERENCED_PARAMETER(pFltObjects);
    UNREFERENCED_PARAMETER(pData);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IoGetTopLevelIrp()) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FLT_IS_FASTIO_OPERATION(pData)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!FLT_IS_IRP_OPERATION(pData)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Skip	PIPE MAILSLOT VOLUME_OPEN
    if (FlagOn(pFltObjects->FileObject->Flags, FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Skip	PAGING_FILE
    if (FlagOn(pData->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    HANDLE nProcessId = (HANDLE)(ULONG_PTR)FltGetRequestorProcessId(pData);

    // Get Name Info
    // Disable logging this errors. Can't identify problem object. 
    PFLT_FILE_NAME_INFORMATION pNameInfo = nullptr;
    (void)FltGetFileNameInformation(pData, (FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT), &pNameInfo);
    if (pNameInfo == nullptr)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Check rules
    ACCESS_MASK desiredAccess = pData->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    // TODO:: Check self protection


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

        status = FltGetInstanceContext(
            pFltObjects->Instance,
            (PFLT_CONTEXT*)&pInstCtx);

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

        pStreamHandleCtx->fDeleteOnClose = 
            BooleanFlagOn(createOptions, FILE_DELETE_ON_CLOSE);
        pStreamHandleCtx->fIsExecute =
            !FlagOn(createOptions, FILE_DIRECTORY_FILE) &&
            FlagOn(desiredAccess, FILE_EXECUTE) &&
            !FlagOn(desiredAccess, FILE_WRITE_DATA) &&
            !FlagOn(desiredAccess, FILE_READ_EA);

        // Fill eCreationStatus
        switch (pData->IoStatus.Information)
        {
        case FILE_SUPERSEDED:
        case FILE_OVERWRITTEN:
            pStreamHandleCtx->eCreationStatus = FILE_CREATION_STATUS::TRUNCATED;
            break;
        case FILE_OPENED:
            pStreamHandleCtx->eCreationStatus = FILE_CREATION_STATUS::OPENED;
            break;
        case FILE_CREATED:
            pStreamHandleCtx->eCreationStatus = FILE_CREATION_STATUS::CREATED;
            break;
        default:
            pStreamHandleCtx->eCreationStatus = FILE_CREATION_STATUS::OPENED;
        }

        // Initialize sequence detection
        if (nSizeAtCreation == 0) {
            pStreamHandleCtx->SequenceWriteInfo.fEnabled = TRUE;
        }

        pStreamHandleCtx->SequenceReadInfo.fEnabled = TRUE;

        // Create unified event
        pEvent = AllocateEventFromPool();

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
            FreeEventFromPool(pEvent);
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

    if (!g_Monitor ||
        KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    NTSTATUS status = FltGetStreamContext(
        pFltObjects->Instance, 
        pFltObjects->FileObject, 
        (PFLT_CONTEXT*)&pStreamHandleCtx);

    if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    BOOLEAN fShouldPost = FALSE;
    auto& writeParams = pData->Iopb->Parameters.Write;

    do {
        auto& info = pStreamHandleCtx->SequenceWriteInfo;

        if (!info.fEnabled || writeParams.Length == 0)
            break;

        UINT64 writePos = 
            (writeParams.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION &&
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
    //PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
    PFILE_SYSTEM_EVENT pEvent = NULL;

    __try
    {
        NTSTATUS status = FltGetStreamContext(
            pFltObjects->Instance,
            pFltObjects->FileObject,
            (PFLT_CONTEXT*)&pStreamHandleCtx);

        if (!NT_SUCCESS(status) ||
            pStreamHandleCtx == NULL)
        {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        auto& info = pStreamHandleCtx->SequenceWriteInfo;

        // Mark file as dirty and update sequence tracking
        if (NT_SUCCESS(pData->IoStatus.Status) &&
            pData->IoStatus.Information > 0) 
        {
            pStreamHandleCtx->fDirty = TRUE;
            info.fEnabled = TRUE;
            pStreamHandleCtx->SequenceReadInfo.fEnabled = FALSE;
        }

        // Update hash for sequence detection
        if (info.fEnabled &&
            NT_SUCCESS(pData->IoStatus.Status)
            )
        {
            status = info.UpdateHashIoOperation(pData, SEQUENCE_TYPE::WRITE);
            if (!NT_SUCCESS(status)) {
                DbgError("Failed to update write hash: 0x%x", status);
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

    // Only monitor reads from untrusted processes
    // or sensitive files
    ULONG processId = 
        (ULONG)(ULONG_PTR)FltGetRequestorProcessId(pData);
    if (IsTrustedSystemProcess(processId))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    NTSTATUS status = FltGetStreamContext(
        pFltObjects->Instance, 
        pFltObjects->FileObject, 
        (PFLT_CONTEXT*)&pStreamHandleCtx);

    if (!NT_SUCCESS(status) ||
        pStreamHandleCtx == NULL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    BOOLEAN fPostIsNecessary = FALSE;
    auto& readParams = pData->Iopb->Parameters.Read;

    do {
        auto& info = pStreamHandleCtx->SequenceReadInfo;

        if (!info.fEnabled || readParams.Length == 0)
            break;

        UINT64 nReadPos = 
            (readParams.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION &&
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
    }
    __finally {
        if (pStreamHandleCtx != NULL)
            FltReleaseContext(pStreamHandleCtx);
    }

	return FLT_POSTOP_FINISHED_PROCESSING;
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
    UNREFERENCED_PARAMETER(pFltObjects);

    if (!g_Monitor || KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS infoClass = pData->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // Only monitor security-relevant information classes
    switch (infoClass) {
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    NTSTATUS status = FltGetStreamHandleContext(
        pFltObjects->Instance,
        pFltObjects->FileObject,
        (PFLT_CONTEXT*)&pStreamHandleCtx);

    if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;


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

    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    NTSTATUS status = FltGetStreamHandleContext(
        pFltObjects->Instance,
        pFltObjects->FileObject,
        (PFLT_CONTEXT*)&pStreamHandleCtx);

    if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;

    __try {
        NTSTATUS status = FltGetFileNameInformation(
            pData,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &pNameInfo);

        if (!NT_SUCCESS(status))
            return FLT_POSTOP_FINISHED_PROCESSING;

        // Determine operation type
        FILE_OPERATION_TYPE operation = FILE_OP_SET_INFO;
        auto eInfoClass = pData->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (infoClass == FileDispositionInformation)
        {
            pStreamHandleCtx->fDispositionDelete =
                ((PFILE_DISPOSITION_INFORMATION)pData->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile;
        }
        else if(infoClass == FileDispositionInformationEx)
        {
            ULONG flags = ((PFILE_DISPOSITION_INFORMATION_EX)pData->Iopb->Parameters.SetFileInformation.InfoBuffer)->Flags;
            if (FlagOn(flags, FILE_DISPOSITION_ON_CLOSE))
                pStreamHandleCtx->fDeleteOnClose = BooleanFlagOn(flags, FILE_DISPOSITION_DELETE);
            else
                pStreamHandleCtx->fDispositionDelete = BooleanFlagOn(flags, FILE_DISPOSITION_DELETE);
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

    FltReleaseContext(pStreamHandleCtx);
    return FLT_PREOP_SYNCHRONIZE;
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

    PINSTANCE_CONTEXT pInstCtx = NULL;
    PSTREAM_HANDLE_CONTEXT pStreamHandleCtx = NULL;
    PFILE_SYSTEM_EVENT pEvent = NULL;

    __try {
        NTSTATUS status = FltGetStreamHandleContext(
            pFltObjects->Instance,
            pFltObjects->FileObject,
            (PFLT_CONTEXT*)&pStreamHandleCtx);

        if (!NT_SUCCESS(status) || pStreamHandleCtx == NULL)
            return FLT_POSTOP_FINISHED_PROCESSING;

        FltGetInstanceContext(
            pFltObjects->Instance,
            (PFLT_CONTEXT*)&pInstCtx);

        if (!NT_SUCCESS(status) || pInstCtx == NULL)
            return FLT_POSTOP_FINISHED_PROCESSING;
    
    bool fFileWasDeleted = false;
        if (pStreamHandleCtx->fDeleteOnClose ||
            pStreamHandleCtx->fDispositionDelete)
        {
            fFileWasDeleted = true;
        }

        // Send read if needed
        if (pStreamHandleCtx->SequenceReadInfo.fEnabled)
        {
            do {
                auto& readInfo = pStreamHandleCtx->SequenceReadInfo;

				// Full file was read sequentially?
                if (readInfo.nNextPos != pStreamHandleCtx->nSizeAtCreation)
                    break;

				// TODO:: SEND SEQUENTIAL READ EVENT
                //sendFileEvent(SysmonEvent::FileDataReadFull, pStreamHandleContext,
                //    [&readInfo](auto pSerializer) {
                //        return writeFileHash(pSerializer, readInfo);
                //    }

                // Log event

                //LOGINFO2("FullRead: pid: %Iu, size:%I64u, hash:%016I64X, file:<%wZ>.\r\n",
                //    (ULONG_PTR)pStreamHandleContext->nOpeningProcessId, readInfo.nNextPos, (uint64_t)readInfo.hash.digest(),
                //    &pStreamHandleContext->pNameInfo->Name);

            } while (false);
        }

		// Send write if needed
        if (pStreamHandleCtx->SequenceWriteInfo.fEnabled) 
        do{
            auto& writeInfo = pStreamHandleCtx->SequenceWriteInfo;
            // Check file was not deleted
            if (fFileWasDeleted)
                break;

            // Todo:: send event
            //sendFileEvent(SysmonEvent::FileDataWriteFull, pStreamHandleContext,
            //    [&writeInfo](auto pSerializer) {
            //        return writeFileHash(pSerializer, writeInfo);
            //    }
            //);

			// Log event
            //LOGINFO2("FullWrite: pid: %Iu, size:%I64u, hash:%016I64X file:<%wZ>.\r\n",
            //    (ULONG_PTR)pStreamHandleContext->nOpeningProcessId, writeInfo.nNextPos, (uint64_t)writeInfo.hash.digest(),
            //    &pStreamHandleContext->pNameInfo->Name);
        }while (false);

		// Send FileDataChange if changed and not deleted
        if (pStreamHandleCtx->fDirty != FALSE 
            && !fFileWasDeleted)
        {
			// TODO:: send event
            //sendFileEvent(SysmonEvent::FileDataChange, pStreamHandleContext);
        }

        // Send FileDelete
        if (fFileWasDeleted &&
            pStreamHandleCtx->eCreationStatus != FILE_CREATION_STATUS::CREATED)
        {
			// TODO:: send event
            //sendFileEvent(SysmonEvent::FileDelete, pStreamHandleContext);
        }

        // TODO:: Send file close event
		// sendFileEvent(SysmonEvent::FileClose, pStreamHandleContext);

    }
    __finally {
        if (pStreamHandleCtx != NULL)
            FltReleaseContext(pStreamHandleCtx);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN IsExecutableFile(PUNICODE_STRING FilePath)
{
    if (!FilePath || FilePath->Length == 0) return FALSE;

    WCHAR* path = FilePath->Buffer;
    USHORT len = FilePath->Length / sizeof(WCHAR);

    // Find extension (last '.')
    WCHAR* ext = NULL;
    for (int i = len - 1; i >= 0 && i > len - 10; i--) {
        if (path[i] == L'.') {
            ext = &path[i];
            break;
        }
    }

    if (!ext) return FALSE;

    // Check executable extensions
    return (_wcsicmp(ext, L".exe") == 0 ||
        _wcsicmp(ext, L".dll") == 0 ||
        _wcsicmp(ext, L".sys") == 0 ||
        _wcsicmp(ext, L".drv") == 0 ||
        _wcsicmp(ext, L".ocx") == 0 ||
        _wcsicmp(ext, L".cpl") == 0 ||
        _wcsicmp(ext, L".scr") == 0);
}

BOOLEAN IsScriptFile(PUNICODE_STRING FilePath)
{
    if (!FilePath || FilePath->Length == 0) return FALSE;

    WCHAR* path = FilePath->Buffer;
    USHORT len = FilePath->Length / sizeof(WCHAR);

    WCHAR* ext = NULL;
    for (int i = len - 1; i >= 0 && i > len - 10; i--) {
        if (path[i] == L'.') {
            ext = &path[i];
            break;
        }
    }

    if (!ext) return FALSE;

    return (_wcsicmp(ext, L".ps1") == 0 ||
        _wcsicmp(ext, L".bat") == 0 ||
        _wcsicmp(ext, L".cmd") == 0 ||
        _wcsicmp(ext, L".vbs") == 0 ||
        _wcsicmp(ext, L".js") == 0 ||
        _wcsicmp(ext, L".wsf") == 0 ||
        _wcsicmp(ext, L".hta") == 0);
}

BOOLEAN IsDocumentFile(PUNICODE_STRING FilePath)
{
    if (!FilePath || FilePath->Length == 0) return FALSE;

    WCHAR* path = FilePath->Buffer;
    USHORT len = FilePath->Length / sizeof(WCHAR);

    WCHAR* ext = NULL;
    for (int i = len - 1; i >= 0 && i > len - 10; i--) {
        if (path[i] == L'.') {
            ext = &path[i];
            break;
        }
    }

    if (!ext) return FALSE;

    return (_wcsicmp(ext, L".doc") == 0 ||
        _wcsicmp(ext, L".docx") == 0 ||
        _wcsicmp(ext, L".xls") == 0 ||
        _wcsicmp(ext, L".xlsx") == 0 ||
        _wcsicmp(ext, L".ppt") == 0 ||
        _wcsicmp(ext, L".pptx") == 0 ||
        _wcsicmp(ext, L".pdf") == 0 ||
        _wcsicmp(ext, L".txt") == 0 ||
        _wcsicmp(ext, L".rtf") == 0);
}

BOOLEAN IsSystemFile(PUNICODE_STRING FilePath)
{
    if (!FilePath || FilePath->Length == 0) return FALSE;

    WCHAR* path = FilePath->Buffer;

    // Check for Windows system paths
    return (wcsstr(path, L"\\Windows\\System32\\") != NULL ||
        wcsstr(path, L"\\Windows\\SysWOW64\\") != NULL ||
        wcsstr(path, L"\\Windows\\WinSxS\\") != NULL);
}

BOOLEAN IsSensitiveFile(PUNICODE_STRING FilePath)
{
    if (!FilePath || FilePath->Length == 0) return FALSE;

    WCHAR* path = FilePath->Buffer;

    // SSH keys and certificates
    if (wcsstr(path, L".ssh\\") ||
        wcsstr(path, L".pem") ||
        wcsstr(path, L".key") ||
        wcsstr(path, L".pfx") ||
        wcsstr(path, L".p12") ||
        wcsstr(path, L"id_rsa") ||
        wcsstr(path, L"id_dsa")) {
        return TRUE;
    }

    // Credential stores
    if (wcsstr(path, L"\\Credentials\\") ||
        wcsstr(path, L"\\SAM") ||
        wcsstr(path, L"\\SECURITY")) {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN IsSuspiciousPath(PUNICODE_STRING FilePath)
{
    if (!FilePath || FilePath->Length == 0) return FALSE;

    WCHAR* path = FilePath->Buffer;

    // Temp directories (malware staging)
    if (wcsstr(path, L"\\Temp\\") ||
        wcsstr(path, L"\\TMP\\") ||
        wcsstr(path, L"\\AppData\\Local\\Temp\\")) {
        return TRUE;
    }

    // Startup locations (persistence)
    if (wcsstr(path, L"\\Startup\\") ||
        wcsstr(path, L"\\Start Menu\\Programs\\Startup\\")) {
        return TRUE;
    }

    // Unusual locations for executables
    if ((IsExecutableFile(FilePath) || IsScriptFile(FilePath)) &&
        (wcsstr(path, L"\\Downloads\\") ||
            wcsstr(path, L"\\Public\\"))) {
        return TRUE;
    }

    return FALSE;
}

NTSTATUS
SendFilesystemEvent(
	FsEventType eventType,
	PSTREAM_HANDLE_CONTEXT pStreamCtx,
    PINSTANCE_CONTEXT pinstCtx
)
{
    UNREFERENCED_PARAMETER(eventType);
    UNREFERENCED_PARAMETER(pStreamCtx);

	FILE_SYSTEM_EVENT rawEvent = {};

    /*
        Write the following:
            1. Event subtype
            2. Event id
			3. Timestamp
            4. Process ID
			5. File path
			6. File volume GUID
            7. File volume type
            8. Device name
            -- Additional fields per subtype --

    */

    LARGE_INTEGER liTimeout = {};
    liTimeout.QuadPart = 
        (LONGLONG)(2 /*sec*/ * 1000 /*ms*/) *
        (LONGLONG)1000 /*micro*/ * 
        (LONGLONG)10 /*100 nano*/ * 
        (LONGLONG)-1/*relative*/;

	rawEvent.Header.EventType = EventType::Filesystem;
	rawEvent.Header.Size = sizeof(FILE_SYSTEM_EVENT);
    rawEvent.FsEventType = eventType;
	KeQuerySystemTime(&rawEvent.Header.TimeStamp);
    rawEvent.Header.ProcessId = pStreamCtx->nOpeningProcessId;

	// File path
    RtlCopyMemory(
        (VOID*)rawEvent.FilePath,
        (VOID*)pStreamCtx->pNameInfo->Name.Buffer,
        pStreamCtx->pNameInfo->Name.Length
        );

	// Opening process path
	// TODO:: Implement process path retrieval

	// Volume information
    RtlCopyMemory(
        (VOID*)rawEvent.VolumeGuid,
        (VOID*)pinstCtx->pVolumeGuidBuffer,
		pinstCtx->usVolumeGuid.Length
    );

    RtlCopyMemory(
        (VOID*)rawEvent.DeviceName,
        (VOID*)pinstCtx->pDeviceNameBuffer,
        pinstCtx->usDeviceName.Length
    );

	rawEvent.DriverType = pStreamCtx->pInstCtx->DriverType;
    SEQUENCE_ACTION& info =
        (eventType == FsEventType::FileDataRead) ?
        pStreamCtx->SequenceReadInfo :
		pStreamCtx->SequenceWriteInfo;

    
    switch (eventType)
    {
    case FsEventType::FileCreate:
    {
        rawEvent.Operation = FILE_OP_CREATE;
        // TODO::Additional create-specific fields can be filled here
        break;
    }
    case FsEventType::FileDelete:
    {
        rawEvent.Operation = FILE_OP_DELETE;
        // TODO::Additional delete-specific fields can be filled here
        break;
    }
    case FsEventType::FileDataRead:
    {
        rawEvent.Operation = FILE_OP_READ;
        // Write file hash
		rawEvent.OperationData.IO.HasHash = info.fHashFinalized ? TRUE : FALSE;
        if (info.fHashFinalized) {
            RtlCopyMemory(
                (VOID*)rawEvent.OperationData.IO.DataHashHex,
                (VOID*)info.FinalHexHash,
                HASH_STRING_LENGTH);
		}

        break;
    }
    case FsEventType::FileDataWrite:
    {
        rawEvent.Operation = FILE_OP_WRITE;
        // Write file hash
        rawEvent.OperationData.IO.HasHash = info.fHashFinalized ? TRUE : FALSE;
        if (info.fHashFinalized) {
            RtlCopyMemory(
                (VOID*)rawEvent.OperationData.IO.DataHashHex,
                (VOID*)info.FinalHexHash,
                HASH_STRING_LENGTH);
        }
        break;
    }
    case FsEventType::FileChanged:
    {
        rawEvent.Operation = FILE_OP_CHANGED;
        // TODO::Additional write-specific fields can be filled here
    }
    case FsEventType::FileClosed:
    {
        rawEvent.Operation = FILE_OP_CLOSE;
        // TODO::Additional write-specific fields can be filled here
    }
    }
    NTSTATUS eSendResult = STATUS_SUCCESS;
    eSendResult = 
        FltSendMessage(
        g_pFilter,
        &g_pClientPort,
        (PVOID)&rawEvent,
        sizeof(rawEvent),
        NULL,
        NULL,
        &liTimeout);

    return eSendResult;
}
