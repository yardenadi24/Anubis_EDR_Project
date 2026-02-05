#pragma once

#include <fltKernel.h>
#include <bcrypt.h>
#include <ntstrsafe.h>
//#include <Ntddstor.h>
#include "commons.h"
#include "SharedCommonsFs.h"

//=============================================================================
// CONSTANTS AND DEFINITIONS
//=============================================================================

#define FILE_SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define MAX_DEVICE_NAME_LENGTH 260
#define MAX_HASH_BYTES 32
#define SEQUENTIAL_THRESHOLD_BYTES (1024 * 1024)
#define SEQUENTIAL_TIMEOUT_SECONDS 5

// Event pool constants
#define EVENT_POOL_SIZE 1000
#define MAX_FILE_EVENTS 10000

// Rate limiting constants
#define MAX_EVENTS_PER_SECOND 100
#define RATE_LIMIT_WINDOW (10000000LL) // 1 second in 100ns units

// Timing constants
static constexpr USHORT c_MinSectorSize = 0x200;
static constexpr UINT64 c_nUnknownFileSize = (UINT64)-1;
constexpr UINT32 c_nSendMsgTimeout = 2 * 1000; // 2 seconds


//=============================================================================
// CONTEXT STRUCTURES
//=============================================================================

// Instance context for volume information
typedef struct _INSTANCE_CONTEXT {
    PFLT_INSTANCE pInstance;
    BOOLEAN fSetupIsFinished;
    CHAR sDeviceName[MAX_DEVICE_NAME_LENGTH];
    USHORT SectorSize;

    // Volume flags
    VOLUME_DRIVER_TYPE DriverType;
    BOOLEAN fIsNetworkFS;
    BOOLEAN fIsMup;
    BOOLEAN fIsUsb;
    BOOLEAN fIsFixed;
    BOOLEAN fIsCdrom;

    // Volume identifiers
    UNICODE_STRING usVolumeGuid;
    WCHAR pVolumeGuidBuffer[MAX_PATH];

    UNICODE_STRING usDiskPdoName;
    WCHAR pDiskPdoBuffer[MAX_PATH];
    
    UNICODE_STRING usDeviceName;
    WCHAR pDeviceNameBuffer[MAX_PATH];
    
    UNICODE_STRING usContainerId;
    WCHAR pContainerIdBuffer[MAX_PATH];

} INSTANCE_CONTEXT, * PINSTANCE_CONTEXT;

// Sequence action for hash calculation
typedef struct _SEQUENCE_ACTION {
    BOOLEAN fEnabled;
    UINT64 nNextPos;
    UINT64 nTotalBytesProcessed;
    ULONG SequentialChunks;
    BOOLEAN fHashInitialized;
    BOOLEAN fHashFinalized;

    // CNG hash objects
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_HASH_HANDLE hHash;

    // Hash results
    UCHAR FinalHash[MAX_HASH_BYTES];
    CHAR FinalHexHash[HASH_STRING_LENGTH];

    // Methods
    NTSTATUS InitializeHash();
    NTSTATUS UpdateHash(PVOID Data, SIZE_T DataSize);
    NTSTATUS FinalizeHash();
    VOID FillHashHexString();
    VOID CleanupHash();
    VOID Reset();
    NTSTATUS UpdateHashIoOperation(PFLT_CALLBACK_DATA pData, SEQUENCE_TYPE Type);
    NTSTATUS ProcessBufferedIOForHash(PVOID pBuffer, SIZE_T DataSize);
    NTSTATUS ProcessDirectIOForHash(PMDL pMdlChain, SIZE_T TotalDataSize);

} SEQUENCE_ACTION, * PSEQUENCE_ACTION;

// Stream handle context for file tracking
typedef struct _STREAM_HANDLE_CONTEXT {
    ULONG nOpeningProcessId;
    PFLT_FILE_NAME_INFORMATION pNameInfo;
    PINSTANCE_CONTEXT pInstCtx;

    UINT64 nSizeAtCreation;
    FILE_CREATION_STATUS eCreationStatus;

    // File flags
    BOOLEAN fIsDirectory;
    BOOLEAN fIsExecute;
    BOOLEAN fDeleteOnClose;
    BOOLEAN fDispositionDelete;
    BOOLEAN fDirty;
    BOOLEAN fSkipItem;

    // Hash tracking
    SEQUENCE_ACTION SequenceReadInfo;
    SEQUENCE_ACTION SequenceWriteInfo;

    // Constructor/Destructor
    void InitializeInternals();
    void CleanUpInternal();

    // Static methods
    static NTSTATUS Initialize(_STREAM_HANDLE_CONTEXT** ppStreamCtx, PCFLT_RELATED_OBJECTS pFltObjects);
    static VOID CleanUp(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE ContextType);

} STREAM_HANDLE_CONTEXT, * PSTREAM_HANDLE_CONTEXT;


//=============================================================================
// CONNECTION AND MEMORY MANAGEMENT
//=============================================================================

// Connection context
typedef struct _CONNECTION_CONTEXT {
    ULONG ProcessId;
    BOOLEAN IsConnected;
} CONNECTION_CONTEXT, * PCONNECTION_CONTEXT;

// Fast path decision
typedef struct _FAST_PATH_DECISION {
    BOOLEAN ShouldMonitor;
    BOOLEAN IsHighPriority;
    BOOLEAN RequiresDetailedAnalysis;
} FAST_PATH_DECISION, * PFAST_PATH_DECISION;

//=============================================================================
// GLOBAL VARIABLES
//=============================================================================

extern PFLT_FILTER g_pFilter;
extern BOOLEAN g_Monitor;
extern BOOLEAN g_PortInitialized;
extern PFLT_PORT g_pServerPort;
extern PFLT_PORT g_pClientPort;
extern CONNECTION_CONTEXT g_ConnectionContext;

//=============================================================================
// FUNCTION DECLARATIONS
//=============================================================================

// Filter lifecycle
NTSTATUS InitializeFsMonitor(PDRIVER_OBJECT pDriverObj);
VOID FinalizeFsMonitor();
NTSTATUS UnloadFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// Instance management
NTSTATUS SetupInstance(
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS eFlags,
    _In_ DEVICE_TYPE eVolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE eVolumeFilesystemType);

NTSTATUS QueryInstanceTeardown(
    PCFLT_RELATED_OBJECTS pFltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS eFlags);

VOID StartInstanceTeardown(
    PCFLT_RELATED_OBJECTS pFltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS eFlags);

VOID CompleteInstanceTeardown(
    PCFLT_RELATED_OBJECTS pFltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS eFlags);

// Context cleanup
VOID CleanUpInstanceContext(
    PFLT_CONTEXT Context,
    FLT_CONTEXT_TYPE ContextType);

// Volume information
NTSTATUS CollectUsbInfo(
    PCFLT_RELATED_OBJECTS pFltObjects,
    PINSTANCE_CONTEXT pInCtx);

//=============================================================================
// CALLBACK FUNCTION DECLARATIONS
//=============================================================================

// File operation callbacks
FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreate(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostCreate(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI PreCleanup(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostCleanup(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI PreSetFileInfo(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostSetFileInfo(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI PreWrite(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostWrite(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI PreRead(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostRead(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

// TODO:: Add support for Query/Set Information and Security operations
//FLT_PREOP_CALLBACK_STATUS FLTAPI PreDirectoryControl(
//    _Inout_ PFLT_CALLBACK_DATA pData,
//    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
//    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);
//
//FLT_POSTOP_CALLBACK_STATUS FLTAPI PostDirectoryControl(
//    _Inout_ PFLT_CALLBACK_DATA pData,
//    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
//    _In_opt_ PVOID pCompletionContext,
//    _In_ FLT_POST_OPERATION_FLAGS Flags);
//
//FLT_PREOP_CALLBACK_STATUS FLTAPI PreQueryInformation(
//    _Inout_ PFLT_CALLBACK_DATA pData,
//    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
//    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);
//
//FLT_POSTOP_CALLBACK_STATUS FLTAPI PostQueryInformation(
//    _Inout_ PFLT_CALLBACK_DATA pData,
//    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
//    _In_opt_ PVOID pCompletionContext,
//    _In_ FLT_POST_OPERATION_FLAGS Flags);
//
//FLT_PREOP_CALLBACK_STATUS FLTAPI PreSetSecurity(
//    _Inout_ PFLT_CALLBACK_DATA pData,
//    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
//    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);
//
//FLT_POSTOP_CALLBACK_STATUS FLTAPI PostSetSecurity(
//    _Inout_ PFLT_CALLBACK_DATA pData,
//    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
//    _In_opt_ PVOID pCompletionContext,
//    _In_ FLT_POST_OPERATION_FLAGS Flags);
//
//FLT_PREOP_CALLBACK_STATUS FLTAPI PreQuerySecurity(
//    _Inout_ PFLT_CALLBACK_DATA pData,
//    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
//    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);
//
//FLT_POSTOP_CALLBACK_STATUS FLTAPI PostQuerySecurity(
//    _Inout_ PFLT_CALLBACK_DATA pData,
//    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
//    _In_opt_ PVOID pCompletionContext,
//    _In_ FLT_POST_OPERATION_FLAGS Flags);

//=============================================================================
// COMMUNICATION PORT FUNCTIONS
//=============================================================================

NTSTATUS FLTAPI FilterConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie);

VOID FLTAPI FilterDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie);

NTSTATUS FLTAPI FilterMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

NTSTATUS InitializeCommunicationPort();
VOID CleanupCommunicationPort();

//=============================================================================
// FILE AND PATH ANALYSIS FUNCTIONS
//=============================================================================

BOOLEAN IsSystemFile(PUNICODE_STRING FilePath);
BOOLEAN IsExecutableFile(PUNICODE_STRING FilePath);
BOOLEAN IsScriptFile(PUNICODE_STRING FilePath);
BOOLEAN IsDocumentFile(PUNICODE_STRING FilePath);
BOOLEAN IsSensitiveFile(PUNICODE_STRING FilePath);
BOOLEAN IsSuspiciousPath(PUNICODE_STRING FilePath);

//=============================================================================
// PROCESS ANALYSIS FUNCTIONS
//=============================================================================

//       TODO:: Add process analysis functions

//=============================================================================
// EVENT SENDING AND MEMORY MANAGEMENT
//=============================================================================
NTSTATUS
SendFilesystemEvent(
    FsEventType eventType,
    PSTREAM_HANDLE_CONTEXT pStreamCtx,
    PINSTANCE_CONTEXT pinstCtx
);
// Event pool
PFILE_SYSTEM_EVENT AllocateEventFromPool();
VOID FreeEventFromPool(_In_ PFILE_SYSTEM_EVENT Event);

//=============================================================================
// UTILITY FUNCTIONS
//=============================================================================

LARGE_INTEGER GetCurrentTimeStamp();
//NTSTATUS GetNormalizedFilePath(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PUNICODE_STRING NormalizedPath);
//NTSTATUS QueryFileSize(PFLT_INSTANCE pInstance, PFILE_OBJECT pFileObject, PULONGLONG pFileSize);
//ULONG GetRequestorProcessId(PFLT_CALLBACK_DATA pData);
//VOID DebugPrintAccessMask(ACCESS_MASK Access);
//
//// String utilities
//PWCHAR RtlFindUnicodeSubstring(PUNICODE_STRING String, PUNICODE_STRING Substring);
//PCWSTR ConvertDriverTypeToString(VOLUME_DRIVER_TYPE DriverType);

//=============================================================================
// DISK AND VOLUME UTILITIES
//=============================================================================

//NTSTATUS GetDiskPdoName(PDEVICE_OBJECT pVolumeDeviceObject, UNICODE_STRING* pDst, PVOID* ppBuffer);

//=============================================================================
// CALLBACK REGISTRATION ARRAYS
//=============================================================================

extern CONST FLT_OPERATION_REGISTRATION c_Callbacks[];
extern CONST FLT_CONTEXT_REGISTRATION c_ContextRegistration[];
extern CONST FLT_REGISTRATION c_FilterRegistration;
