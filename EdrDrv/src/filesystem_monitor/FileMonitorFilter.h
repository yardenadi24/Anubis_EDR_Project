#pragma once

#include <fltKernel.h>
#include <bcrypt.h>
#include <ntstrsafe.h>
#include <Ntddstor.h>
#include "../Commons/commons.h"

//=============================================================================
// CONSTANTS AND DEFINITIONS
//=============================================================================

#define FILE_SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define MAX_DEVICE_NAME_LENGTH 260
#define HASH_STRING_LENGTH 65
#define MAX_HASH_BYTES 32
#define SEQUENTIAL_THRESHOLD_BYTES (1024 * 1024)
#define SEQUENTIAL_TIMEOUT_SECONDS 5

// Communication port constants
#define FILTER_PORT_NAME L"\\AnubisFileMonitorPort"
#define MAX_CONNECTIONS 1

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
// ENUMERATIONS
//=============================================================================

// File system operation types
typedef enum _FILE_OPERATION_TYPE : ULONG {
    FILE_OP_UNKNOWN = 0,
    FILE_OP_CREATE = 1,
    FILE_OP_WRITE = 2,
    FILE_OP_READ = 3,
    FILE_OP_DELETE = 4,
    FILE_OP_CLOSE = 5,
    FILE_OP_CLEANUP = 6,
    FILE_OP_SET_INFO = 7,
    FILE_OP_QUERY_INFO = 8,
    FILE_OP_SET_SECURITY = 9,
    FILE_OP_QUERY_SECURITY = 10,
    FILE_OP_DIRECTORY_ENUM = 11,
    FILE_OP_RENAME = 12,
    FILE_OP_MAX
} FILE_OPERATION_TYPE;

// File event flags
typedef enum _FILE_EVENT_FLAGS : ULONG {
    FILE_EVENT_FLAG_NONE = 0x00000000,
    FILE_EVENT_FLAG_SYSTEM_FILE = 0x00000001,
    FILE_EVENT_FLAG_EXECUTABLE = 0x00000002,
    FILE_EVENT_FLAG_SCRIPT = 0x00000004,
    FILE_EVENT_FLAG_DOCUMENT = 0x00000008,
    FILE_EVENT_FLAG_SENSITIVE = 0x00000010,
    FILE_EVENT_FLAG_ENCRYPTED = 0x00000020,
    FILE_EVENT_FLAG_COMPRESSED = 0x00000040,
    FILE_EVENT_FLAG_HIDDEN = 0x00000080,
    FILE_EVENT_FLAG_READONLY = 0x00000100,
    FILE_EVENT_FLAG_NETWORK_PATH = 0x00000200,
    FILE_EVENT_FLAG_REMOVABLE_MEDIA = 0x00000400,
    FILE_EVENT_FLAG_SUSPICIOUS_PATH = 0x00000800,
    FILE_EVENT_FLAG_RAPID_SEQUENCE = 0x00001000,
    FILE_EVENT_FLAG_LARGE_FILE = 0x00002000,
    FILE_EVENT_FLAG_PROCESS_UNTRUSTED = 0x00004000,
    FILE_EVENT_FLAG_HIGH_RISK_OPERATION = 0x00008000
} FILE_EVENT_FLAGS;

// Volume driver types
enum class VOLUME_DRIVER_TYPE {
    NONE,
    FIXED,
    NETWORK,
    REMOVABLE,
    LAST
};

// File creation status
enum class FILE_CREATION_STATUS {
    NONE,
    CREATED,
    OPENED,
    TRUNCATED,
    LAST
};

// Sequence types
enum class SEQUENCE_TYPE {
    NONE,
    READ,
    WRITE,
    LAST
};

//=============================================================================
// STRUCTURES FOR OPERATION-SPECIFIC DATA
//=============================================================================

// Create/Write operation data
typedef struct _FILE_CREATE_DATA {
    ACCESS_MASK DesiredAccess;
    ULONG CreateDisposition;
    ULONG CreateOptions;
    ULONG FileAttributes;
    ULONG ShareAccess;
    LARGE_INTEGER FileSize;
    BOOLEAN CreatedNewFile;
    BOOLEAN DeleteOnClose;
    BOOLEAN IsExecute;
} FILE_CREATE_DATA, * PFILE_CREATE_DATA;

// Read/Write operation data
typedef struct _FILE_IO_DATA {
    LARGE_INTEGER ByteOffset;
    ULONG Length;
    ULONG ActualBytesTransferred;
    BOOLEAN IsSequential;
    BOOLEAN IsFirstIO;
    BOOLEAN IsLastIO;
    UCHAR DataHash[32]; // SHA-256
    BOOLEAN HasHash;
} FILE_IO_DATA, * PFILE_IO_DATA;

typedef struct _FILE_INFO_DATA {

    FILE_INFORMATION_CLASS InformationClass;
    ULONG BufferLength;
    NTSTATUS OperationStatus;
    union {
        struct {
            LARGE_INTEGER CreationTime;
            LARGE_INTEGER LastAccessTime;
            LARGE_INTEGER LastWriteTime;
            LARGE_INTEGER ChangeTime;
            ULONG FileAttributes;
        } BasicInfo;

        struct {
            LARGE_INTEGER AllocationSize;
            LARGE_INTEGER EndOfFile;
            ULONG NumberOfLinks;
            BOOLEAN DeletePending;
            BOOLEAN Directory;
        } StandardInfo;

        struct {
            BOOLEAN DeleteFile;
        } DispositionInfo;
    };

} FILE_INFO_DATA, * PFILE_INFO_DATA;

// Security operation data
typedef struct _FILE_SECURITY_DATA {
    SECURITY_INFORMATION SecurityInformation;
    ULONG SecurityDescriptorLength;
    BOOLEAN PermissionsChanged;
    BOOLEAN OwnerChanged;
    BOOLEAN InheritanceChanged;
} FILE_SECURITY_DATA, * PFILE_SECURITY_DATA;

// Directory enumeration data
typedef struct _FILE_DIRECTORY_DATA {
    FILE_INFORMATION_CLASS InformationClass;
    ULONG FileCount;
    BOOLEAN ReturnSingleEntry;
    BOOLEAN RestartScan;
    BOOLEAN IndexSpecified;
    WCHAR SearchPattern[64];
} FILE_DIRECTORY_DATA, * PFILE_DIRECTORY_DATA;

// Rename operation data
typedef struct _FILE_RENAME_DATA {
    WCHAR TargetPath[MAX_PATH];
    BOOLEAN ReplaceIfExists;
    BOOLEAN SameDirectory;
    BOOLEAN ExtensionChanged;
    WCHAR OldExtension[16];
    WCHAR NewExtension[16];
} FILE_RENAME_DATA, * PFILE_RENAME_DATA;

//=============================================================================
// UNIFIED FILE SYSTEM EVENT STRUCTURE
//=============================================================================


typedef struct _FILE_SYSTEM_EVENT {
    // Common header
    EVENT_HEADER Header;

    // Core file information
    WCHAR FilePath[MAX_PATH];
    WCHAR ProcessPath[MAX_PATH];
    WCHAR VolumeGuid[64];
    WCHAR VolumeName[32];

    // Operation details
    FILE_OPERATION_TYPE Operation;
    FILE_EVENT_FLAGS Flags;
    NTSTATUS Status;
    ULONG ThreadId;

    // Process context
    LARGE_INTEGER ProcessCreationTime;
    ULONG ParentProcessId;
    WCHAR ProcessCommandLine[512];

    // File context
    LARGE_INTEGER FileId;
    ULONG FileAttributes;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastWriteTime;

    // Operation-specific data
    union {
        FILE_CREATE_DATA Create;
        FILE_IO_DATA IO;
        FILE_INFO_DATA Info;
        FILE_SECURITY_DATA Security;
        FILE_DIRECTORY_DATA Directory;
        FILE_RENAME_DATA Rename;
        UCHAR RawData[512]; // For future extensibility
    } OperationData;

} FILE_SYSTEM_EVENT, * PFILE_SYSTEM_EVENT;

//=============================================================================
// CONTEXT STRUCTURES
//=============================================================================

// Instance context for volume information
typedef struct _INSTANCE_CONTEXT {
    PFLT_INSTANCE pInstance;
    BOOLEAN fSetupIsFinished;
    CHAR sDeviceName[MAX_DEVICE_NAME_LENGTH];
    VOLUME_DRIVER_TYPE DriverType;
    USHORT SectorSize;

    // Volume flags
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
    ULONG_PTR nOpeningProcessId;
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
    _STREAM_HANDLE_CONTEXT();
    ~_STREAM_HANDLE_CONTEXT();

    // Operators
    PVOID __cdecl operator new(size_t, PVOID p) { return p; }
    VOID __cdecl operator delete(PVOID, PVOID) {}

    // Static methods
    static NTSTATUS Initialize(PSTREAM_HANDLE_CONTEXT* ppStreamCtx, PCFLT_RELATED_OBJECTS pFltObjects);
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

// Event pool for performance
typedef struct _EVENT_POOL {
    KSPIN_LOCK Lock;
    SLIST_HEADER FreeList;
    PFILE_SYSTEM_EVENT Events;
    ULONG TotalEvents;
    LONG FreeEvents;
} EVENT_POOL, * PEVENT_POOL;

typedef struct _RATE_LIMIT_ENTRY {
    ULONG ProcessId;
    FILE_OPERATION_TYPE Operation;
    LARGE_INTEGER LastEventTime;
    ULONG EventCount;
    ULONG DropCount;
} RATE_LIMIT_ENTRY, * PRATE_LIMIT_ENTRY;

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
extern EVENT_POOL g_EventPool;

//=============================================================================
// FUNCTION DECLARATIONS
//=============================================================================

// Filter lifecycle
NTSTATUS Initialize(PDRIVER_OBJECT pDriverObj);
VOID Finalize();
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

FLT_PREOP_CALLBACK_STATUS FLTAPI PreDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI PreQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI PreSetSecurity(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostSetSecurity(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI PreQuerySecurity(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* pCompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostQuerySecurity(
    _Inout_ PFLT_CALLBACK_DATA pData,
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_opt_ PVOID pCompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

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
// EVENT CREATION AND ANALYSIS FUNCTIONS
//=============================================================================

NTSTATUS CreateBaseFileEvent(
    _Out_ PFILE_SYSTEM_EVENT Event,
    _In_ FILE_OPERATION_TYPE Operation,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo);

FILE_EVENT_FLAGS AnalyzeFileOperation(
    _In_ PFILE_SYSTEM_EVENT Event,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects);

//=============================================================================
// FILE AND PATH ANALYSIS FUNCTIONS
//=============================================================================

BOOLEAN IsSystemFile(PUNICODE_STRING FilePath);
BOOLEAN IsExecutableFile(PUNICODE_STRING FilePath);
BOOLEAN IsScriptFile(PUNICODE_STRING FilePath);
BOOLEAN IsDocumentFile(PUNICODE_STRING FilePath);
BOOLEAN IsSensitiveFile(PUNICODE_STRING FilePath);
BOOLEAN IsSuspiciousPath(PUNICODE_STRING FilePath);
BOOLEAN IsHighRiskPath(PUNICODE_STRING FilePath);
BOOLEAN IsUserDocumentsPath(PUNICODE_STRING FilePath);
BOOLEAN IsSystemDirectory(PUNICODE_STRING FilePath);
BOOLEAN IsCredentialFile(PUNICODE_STRING FilePath);

//=============================================================================
// PROCESS ANALYSIS FUNCTIONS
//=============================================================================

BOOLEAN IsUntrustedProcess(ULONG ProcessId);
BOOLEAN IsTrustedSystemProcess(ULONG ProcessId);
BOOLEAN IsHighRiskOperation(FILE_OPERATION_TYPE Operation, FILE_EVENT_FLAGS Flags);

//=============================================================================
// EVENT SENDING AND MEMORY MANAGEMENT
//=============================================================================

NTSTATUS SendFileSystemEvent(_In_ PFILE_SYSTEM_EVENT Event);
BOOLEAN ApplyRateLimit(_In_ PFILE_SYSTEM_EVENT Event);


// Event pool management
NTSTATUS InitializeEventPool(_Out_ PEVENT_POOL Pool);
VOID CleanupEventPool(_In_ PEVENT_POOL Pool);
PFILE_SYSTEM_EVENT AllocateEventFromPool(_In_ PEVENT_POOL Pool);
VOID FreeEventToPool(_In_ PEVENT_POOL Pool, _In_ PFILE_SYSTEM_EVENT Event);

//=============================================================================
// UTILITY FUNCTIONS
//=============================================================================

LARGE_INTEGER GetCurrentTimeStamp();
NTSTATUS GetNormalizedFilePath(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PUNICODE_STRING NormalizedPath);
NTSTATUS QueryFileSize(PFLT_INSTANCE pInstance, PFILE_OBJECT pFileObject, PULONGLONG pFileSize);
ULONG GetRequestorProcessId(PFLT_CALLBACK_DATA pData);
VOID DebugPrintAccessMask(ACCESS_MASK Access);

// String utilities
PWCHAR RtlFindUnicodeSubstring(PUNICODE_STRING String, PUNICODE_STRING Substring);
PCWSTR ConvertDriverTypeToString(VOLUME_DRIVER_TYPE DriverType);

//=============================================================================
// DISK AND VOLUME UTILITIES
//=============================================================================

NTSTATUS GetDiskPdoName(PDEVICE_OBJECT pVolumeDeviceObject, UNICODE_STRING* pDst, PVOID* ppBuffer);

//=============================================================================
// CALLBACK REGISTRATION ARRAYS
//=============================================================================

extern CONST FLT_OPERATION_REGISTRATION c_Callbacks[];
extern CONST FLT_CONTEXT_REGISTRATION c_ContextRegistration[];
extern CONST FLT_REGISTRATION c_FilterRegistration;
