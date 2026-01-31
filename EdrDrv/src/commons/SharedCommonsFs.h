#pragma once
#include "SharedCommons.h"

//=============================================================================
// FILE SYSTEM OPERATION TYPES AND FLAGS (from FileMonitorFilter.h)
//=============================================================================

// Communication port constants
#define FILTER_PORT_NAME L"\\AnubisFileMonitorPort"
#define MAX_CONNECTIONS 1
#define HASH_STRING_LENGTH 65

enum class FsEventType
{
    FileCreate,
    FileDelete,
    FileChanged,
    FileDataRead,
    FileDataWrite,
    FileClosed,
    Last
};

// File system operation types
typedef enum _FILE_OPERATION_TYPE : ULONG {
    FILE_OP_UNKNOWN ,
    FILE_OP_CREATE ,
    FILE_OP_WRITE ,
    FILE_OP_READ ,
    FILE_OP_DELETE ,
    FILE_OP_CHANGED ,
    FILE_OP_CLOSE ,
    FILE_OP_CLEANUP ,
    FILE_OP_SET_INFO ,
    FILE_OP_QUERY_INFO ,
    FILE_OP_SET_SECURITY ,
    FILE_OP_QUERY_SECURITY,
    FILE_OP_DIRECTORY_ENUM,
    FILE_OP_RENAME,
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

//typedef enum _FILE_INFORMATION_CLASS {
//    FileDirectoryInformation = 1,
//    FileFullDirectoryInformation = 2,
//    FileBothDirectoryInformation = 3,
//    FileBasicInformation = 4,
//    FileStandardInformation = 5,
//    FileInternalInformation = 6,
//    FileEaInformation = 7,
//    FileAccessInformation = 8,
//    FileNameInformation = 9,
//    FileRenameInformation = 10,
//    FileLinkInformation = 11,
//    FileNamesInformation = 12,
//    FileDispositionInformation = 13,
//    FilePositionInformation = 14,
//    FileFullEaInformation = 15,
//    FileModeInformation = 16,
//    FileAlignmentInformation = 17,
//    FileAllInformation = 18,
//    FileAllocationInformation = 19,
//    FileEndOfFileInformation = 20,
//    FileAlternateNameInformation = 21,
//    FileStreamInformation = 22,
//    FilePipeInformation = 23,
//    FilePipeLocalInformation = 24,
//    FilePipeRemoteInformation = 25,
//    FileMailslotQueryInformation = 26,
//    FileMailslotSetInformation = 27,
//    FileCompressionInformation = 28,
//    FileObjectIdInformation = 29,
//    FileCompletionInformation = 30,
//    FileMoveClusterInformation = 31,
//    FileQuotaInformation = 32,
//    FileReparsePointInformation = 33,
//    FileNetworkOpenInformation = 34,
//    FileAttributeTagInformation = 35,
//    FileTrackingInformation = 36,
//    FileIdBothDirectoryInformation = 37,
//    FileIdFullDirectoryInformation = 38,
//    FileValidDataLengthInformation = 39,
//    FileShortNameInformation = 40,
//    FileIoCompletionNotificationInformation = 41,
//    FileIoStatusBlockRangeInformation = 42,
//    FileIoPriorityHintInformation = 43,
//    FileSfioReserveInformation = 44,
//    FileSfioVolumeInformation = 45,
//    FileHardLinkInformation = 46,
//    FileProcessIdsUsingFileInformation = 47,
//    FileNormalizedNameInformation = 48,
//    FileNetworkPhysicalNameInformation = 49,
//    FileIdGlobalTxDirectoryInformation = 50,
//    FileIsRemoteDeviceInformation = 51,
//    FileUnusedInformation = 52,
//    FileNumaNodeInformation = 53,
//    FileStandardLinkInformation = 54,
//    FileRemoteProtocolInformation = 55,
//    FileRenameInformationBypassAccessCheck = 56,
//    FileLinkInformationBypassAccessCheck = 57,
//    FileVolumeNameInformation = 58,
//    FileIdInformation = 59,
//    FileIdExtdDirectoryInformation = 60,
//    FileReplaceCompletionInformation = 61,
//    FileHardLinkFullIdInformation = 62,
//    FileIdExtdBothDirectoryInformation = 63,
//    FileDispositionInformationEx = 64,
//    FileRenameInformationEx = 65,
//    FileRenameInformationExBypassAccessCheck = 66,
//    FileDesiredStorageClassInformation = 67,
//    FileStatInformation = 68,
//    FileMemoryPartitionInformation = 69,
//    FileStatLxInformation = 70,
//    FileCaseSensitiveInformation = 71,
//    FileLinkInformationEx = 72,
//    FileLinkInformationExBypassAccessCheck = 73,
//    FileStorageReserveIdInformation = 74,
//    FileCaseSensitiveInformationForceAccessCheck = 75,
//    FileKnownFolderInformation = 76,
//    FileStatBasicInformation = 77,
//    FileId64ExtdDirectoryInformation = 78,
//    FileId64ExtdBothDirectoryInformation = 79,
//    FileIdAllExtdDirectoryInformation = 80,
//    FileIdAllExtdBothDirectoryInformation = 81,
//    FileStreamReservationInformation,
//    FileMupProviderInfo,
//    FileMaximumInformation
//} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;


#define IS_ESSENTIAL_OPERATION(op) \
    ((op) == FILE_OP_CREATE || (op) == FILE_OP_WRITE || \
     (op) == FILE_OP_DELETE || (op) == FILE_OP_RENAME)

#define IS_IMPORTANT_OPERATION(op) \
    ((op) == FILE_OP_SET_INFO || (op) == FILE_OP_SET_SECURITY)

// Check if file type should be monitored
#define IS_HIGH_PRIORITY_FILE(flags) \
    ((flags) & (FILE_EVENT_FLAG_EXECUTABLE | FILE_EVENT_FLAG_SCRIPT | \
                FILE_EVENT_FLAG_SYSTEM_FILE | FILE_EVENT_FLAG_DOCUMENT | \
                FILE_EVENT_FLAG_SENSITIVE))

// Check for high-risk indicators
#define IS_HIGH_RISK_EVENT(flags) \
    ((flags) & (FILE_EVENT_FLAG_HIGH_RISK_OPERATION | \
                FILE_EVENT_FLAG_SUSPICIOUS_PATH | \
                FILE_EVENT_FLAG_PROCESS_UNTRUSTED))

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
    UCHAR DataHashHex[HASH_STRING_LENGTH]; // SHA-256
    BOOLEAN HasHash;
} FILE_IO_DATA, * PFILE_IO_DATA;

// Information query/set data
typedef struct _FILE_INFO_DATA {
    ULONG InformationClass;
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
    ULONG InformationClass;
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

typedef struct _FILE_SYSTEM_EVENT {
    
    // Common header
    EVENT_HEADER Header;
    FsEventType FsEventType;
    FILE_EVENT_FLAGS Flags;
    // Core file information
    WCHAR FilePath[MAX_PATH]; 
    WCHAR ProcessPath[MAX_PATH]; // TODO
    WCHAR VolumeGuid[MAX_PATH];
    WCHAR DeviceName[MAX_PATH];
	VOLUME_DRIVER_TYPE DriverType;

    // Operation details
    FILE_OPERATION_TYPE Operation;
    
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
