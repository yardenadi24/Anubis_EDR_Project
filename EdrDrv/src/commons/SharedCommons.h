#pragma once

// Avoid including kernel or user headers directly
#define MAX_PATH 260
#define BASE_DEVICE_NAME  L"AnubisEdrDevice"
#define EVENT_TYPE_WCHAR_LENGTH 30

//=============================================================================
// MEMORY TAGS AND CONSTANTS
//=============================================================================

#define EDR_MEMORY_TAG 'RdnA'  // 'AnDR' in little endian
#define MAX_PATH_LENGTH 260
#define MAX_PROCESS_PATH_LENGTH 512
#define MAX_COMMAND_LINE_LENGTH 1024

typedef unsigned long ULONG;
typedef UCHAR BOOLEAN;


//=============================================================================
// EVENT TYPES - UNIFIED DESIGN
//=============================================================================

// Single event type enum for all EDR events
typedef enum _kEventType : ULONG {
    // Process events
    ProcessCreate = 1,
    ProcessTerminate = 2,
    ProcessAccess = 3,

    // File system events (unified)
    FileSystemOperation = 10,

    // Network events
    NetworkConnection = 20,
    NetworkData = 21,

    // Registry events (Place holder)
    RegistryOperation = 30,

    // Threat detection events
    ThreatDetection = 100,
    PolicyViolation = 101,

    // System events
    DriverLoad = 200,
    ServiceChange = 201,

    Last = 999
} kEventType;

//=============================================================================
// COMMON EVENT HEADER
//=============================================================================

typedef struct _EVENT_HEADER {
    kEventType EventType;           // Type of event
    LARGE_INTEGER TimeStamp;        // When the event occurred
    ULONG ProcessId;                // Process that triggered the event
    ULONG SequenceNumber;           // For event ordering
    ULONG Size;                     // Total size of the event structure
    ULONG Version;                  // Event structure version
} EVENT_HEADER, * PEVENT_HEADER;

//=============================================================================
// FILE SYSTEM OPERATION TYPES AND FLAGS (from FileMonitorFilter.h)
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

//=============================================================================
// OPERATION-SPECIFIC DATA STRUCTURES
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

// Information query/set data
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

typedef struct _AGENT_PROCESS_EVENT {
    ULONG ProcessId;
    WCHAR ImageFileName[MAX_PATH];
    BOOLEAN AllowProcess;
}AGENT_PROCESS_EVENT, * PAGENT_PROCESS_EVENT;

//=============================================================================
// UNIFIED FILE SYSTEM EVENT STRUCTURE
//=============================================================================


enum class kEventType
{
    ProcessCreate = 0,
    ProcessTerminate,
    RegistryKeyNameChange,
    RegistryKeyDelete,
    RegistryValueSet,
    RegistryValueDelete,
    FileCreate,
    FileDelete,
    FileClose,
    FileDataChange,
    FileDataRead,
    FileDataWrite,
    DirectoryEnum,
    FileQuery,
    SecurityChange,
    SecurityQuery,
    ProcessOpen,
    NetworkConnect,
    NetworkDns,
    NetworkHttp,

    Last
};

// Common header for all events
typedef struct _EVENT_HEADER {
    ULONG  RawEventId;
    LARGE_INTEGER TimeStamp;
    kEventType  EventType;  // EVENT_TYPE_PROCESS, EVENT_TYPE_REGISTRY, etc.
    ULONG ProcessId;
} EVENT_HEADER, * PEVENT_HEADER;

// Process Event
typedef struct _PROCESS_EVENT {
    EVENT_HEADER Header;
    ULONG  ProcessParentPid;
    ULONG  ProcessCreatorPid;
    WCHAR  ProcessCmdLine[512];
    WCHAR  ProcessImageFile[260];
    WCHAR  ProcessUserSid[128];
    BOOLEAN ProcessIsElevated;
    ULONG  ProcessElevationType;  // TOKEN_ELEVATION_TYPE
    LARGE_INTEGER ProcessCreationTime;
    LARGE_INTEGER ProcessDeletionTime;
    LONG   ProcessExitCode;
} PROCESS_EVENT, * PPROCESS_EVENT;

// Registry Event
typedef struct _REGISTRY_EVENT {
    EVENT_HEADER Header;
    WCHAR  RegistryPath[512];
    WCHAR  RegistryKeyNewName[256];
    WCHAR  RegistryName[256];
    ULONG  RegistryDataType;
    ULONG  RegistryDataSize;
    UCHAR  RegistryRawData[1024];  // Variable size in practice
} REGISTRY_EVENT, * PREGISTRY_EVENT;

// File Event
typedef struct _FILE_EVENT {
    EVENT_HEADER Header;
    WCHAR  FilePath[512];
    WCHAR  FileVolumeGuid[40];
    WCHAR  FileVolumeType[EVENT_TYPE_WCHAR_LENGTH];
    WCHAR  FileVolumeDevice[256];
    CHAR  FileRawHash[65];  // SHA256 as hex string
} FILE_EVENT, * PFILE_EVENT;


// Process Access Event
typedef struct _PROCESS_ACCESS_EVENT {
    EVENT_HEADER Header;
    ULONG  TargetProcessPid;
    ULONG  AccessMask;
} PROCESS_ACCESS_EVENT, * PPROCESS_ACCESS_EVENT;



// Device type
#define FILE_DEVICE_EDR   0x8000

// Access types
#define EDR_IOCTL_METHOD_BUFFERED  METHOD_BUFFERED
#define EDR_IOCTL_FILE_ANY_ACCESS  FILE_ANY_ACCESS

// Macro to define control codes
#define EDR_CTL_CODE_BUFFERED(Function) \
    CTL_CODE(FILE_DEVICE_EDR, Function, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOCTLs
#define IOCTL_GET_PROCESS_EVENT             EDR_CTL_CODE_BUFFERED(0x800)
#define IOCTL_POST_PROCESS_VERDICT          EDR_CTL_CODE_BUFFERED(0x801)
#define IOCTL_START_MONITORING              EDR_CTL_CODE_BUFFERED(0x802)
#define IOCTL_STOP_MONITORING              EDR_CTL_CODE_BUFFERED(0x803)


/*
       * Buffered I/O
       +----------------+
       |  User Buffer   |
       +----------------+
              |
              v (copied by I/O Manager)
       +----------------+
       | System Buffer  |  <-- Accessible by Driver
       +----------------+
              |
              v (copied back by I/O Manager)
       +----------------+
       |  User Buffer   |
       +----------------+


        * Direct I/O
        In:
       +----------------+
       |  User Buffer   |  (input only)
       +----------------+
              |
              v (I/O Manager creates MDL)
       +-----------------------+
       |  MDL (mapped buffer)  |  <-- Read-only for driver
       +-----------------------+
              |
              v
       +-----------------------+
       | Driver reads input    |
       +-----------------------+

       Out:
       +----------------+
       |  User Buffer   |  (output only)
       +----------------+
              |
              v (I/O Manager creates MDL)
       +-----------------------+
       |  MDL (mapped buffer)  |  <-- Writable by driver
       +-----------------------+
              |
              v
       +------------------------+
       | Driver writes output   |
       +------------------------+
*/