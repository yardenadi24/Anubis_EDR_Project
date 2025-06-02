#pragma once
// Avoid including kernel or user headers directly
#define MAX_PATH 260
#define BASE_DEVICE_NAME  L"AnubisEdrDevice"
#define EVENT_TYPE_WCHAR_LENGTH 30


typedef unsigned long ULONG;
typedef UCHAR BOOLEAN;

typedef struct _AGENT_PROCESS_EVENT {
    ULONG ProcessId;
    WCHAR ImageFileName[MAX_PATH];
    BOOLEAN AllowProcess;
}AGENT_PROCESS_EVENT, * PAGENT_PROCESS_EVENT;


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