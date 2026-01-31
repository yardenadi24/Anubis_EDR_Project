#pragma once

// Avoid including kernel or user headers directly
#define MAX_PATH 260
#define BASE_DEVICE_NAME  L"AnubisEdrDevice"
#define EVENT_TYPE_WCHAR_LENGTH 30

//=============================================================================
// MEMORY TAGS AND CONSTANTS
//=============================================================================

#define MAX_PATH_LENGTH 260
#define MAX_PROCESS_PATH_LENGTH 512
#define MAX_COMMAND_LINE_LENGTH 1024

// Defines to avoid including Windows headers
//UCHAR
typedef unsigned char UCHAR;
// BOOLEAN
typedef UCHAR BOOLEAN;
// ULONG
typedef long LONG;
typedef unsigned long ULONG;
// WCHAR
//typedef unsigned short WCHAR;
// CHAR
typedef char CHAR;
// LARGE_INTEGER
//typedef struct _LARGE_INTEGER {
//    __int64 QuadPart;
//} LARGE_INTEGER;
// NTSTATUS
typedef long NTSTATUS;
// SECURITY_INFORMATION
typedef ULONG SECURITY_INFORMATION;
// ACCESS_MASK
typedef ULONG ACCESS_MASK;

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



//=============================================================================
// EVENT TYPES - UNIFIED DESIGN
//=============================================================================

enum class EventType
{
    Process = 0,
    Registry,
    Filesystem,
    Network,
    Unknown
};

//=============================================================================
// COMMON EVENT HEADER
//=============================================================================

typedef struct _EVENT_HEADER {
    EventType EventType;           // Type of event
    UINT64 TimeStamp;        // When the event occurred
    ULONG ProcessId;                // Process that triggered the event
    ULONG Size;                     // Total size of the event structure
} EVENT_HEADER, * PEVENT_HEADER;


// Registry Event
typedef struct _REGISTRY_EVENT {
    EVENT_HEADER Header;
    EventType EventSubType;
    WCHAR  RegistryPath[512];
    WCHAR  RegistryKeyNewName[256];
    WCHAR  RegistryName[256];
    ULONG  RegistryDataType;
    ULONG  RegistryDataSize;
    UCHAR  RegistryRawData[1024];  // Variable size in practice
} REGISTRY_EVENT, * PREGISTRY_EVENT;



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