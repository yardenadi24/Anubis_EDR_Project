#pragma once
#ifdef ANUBIS_DRV
#pragma message(">>> ANUBIS_DRV IS DEFINED")
#else
#pragma message(">>> ANUBIS_DRV IS NOT DEFINED")
#endif

#define INVALIDE_PROCESS_ID 0xFFFFFFFF

#define MAX_PATH 260
#define BASE_DEVICE_NAME  L"AnubisEdrDevice"

#define MAX_PATH_SIZE               512     // in WCHARs
#define MAX_PROCESS_NAME_SIZE       260     // in WCHARs
#define MAX_IP_STR_SIZE             46      // enough for IPv6 string


// Device type
#define FILE_DEVICE_EDR   0x8000

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)


#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe


#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

// Access types
#define EDR_IOCTL_METHOD_BUFFERED  METHOD_BUFFERED
#define EDR_IOCTL_FILE_ANY_ACCESS  FILE_ANY_ACCESS

// Macro to define control codes
#define EDR_CTL_CODE_BUFFERED(Function) \
    CTL_CODE(FILE_DEVICE_EDR, Function, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Process Monitor IOCTLs
#define IOCTL_GET_PROCESS_EVENT                     EDR_CTL_CODE_BUFFERED(0x800)
#define IOCTL_POST_PROCESS_VERDICT                  EDR_CTL_CODE_BUFFERED(0x801)
#define IOCTL_START_PROCESS_MONITORING              EDR_CTL_CODE_BUFFERED(0x802)
#define IOCTL_STOP_PROCESS_MONITORING               EDR_CTL_CODE_BUFFERED(0x803)

// Filesystem Monitor IOCTLs
#define IOCTL_GET_FS_EVENT                          EDR_CTL_CODE_BUFFERED(0x804)
#define IOCTL_POST_FS_VERDICT                       EDR_CTL_CODE_BUFFERED(0x805)
#define IOCTL_START_FS_MONITORING                   EDR_CTL_CODE_BUFFERED(0x806)
#define IOCTL_STOP_FS_MONITORING                    EDR_CTL_CODE_BUFFERED(0x807)

// Network monitor
#define IOCTL_START_NET_MONITORING                  EDR_CTL_CODE_BUFFERED(0x808)
#define IOCTL_STOP_NET_MONITORING                   EDR_CTL_CODE_BUFFERED(0x809)
#define IOCTL_GET_NET_EVENT                         EDR_CTL_CODE_BUFFERED(0x810)

// Agent Management IOCTLs
// FIX #13: Added IOCTL to allow the agent to register its PID with the driver
// so the minifilter can skip the agent's own file I/O and avoid self-deadlock.
#define IOCTL_SET_AGENT_PID                         EDR_CTL_CODE_BUFFERED(0x812)

// Filesystem operation types
#define FS_OPERATION_CREATE     1   // IRP_MJ_CREATE
#define FS_OPERATION_WRITE      2   // IRP_MJ_WRITE (post-operation)
#define FS_OPERATION_RENAME     3   // IRP_MJ_SET_INFORMATION (FileRenameInformation)
#define FS_OPERATION_DELETE     4   // IRP_MJ_SET_INFORMATION (FileDispositionInformation) or IRP_MJ_CREATE with DELETE_ON_CLOSE
#define FS_OPERATION_SET_INFO   5   // IRP_MJ_SET_INFORMATION (other)


#ifdef ANUBIS_DRV
// Kernel-mode: define only what we need (no windows.h in kernel)
typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef unsigned char BOOLEAN;
typedef unsigned short WCHAR;
typedef int BOOL;
#else
// User-mode: pull in the full Windows API
#include <Windows.h>
#endif

typedef struct _AGENT_PID_INFO {
    ULONG ProcessId;
} AGENT_PID_INFO, *PAGENT_PID_INFO;

struct ScanContext {
    HANDLE hEvent;
    BOOL verdict;           // TRUE = allow, FALSE = block
};

typedef enum _NET_EVENT_TYPE {
    NET_EVENT_BIND = 1,    // Process bound a socket to a local port (listening)
    NET_EVENT_CONNECT = 2,    // Outbound connection request initiated
    NET_EVENT_ACCEPT = 3,    // Inbound connection accepted (listen socket)
    NET_EVENT_ESTABLISHED = 4,    // Connection fully established (flow created)
    NET_EVENT_DISCONNECT = 5,    // Connection closed / endpoint deleted
} NET_EVENT_TYPE;

typedef enum _NET_PROTOCOL {
    NET_PROTO_TCP = 6,
    NET_PROTO_UDP = 17,
    NET_PROTO_OTHER = 0,
} NET_PROTOCOL;

typedef enum _NET_DIRECTION {
    NET_DIR_OUTBOUND = 0,
    NET_DIR_INBOUND = 1,
} NET_DIRECTION;



typedef struct _AGENT_PROCESS_EVENT {
    ULONG ProcessId;
    WCHAR ImageFileName[MAX_PATH];
    BOOLEAN AllowProcess;
}AGENT_PROCESS_EVENT, * PAGENT_PROCESS_EVENT;

// Filesystem event structure (from minifilter driver)
typedef struct _AGENT_FS_EVENT {
    ULONG ProcessId;                    // PID of the process performing the operation
    ULONG Operation;                    // FS_OPERATION_* constant
    WCHAR FilePath[MAX_PATH];           // Full path of the target file
    WCHAR NewFilePath[MAX_PATH];        // New path (used for rename operations)
    ULONG FileSize;             // File size in bytes (if available)
    BOOLEAN IsDirectory;                // TRUE if the target is a directory
    BOOLEAN AllowOperation;             // Verdict: TRUE = allow, FALSE = block
} AGENT_FS_EVENT, * PAGENT_FS_EVENT;

typedef struct _AGENT_NET_EVENT {
    ULONG           ProcessId;
    WCHAR           ProcessName[MAX_PROCESS_NAME_SIZE];
    NET_EVENT_TYPE  EventType;                  // What happened
    NET_PROTOCOL    Protocol;                   // TCP / UDP / Other
    NET_DIRECTION   Direction;                  // Inbound / Outbound
    ULONG           LocalAddress;               // IPv4 in network byte order
    USHORT          LocalPort;                  // Host byte order
    ULONG           RemoteAddress;              // IPv4 in network byte order (0 for bind/listen)
    USHORT          RemotePort;                 // Host byte order (0 for bind/listen)
} AGENT_NET_EVENT, * PAGENT_NET_EVENT;


