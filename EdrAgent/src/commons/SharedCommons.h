#pragma once
#include <Windows.h>

// Avoid including kernel or user headers directly
#define MAX_PATH 260
#define BASE_DEVICE_NAME  L"AnubisEdrDevice"

typedef unsigned long ULONG;
typedef UCHAR BOOLEAN;

typedef struct _AGENT_PROCESS_EVENT {
    ULONG ProcessId;
    WCHAR ImageFileName[MAX_PATH];
    BOOLEAN AllowProcess;
}AGENT_PROCESS_EVENT, * PAGENT_PROCESS_EVENT;

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