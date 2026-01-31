#pragma once
#include "SharedCommons.h"

// Process Event
//typedef struct _PROCESS_EVENT {
//    EVENT_HEADER Header;
//    ULONG  ProcessParentPid;
//    ULONG  ProcessCreatorPid;
//    WCHAR  ProcessCmdLine[512];
//    WCHAR  ProcessImageFile[260];
//    WCHAR  ProcessUserSid[128];
//    BOOLEAN ProcessIsElevated;
//    ULONG  ProcessElevationType;  // TOKEN_ELEVATION_TYPE
//    LARGE_INTEGER ProcessCreationTime;
//    LARGE_INTEGER ProcessDeletionTime;
//    LONG   ProcessExitCode;
//} PROCESS_EVENT, * PPROCESS_EVENT;

typedef struct _AGENT_PROCESS_EVENT {
    ULONG ProcessId;
    WCHAR ImageFileName[MAX_PATH];
    BOOLEAN AllowProcess;
}AGENT_PROCESS_EVENT, * PAGENT_PROCESS_EVENT;
