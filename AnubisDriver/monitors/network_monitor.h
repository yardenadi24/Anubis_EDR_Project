#pragma once
// WFP headers — must come after ntddk/ntifs
#include "commons.h"
#ifndef NDIS_WDM
#define NDIS_WDM    1
#endif
#ifndef NDIS680
#define NDIS680     1
#endif
// NDIS must come before fwpsk.h — fwpsk.h uses NET_BUFFER_LIST
// but does NOT include ndis.h itself
#include <ndis.h>

#include <fwpmk.h>
#include <fwpsk.h>
#include <fwpvi.h>


// {A1B2C3D4-E5F6-7890-ABCD-EF1234567801}  Bind / Listen (ALE AUTH LISTEN V4)
DEFINE_GUID(ANUBIS_CALLOUT_BIND_V4,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x01);

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567802}  Connect request (ALE AUTH CONNECT V4)
DEFINE_GUID(ANUBIS_CALLOUT_CONNECT_V4,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x02);

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567803}  Accept / Recv (ALE AUTH RECV ACCEPT V4)
DEFINE_GUID(ANUBIS_CALLOUT_ACCEPT_V4,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x03);

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567804}  Flow established (ALE FLOW ESTABLISHED V4)
DEFINE_GUID(ANUBIS_CALLOUT_FLOW_V4,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x04);

// Sublayer for all Anubis filters
// {A1B2C3D4-E5F6-7890-ABCD-EF1234567810}
DEFINE_GUID(ANUBIS_SUBLAYER_GUID,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x10);

typedef enum _NET_EVENT_STATE {
    NET_PENDING = 0,    // Waiting for agent verdict
    NET_IN_PROGRESS = 1,    // Agent has dequeued but not yet replied
    NET_PROCESSED = 2,    // Agent replied; callout can continue
} NET_EVENT_STATE;

typedef struct _NET_EVENT {
    LIST_ENTRY      ListEntry;

    // Identification
    ULONG           ProcessId;
    WCHAR           ProcessName[MAX_PROCESS_NAME_SIZE];
    ULONG64         ConnectionId;           // Unique flow/event ID

    // Network info
    NET_EVENT_TYPE  EventType;
    NET_PROTOCOL    Protocol;
    NET_DIRECTION   Direction;
    ULONG           LocalAddress;           // IPv4, network byte order
    USHORT          LocalPort;              // Host byte order
    ULONG           RemoteAddress;          // IPv4, network byte order
    USHORT          RemotePort;             // Host byte order
} NET_EVENT, * PNET_EVENT;

typedef struct _NETWORK_MONITOR {
    LIST_ENTRY      g_NetMonList;           // Pending event queue
    KSPIN_LOCK      g_NetMonLock;           // Protects the list
    BOOLEAN         g_Monitor;             // Monitoring active flag
    LONG            g_AgentPID;            // PID of the agent process

    // WFP handles
    HANDLE          g_EngineHandle;         // BFE engine handle
    UINT32          g_CalloutIdBind;        // Registered callout IDs
    UINT32          g_CalloutIdConnect;
    UINT32          g_CalloutIdAccept;
    UINT32          g_CalloutIdFlow;

    volatile ULONG64 g_NextConnectionId;   // Monotonic event ID counter

} NETWORK_MONITOR, * PNETWORK_MONITOR;

extern PNETWORK_MONITOR g_pNetMonitor;

// Initialize: registers WFP callouts and adds filters
PNETWORK_MONITOR
InitializeNetworkMonitor(
    _In_ PDEVICE_OBJECT DeviceObject
);

VOID ReleaseFsEvent(
    PNET_EVENT pNetEvent
);

// Uninitialize: removes filters, unregisters callouts
VOID
UninitializeNetworkMonitor();

VOID
NetCalloutClassifyBind(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64                                  flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut
);

VOID
NetCalloutClassifyConnect(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64                                  flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut
);

VOID
NetCalloutClassifyAccept(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64                                  flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut
);

VOID
NetCalloutClassifyFlow(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64                                  flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS
NetCalloutNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE   notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter
);

NTSTATUS
NetEnqueueEvent(
    _In_ NET_EVENT_TYPE     EventType,
    _In_ NET_PROTOCOL       Protocol,
    _In_ NET_DIRECTION      Direction,
    _In_ ULONG              ProcessId,
    _In_ ULONG              LocalAddress,
    _In_ USHORT             LocalPort,
    _In_ ULONG              RemoteAddress,
    _In_ USHORT             RemotePort
);

PNET_EVENT
NetFindEventSafe(
    _In_ ULONG64 ConnectionId
);

VOID
NetReleaseEvent(
    _In_ PNET_EVENT pEntry
);

VOID
NetGetProcessName(
    _In_  ULONG  ProcessId,
    _Out_ PWCHAR Buffer,
    _In_  ULONG  BufferChars
);

NTSTATUS
NetworkMonitorDispatchDeviceControl(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp,
    ULONG IoCode,
    ULONG& Written);
