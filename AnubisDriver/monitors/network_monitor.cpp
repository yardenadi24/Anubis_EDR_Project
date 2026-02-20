#define INITGUID
#include "network_monitor.h"
#pragma warning(disable: 4996)  // RtlCopyMemory / deprecated helpers
PNETWORK_MONITOR g_pNetMonitor = NULL;

#define NET_VERDICT_TIMEOUT_MS  2000

#define REGISTER_CALLOUT(ClassifyFn, NotifyFn, LayerGuid, CalloutGuid, pCalloutId)          \
    do {                                                                                          \
        FWPS_CALLOUT1 callout = { 0 };                                                           \
        callout.calloutKey      = (CalloutGuid);                                                 \
        callout.classifyFn      = (FWPS_CALLOUT_CLASSIFY_FN1)(ClassifyFn);                      \
        callout.notifyFn        = (FWPS_CALLOUT_NOTIFY_FN1)(NotifyFn);                          \
        callout.flowDeleteFn    = NULL;                                                          \
        Status = FwpsCalloutRegister1(DeviceObject, &callout, (pCalloutId));                    \
        if (!NT_SUCCESS(Status)) {                                                               \
            DbgError("FwpsCalloutRegister1 failed for " #LayerGuid ": 0x%X", Status);           \
            goto Cleanup;                                                                        \
        }                                                                                        \
    } while(FALSE)

#define ADD_CALLOUT_TO_BFE(LayerGuid, CalloutGuid, NameStr)                                 \
    do {                                                                                          \
        FWPM_CALLOUT0 bfeCallout = { 0 };                                                       \
        bfeCallout.calloutKey   = (CalloutGuid);                                                 \
        bfeCallout.displayData.name = (NameStr);                                                 \
        bfeCallout.applicableLayer  = (LayerGuid);                                               \
        Status = FwpmCalloutAdd0(hEngine, &bfeCallout, NULL, NULL);                              \
        if (!NT_SUCCESS(Status) && Status != STATUS_FWP_ALREADY_EXISTS) {                       \
            DbgError("FwpmCalloutAdd0 failed for " #LayerGuid ": 0x%X", Status);                \
            goto Cleanup;                                                                        \
        }                                                                                        \
    } while(FALSE)

#define ADD_FILTER(LayerGuid, CalloutGuid, NameStr)                                          \
    do {                                                                                          \
        FWPM_FILTER0 filter = { 0 };                                                             \
        filter.displayData.name     = (NameStr);                                                 \
        filter.layerKey             = (LayerGuid);                                               \
        filter.subLayerKey          = ANUBIS_SUBLAYER_GUID;                                      \
        filter.weight.type          = FWP_EMPTY;    /* auto-weight */                            \
        filter.numFilterConditions  = 0;            /* match all traffic */                      \
        filter.action.type          = FWP_ACTION_CALLOUT_INSPECTION;                             \
        filter.action.calloutKey    = (CalloutGuid);                                             \
        UINT64 filterId = 0;                                                                     \
        Status = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);                              \
        if (!NT_SUCCESS(Status)) {                                                               \
            DbgError("FwpmFilterAdd0 failed for " #LayerGuid ": 0x%X", Status);                 \
            goto Cleanup;                                                                        \
        }                                                                                        \
    } while(FALSE)

PNETWORK_MONITOR
InitializeNetworkMonitor(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS            Status = STATUS_SUCCESS;
    PNETWORK_MONITOR    pMon = NULL;
    HANDLE              hEngine = NULL;
    BOOLEAN             bEngineOpen = FALSE;

    DbgInfo("Initializing network monitor (WFP callout driver)");

    pMon = (PNETWORK_MONITOR)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(NETWORK_MONITOR), EDR_MEMORY_TAG);
    if (pMon == NULL)
    {
        DbgError("Failed to allocate NETWORK_MONITOR context");
        return NULL;
    }

    RtlZeroMemory(pMon, sizeof(NETWORK_MONITOR));

    InitializeListHead(&pMon->g_NetMonList);
    KeInitializeSpinLock(&pMon->g_NetMonLock);
    pMon->g_Monitor = FALSE;
    pMon->g_AgentPID = INVALIDE_PROCESS_ID;
    pMon->g_NextConnectionId = 1;

    FWPM_SESSION0 session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; // Filters removed on session close

    Status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &hEngine);
    if (!NT_SUCCESS(Status))
    {
        DbgError("FwpmEngineOpen0 failed: 0x%X", Status);
        goto Cleanup;
    }
    pMon->g_EngineHandle = hEngine;
    bEngineOpen = TRUE;

    REGISTER_CALLOUT(NetCalloutClassifyBind, NetCalloutNotify,
        FWPM_LAYER_ALE_AUTH_LISTEN_V4, ANUBIS_CALLOUT_BIND_V4, &pMon->g_CalloutIdBind);
    REGISTER_CALLOUT(NetCalloutClassifyConnect, NetCalloutNotify,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, ANUBIS_CALLOUT_CONNECT_V4, &pMon->g_CalloutIdConnect);
    REGISTER_CALLOUT(NetCalloutClassifyAccept, NetCalloutNotify,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, ANUBIS_CALLOUT_ACCEPT_V4, &pMon->g_CalloutIdAccept);
    REGISTER_CALLOUT(NetCalloutClassifyFlow, NetCalloutNotify,
        FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, ANUBIS_CALLOUT_FLOW_V4, &pMon->g_CalloutIdFlow);

    ADD_CALLOUT_TO_BFE(FWPM_LAYER_ALE_AUTH_LISTEN_V4, ANUBIS_CALLOUT_BIND_V4, (PWSTR)L"AnubisBind");
    ADD_CALLOUT_TO_BFE(FWPM_LAYER_ALE_AUTH_CONNECT_V4, ANUBIS_CALLOUT_CONNECT_V4, (PWSTR)L"AnubisConnect");
    ADD_CALLOUT_TO_BFE(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, ANUBIS_CALLOUT_ACCEPT_V4, (PWSTR)L"AnubisAccept");
    ADD_CALLOUT_TO_BFE(FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, ANUBIS_CALLOUT_FLOW_V4, (PWSTR)L"AnubisFlow");

    {
        FWPM_SUBLAYER0 sublayer = { 0 };
        sublayer.subLayerKey = ANUBIS_SUBLAYER_GUID;
        sublayer.displayData.name = (PWSTR)L"AnubisEdrSublayer";
        sublayer.weight = 0x100;

        Status = FwpmSubLayerAdd0(hEngine, &sublayer, NULL);
        if (!NT_SUCCESS(Status) && Status != STATUS_FWP_ALREADY_EXISTS)
        {
            DbgError("FwpmSubLayerAdd0 failed: 0x%X", Status);
            goto Cleanup;
        }
    }

    // Bind / listen and flow-established are observation only, so CALLOUT_INSPECTION is fine.
    // Connect and accept are blocking capable; use CALLOUT_TERMINATING so we can BLOCK.
    ADD_FILTER(FWPM_LAYER_ALE_AUTH_LISTEN_V4, ANUBIS_CALLOUT_BIND_V4, (PWSTR)L"AnubisFilterBind");
    ADD_FILTER(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, ANUBIS_CALLOUT_ACCEPT_V4, (PWSTR)L"AnubisFilterAccept");
    ADD_FILTER(FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, ANUBIS_CALLOUT_FLOW_V4, (PWSTR)L"AnubisFilterFlow");

    // Connect uses terminating action so we can block outbound connections
    {
        FWPM_FILTER0 filter = { 0 };
        filter.displayData.name = (PWSTR)L"AnubisFilterConnect";
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.subLayerKey = ANUBIS_SUBLAYER_GUID;
        filter.weight.type = FWP_EMPTY;
        filter.numFilterConditions = 0;
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = ANUBIS_CALLOUT_CONNECT_V4;
        UINT64 filterId = 0;
        Status = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
        if (!NT_SUCCESS(Status))
        {
            DbgError("FwpmFilterAdd0 failed for CONNECT layer: 0x%X", Status);
            goto Cleanup;
        }
    }

    DbgInfo("Network monitor (WFP) initialized successfully");
    g_pNetMonitor = pMon;
    return pMon;

Cleanup:
    if (bEngineOpen)
    {
        FwpmEngineClose0(hEngine);
    }
    if (pMon)
    {
        // Unregister any callouts already registered
        if (pMon->g_CalloutIdBind)    FwpsCalloutUnregisterById0(pMon->g_CalloutIdBind);
        if (pMon->g_CalloutIdConnect) FwpsCalloutUnregisterById0(pMon->g_CalloutIdConnect);
        if (pMon->g_CalloutIdAccept)  FwpsCalloutUnregisterById0(pMon->g_CalloutIdAccept);
        if (pMon->g_CalloutIdFlow)    FwpsCalloutUnregisterById0(pMon->g_CalloutIdFlow);

        ExFreePoolWithTag(pMon, EDR_MEMORY_TAG);
    }
    return NULL;
}

VOID ReleaseFsEvent(
    PNET_EVENT pNetEvent
)
{
    if (pNetEvent != NULL)
    {
        ExFreePoolWithTag(pNetEvent, EDR_MEMORY_TAG);
    }
}

VOID
UninitializeNetworkMonitor()
{
    if (g_pNetMonitor == NULL) return;

    DbgInfo("Uninitializing network monitor");

    // Stop accepting new events
    g_pNetMonitor->g_Monitor = FALSE;

    // Close BFE session � dynamic session removes all filters/callouts/sublayers automatically
    if (g_pNetMonitor->g_EngineHandle)
    {
        FwpmEngineClose0(g_pNetMonitor->g_EngineHandle);
        g_pNetMonitor->g_EngineHandle = NULL;
    }

    // Unregister kernel-side callouts
    if (g_pNetMonitor->g_CalloutIdBind)    FwpsCalloutUnregisterById0(g_pNetMonitor->g_CalloutIdBind);
    if (g_pNetMonitor->g_CalloutIdConnect) FwpsCalloutUnregisterById0(g_pNetMonitor->g_CalloutIdConnect);
    if (g_pNetMonitor->g_CalloutIdAccept)  FwpsCalloutUnregisterById0(g_pNetMonitor->g_CalloutIdAccept);
    if (g_pNetMonitor->g_CalloutIdFlow)    FwpsCalloutUnregisterById0(g_pNetMonitor->g_CalloutIdFlow);

    // Drain and free any remaining events in the queue
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_pNetMonitor->g_NetMonLock, &oldIrql);
    while (!IsListEmpty(&g_pNetMonitor->g_NetMonList))
    {
        PLIST_ENTRY pEntry = RemoveHeadList(&g_pNetMonitor->g_NetMonList);
        PNET_EVENT pItem = CONTAINING_RECORD(pEntry, NET_EVENT, ListEntry);\
        ReleaseFsEvent(pItem);
    }
    KeReleaseSpinLock(&g_pNetMonitor->g_NetMonLock, oldIrql);

    ExFreePoolWithTag(g_pNetMonitor, EDR_MEMORY_TAG);
    g_pNetMonitor = NULL;
    DbgInfo("Network monitor uninitialized");
}

VOID
NetGetProcessName(
    _In_  ULONG  ProcessId,
    _Out_ PWCHAR Buffer,
    _In_  ULONG  BufferChars)
{
    RtlZeroMemory(Buffer, BufferChars * sizeof(WCHAR));

    PEPROCESS pProcess = NULL;
    NTSTATUS  Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &pProcess);
    if (!NT_SUCCESS(Status) || pProcess == NULL) return;

    // SeLocateProcessImageName is the cleanest kernel API for this
    PUNICODE_STRING pImageName = NULL;
    Status = SeLocateProcessImageName(pProcess, &pImageName);
    if (NT_SUCCESS(Status) && pImageName != NULL)
    {
        ULONG copyChars = min(pImageName->Length / sizeof(WCHAR), BufferChars - 1);
        RtlCopyMemory(Buffer, pImageName->Buffer, copyChars * sizeof(WCHAR));
        Buffer[copyChars] = L'\0';
        ExFreePool(pImageName);
    }
    ObDereferenceObject(pProcess);
}

NTSTATUS
NetEnqueueEvent(
    _In_ NET_EVENT_TYPE  EventType,
    _In_ NET_PROTOCOL    Protocol,
    _In_ NET_DIRECTION   Direction,
    _In_ ULONG           ProcessId,
    _In_ ULONG           LocalAddress,
    _In_ USHORT          LocalPort,
    _In_ ULONG           RemoteAddress,
    _In_ USHORT          RemotePort)
{

    if (g_pNetMonitor == NULL || !g_pNetMonitor->g_Monitor)
        return STATUS_SUCCESS;

    // Allocate event entry from non-paged pool (we may be at DISPATCH_LEVEL)
    PNET_EVENT pEvt = (PNET_EVENT)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(NET_EVENT), EDR_MEMORY_TAG);
    if (pEvt == NULL)
    {
        DbgError("NetEnqueueEvent: allocation failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pEvt, sizeof(NET_EVENT));

    pEvt->ProcessId = ProcessId;
    pEvt->EventType = EventType;
    pEvt->Protocol = Protocol;
    pEvt->Direction = Direction;
    pEvt->LocalAddress = LocalAddress;
    pEvt->LocalPort = LocalPort;
    pEvt->RemoteAddress = RemoteAddress;
    pEvt->RemotePort = RemotePort;
    // Resolve process name (best effort; may fail for system PIDs)
	// Will happen for now when retrieving the event at dispatch level

    // Enqueue
	KIRQL oldIrql;
    KeAcquireSpinLock(&g_pNetMonitor->g_NetMonLock, &oldIrql);
    InsertTailList(&g_pNetMonitor->g_NetMonList, &pEvt->ListEntry);
    KeReleaseSpinLock(&g_pNetMonitor->g_NetMonLock, oldIrql);

    return STATUS_SUCCESS;
}

PNET_EVENT
NetFindEventSafe(_In_ ULONG64 ConnectionId)
{
    if (g_pNetMonitor == NULL) return NULL;

    PNET_EVENT pFound = NULL;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_pNetMonitor->g_NetMonLock, &oldIrql);
    PLIST_ENTRY pEntry = g_pNetMonitor->g_NetMonList.Flink;
    while (pEntry != &g_pNetMonitor->g_NetMonList)
    {
        PNET_EVENT pEvt = CONTAINING_RECORD(pEntry, NET_EVENT, ListEntry);
        if (pEvt->ConnectionId == ConnectionId)
        {
            pFound = pEvt;
            break;
        }
        pEntry = pEntry->Flink;
    }
    KeReleaseSpinLock(&g_pNetMonitor->g_NetMonLock, oldIrql);

    return pFound;
}

VOID
NetReleaseEvent(_In_ PNET_EVENT pEntry)
{
    if (pEntry)
        ExFreePoolWithTag(pEntry, EDR_MEMORY_TAG);
}

NTSTATUS
NetCalloutNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE   notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static VOID
ExtractBindFields(
    _In_ const FWPS_INCOMING_VALUES0* vals,
    _Out_ ULONG* pLocalAddr,
    _Out_ USHORT* pLocalPort,
    _Out_ NET_PROTOCOL* pProto)
{
    *pLocalAddr = vals->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS].value.uint32;
    *pLocalPort = vals->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_PORT].value.uint16;
    *pProto = NET_PROTO_TCP;
}

static VOID
ExtractConnectFields(
    _In_ const FWPS_INCOMING_VALUES0* vals,
    _Out_ ULONG* pLocalAddr,
    _Out_ USHORT* pLocalPort,
    _Out_ ULONG* pRemoteAddr,
    _Out_ USHORT* pRemotePort,
    _Out_ NET_PROTOCOL* pProto)
{
    *pLocalAddr = vals->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    *pLocalPort = vals->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
    *pRemoteAddr = vals->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    *pRemotePort = vals->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    UINT8 proto = (UINT8)vals->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    *pProto = (proto == IPPROTO_TCP) ? NET_PROTO_TCP :
        (proto == IPPROTO_UDP) ? NET_PROTO_UDP : NET_PROTO_OTHER;
}

static VOID
ExtractAcceptFields(
    _In_ const FWPS_INCOMING_VALUES0* vals,
    _Out_ ULONG* pLocalAddr,
    _Out_ USHORT* pLocalPort,
    _Out_ ULONG* pRemoteAddr,
    _Out_ USHORT* pRemotePort,
    _Out_ NET_PROTOCOL* pProto)
{
    *pLocalAddr = vals->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
    *pLocalPort = vals->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
    *pRemoteAddr = vals->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
    *pRemotePort = vals->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
    UINT8 proto = (UINT8)vals->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
    *pProto = (proto == IPPROTO_TCP) ? NET_PROTO_TCP :
        (proto == IPPROTO_UDP) ? NET_PROTO_UDP : NET_PROTO_OTHER;
}

VOID
NetCalloutClassifyBind(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64                                  flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Always permit; we are just observing
    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (g_pNetMonitor == NULL || !g_pNetMonitor->g_Monitor) return;

    ULONG       localAddr = 0;
    USHORT      localPort = 0;
    NET_PROTOCOL proto = NET_PROTO_OTHER;

    ExtractBindFields(inFixedValues, &localAddr, &localPort, &proto);

    ULONG pid = (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)
        ? (ULONG)inMetaValues->processId : 0;

    NetEnqueueEvent(NET_EVENT_BIND, proto, NET_DIR_INBOUND,
        pid, localAddr, localPort, 0, 0);
}

VOID
NetCalloutClassifyConnect(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64                                  flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Default: permit
    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (g_pNetMonitor == NULL || !g_pNetMonitor->g_Monitor) return;

    // Skip if the filter does not have the RIGHTS_HARD_TO_CLEAR flag
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) return;

    ULONG       localAddr = 0, remoteAddr = 0;
    USHORT      localPort = 0, remotePort = 0;
    NET_PROTOCOL proto = NET_PROTO_OTHER;
    ExtractConnectFields(inFixedValues,
        &localAddr, &localPort, &remoteAddr, &remotePort, &proto);

    ULONG pid = (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)
        ? (ULONG)inMetaValues->processId : 0;

    NetEnqueueEvent(NET_EVENT_CONNECT, proto, NET_DIR_OUTBOUND,
        pid, localAddr, localPort, remoteAddr, remotePort);

    classifyOut->actionType =  FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE; // finalise decision
}

VOID
NetCalloutClassifyAccept(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64                                  flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (g_pNetMonitor == NULL || !g_pNetMonitor->g_Monitor) return;

    ULONG       localAddr = 0, remoteAddr = 0;
    USHORT      localPort = 0, remotePort = 0;
    NET_PROTOCOL proto = NET_PROTO_OTHER;
    ExtractAcceptFields(inFixedValues,
        &localAddr, &localPort, &remoteAddr, &remotePort, &proto);

    ULONG pid = (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)
        ? (ULONG)inMetaValues->processId : 0;

    NetEnqueueEvent(NET_EVENT_ACCEPT, proto, NET_DIR_INBOUND,
        pid, localAddr, localPort, remoteAddr, remotePort);
}

VOID
NetCalloutClassifyFlow(
    _In_        const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_    const VOID* classifyContext,
    _In_        const FWPS_FILTER1* filter,
    _In_        UINT64                                  flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (g_pNetMonitor == NULL || !g_pNetMonitor->g_Monitor) return;

    // ALE_FLOW_ESTABLISHED shares the same field indices as AUTH_CONNECT for V4
    ULONG       localAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;
    USHORT      localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
    ULONG       remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;
    USHORT      remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;
    UINT8       protoRaw = (UINT8)inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;
    NET_PROTOCOL proto = (protoRaw == IPPROTO_TCP) ? NET_PROTO_TCP :
        (protoRaw == IPPROTO_UDP) ? NET_PROTO_UDP : NET_PROTO_OTHER;

    NET_DIRECTION direction =
        (inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.uint32
            == FWP_DIRECTION_OUTBOUND) ? NET_DIR_OUTBOUND : NET_DIR_INBOUND;

    ULONG pid = (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)
        ? (ULONG)inMetaValues->processId : 0;

    NetEnqueueEvent(NET_EVENT_ESTABLISHED, proto, direction,
        pid, localAddr, localPort, remoteAddr, remotePort);
}

NTSTATUS
NetworkMonitorDispatchDeviceControl(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp,
    ULONG IoCode,
    ULONG& Written)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    NTSTATUS Status = STATUS_SUCCESS;

    if (g_pNetMonitor == NULL)
        return STATUS_DEVICE_NOT_READY;

    switch (IoCode)
    {
    case IOCTL_START_NET_MONITORING:
    {
        DbgInfo("IOCTL_START_NET_MONITORING");
        if (g_pNetMonitor->g_Monitor)
            return Status;
        g_pNetMonitor->g_Monitor = TRUE;
        break;
    }
    case IOCTL_STOP_NET_MONITORING:
    {
        DbgInfo("IOCTL_STOP_NET_MONITORING");
        if (!g_pNetMonitor->g_Monitor)
            return Status;
        g_pNetMonitor->g_Monitor = FALSE;
        break;
    }
    case IOCTL_GET_NET_EVENT:
    {
        DbgInfo("IOCTL_GET_NET_EVENT");

        if (!g_pNetMonitor->g_Monitor)
        {
            Status = STATUS_NO_MORE_ENTRIES;
            break;
        }

        PAGENT_NET_EVENT pAgentNetEvent = (PAGENT_NET_EVENT)pIrp->AssociatedIrp.SystemBuffer;
        if (pAgentNetEvent == NULL)
        {
            DbgError("Invalid buffer for IOCTL_GET_NET_EVENT");
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN Found = FALSE;
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_pNetMonitor->g_NetMonLock, &oldIrql);

        PLIST_ENTRY pEntry = g_pNetMonitor->g_NetMonList.Flink;
        PNET_EVENT pEvt = NULL;
        while (pEntry != &g_pNetMonitor->g_NetMonList)
        {
            pEvt = CONTAINING_RECORD(pEntry, NET_EVENT, ListEntry);

            if (pEvt != NULL)
            {
                RtlZeroMemory(pAgentNetEvent, sizeof(AGENT_NET_EVENT));
                pAgentNetEvent->ProcessId = pEvt->ProcessId;
                pAgentNetEvent->EventType = pEvt->EventType;
                pAgentNetEvent->Protocol = pEvt->Protocol;
                pAgentNetEvent->Direction = pEvt->Direction;
                pAgentNetEvent->LocalAddress = pEvt->LocalAddress;
                pAgentNetEvent->LocalPort = pEvt->LocalPort;
                pAgentNetEvent->RemoteAddress = pEvt->RemoteAddress;
                pAgentNetEvent->RemotePort = pEvt->RemotePort;
                Found = TRUE;
                break;
            }

            pEntry = pEntry->Flink;
        }
        // Remove from list and free
        PNET_EVENT pEvtToFree = NULL;
        if (Found)
        {
            pEvtToFree = CONTAINING_RECORD(pEntry, NET_EVENT, ListEntry);
            Written = sizeof(AGENT_NET_EVENT);
            RemoveEntryList(pEntry);
            Status = STATUS_SUCCESS;
        }
        else
        {
            DbgInfo("No pending net events");
            Written = 0;
            Status = STATUS_NO_MORE_ENTRIES;
        }
        KeReleaseSpinLock(&g_pNetMonitor->g_NetMonLock, oldIrql);
        if (Found)
        {
            NetGetProcessName(pAgentNetEvent->ProcessId, pAgentNetEvent->ProcessName, MAX_PROCESS_NAME_SIZE);
        }
        if(pEvtToFree != NULL)
        {
            ExFreePoolWithTag(pEvtToFree, EDR_MEMORY_TAG);
        }     

        break;
    }
    }
    return Status;
}