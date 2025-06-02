#include "NetworkMonitor.h"

/*
 * NetworkMonitor.cpp
 *
 * Implementation of Windows Filtering Platform (WFP) based network monitoring
 *
 * This module provides kernel-level network traffic inspection capabilities
 * for the Anubis EDR system, detecting malicious network behavior patterns.
 */

#include <ndis.h>  // For NET_BUFFER manipulation
#include <ndis/nbl.h>
#include <ndis/nblaccessors.h>
#include <ndis/nblapi.h>
#include <ntstrsafe.h>
#include "..\utils\kOsUtils.h"

 // =============================================================================
 // GLOBAL STATE
 // =============================================================================

// Singleton network monitor instance
static PNETWORK_MONITOR g_NetworkMonitor = NULL;

// Maximum events to queue before dropping (prevent memory exhaustion)
#define MAX_QUEUED_EVENTS 10000

// Maximum time to keep connection state (in seconds)
#define CONNECTION_TIMEOUT 300  // 5 minutes

// =============================================================================
// INITIALIZATION AND CLEANUP
// =============================================================================

/*
 * InitializeNetworkMonitor
 *
 * Sets up the network monitoring subsystem:
 * 1. Allocates monitor structure
 * 2. Initializes synchronization objects
 * 3. Opens WFP engine handle
 * 4. Registers callouts with WFP
 * 5. Adds filters to direct traffic
 */

NTSTATUS InitializeNetworkMonitor()
{

	NTSTATUS Status = STATUS_SUCCESS;

	DbgInfo("Initializing metwork monitoring ...\n");

	// Allocate monitor struct from non paged
	g_NetworkMonitor = (PNETWORK_MONITOR)ExAllocatePoolWithTag(NonPagedPool, sizeof(NETWORK_MONITOR), EDR_MEMORY_TAG);

	if (!g_NetworkMonitor)
	{
		DbgError("Failed to allocate network monitor struct\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(g_NetworkMonitor, sizeof(NETWORK_MONITOR));

	InitializeListHead(&g_NetworkMonitor->EventQueue);
	KeInitializeSpinLock(&g_NetworkMonitor->QueueLock);

	g_NetworkMonitor->IsInitialized = TRUE;
	g_NetworkMonitor->IsMonitoring = FALSE;

	g_NetworkMonitor->TotalConnections = 0;
	g_NetworkMonitor->TotalPackets = 0;
	g_NetworkMonitor->TotalBytes = 0;
	g_NetworkMonitor->BlockedConnections = 0;
	g_NetworkMonitor->DnsQueries = 0;
	g_NetworkMonitor->HttpRequests = 0;

	// Note: We'll open the WFP engine handle when registering callouts

	// Register all WPF callouts
	Status = RegisterWfpCallouts();
	if (!NT_SUCCESS(Status))
	{
		DbgError("Failed to register WFP callouts: 0x%x", Status);
		goto cleanup;
	}

	DbgInfo("Network monitor initialized successfully");
	DbgInfo("Statistics address: Connections=%p, Packets=%p",
		&g_NetworkMonitor->TotalConnections,
		&g_NetworkMonitor->TotalPackets);

	return STATUS_SUCCESS;

cleanup:

	UninitializeNetworkMonitor();
	return Status;
}

/*
* UninitializeNetworkMonitor
*
* Cleanup network monitoring:
* 1. Stop monitoring
* 2. Unregister callouts
* 3. Clean up event queue
* 4. Free resources
*/
VOID
UninitializeNetworkMonitor()
{
	if (!g_NetworkMonitor)
	{
		return;
	}

	DbgInfo("Uninitialize network monitor");

	// Stop monitoring first
	StopNetworkMonitoring();

	// Unregister all callouts
	if (g_NetworkMonitor->AleConnectCalloutIdV4)
	{
		FwpsCalloutUnregisterById(g_NetworkMonitor->AleConnectCalloutIdV4);
		DbgInfo("Unregistered ALE Connect V4 callout");
	}
	if (g_NetworkMonitor->AleConnectCalloutIdV6) {
		FwpsCalloutUnregisterById(g_NetworkMonitor->AleConnectCalloutIdV6);
		DbgInfo("Unregistered ALE Connect V6 callout");
	}
	if (g_NetworkMonitor->AleRecvAcceptCalloutIdV4) {
		FwpsCalloutUnregisterById(g_NetworkMonitor->AleRecvAcceptCalloutIdV4);
		DbgInfo("Unregistered ALE Accept V4 callout");
	}
	if (g_NetworkMonitor->AleRecvAcceptCalloutIdV6) {
		FwpsCalloutUnregisterById(g_NetworkMonitor->AleRecvAcceptCalloutIdV6);
		DbgInfo("Unregistered ALE Accept V6 callout");
	}
	if (g_NetworkMonitor->StreamCalloutIdV4) {
		FwpsCalloutUnregisterById(g_NetworkMonitor->StreamCalloutIdV4);
		DbgInfo("Unregistered Stream V4 callout");
	}
	if (g_NetworkMonitor->StreamCalloutIdV6) {
		FwpsCalloutUnregisterById(g_NetworkMonitor->StreamCalloutIdV6);
		DbgInfo("Unregistered Stream V6 callout");
	}
	if (g_NetworkMonitor->DatagramCalloutIdV4) {
		FwpsCalloutUnregisterById(g_NetworkMonitor->DatagramCalloutIdV4);
		DbgInfo("Unregistered Datagram V4 callout");
	}
	if (g_NetworkMonitor->DatagramCalloutIdV6) {
		FwpsCalloutUnregisterById(g_NetworkMonitor->DatagramCalloutIdV6);
		DbgInfo("Unregistered Datagram V6 callout");
	}

	// Clean up event queue
	KeAcquireSpinLock(&g_NetworkMonitor->QueueLock, &g_NetworkMonitor->OldIrql);
	while (!IsListEmpty(&g_NetworkMonitor->EventQueue))
	{
		PLIST_ENTRY entry = RemoveHeadList(&g_NetworkMonitor->EventQueue);
		PNETWORK_EVENT_QUEUE_ITEM queueItem = CONTAINING_RECORD(entry, NETWORK_EVENT_QUEUE_ITEM, ListEntry);
		if (queueItem)
			ExFreePoolWithTag(queueItem, EDR_MEMORY_TAG);
	}
	KeReleaseSpinLock(&g_NetworkMonitor->QueueLock, g_NetworkMonitor->OldIrql);

	// Log final statistics
	DbgInfo("Network Monitor Statistics:");
	DbgInfo("  Total Connections: %lld", g_NetworkMonitor->TotalConnections);
	DbgInfo("  Total Packets: %lld", g_NetworkMonitor->TotalPackets);
	DbgInfo("  Total Bytes: %lld", g_NetworkMonitor->TotalBytes);
	DbgInfo("  Blocked Connections: %lld", g_NetworkMonitor->BlockedConnections);
	DbgInfo("  DNS Queries: %lld", g_NetworkMonitor->DnsQueries);
	DbgInfo("  HTTP Requests: %lld", g_NetworkMonitor->HttpRequests);
	
	// Free monitor structure
	ExFreePoolWithTag(g_NetworkMonitor, EDR_MEMORY_TAG);
	g_NetworkMonitor = NULL;

	DbgInfo("Network monitor uninitialized");
}


// =============================================================================
// WFP REGISTRATION
// =============================================================================
/*
 * RegisterWfpCallouts
 *
 * Register all callout functions with Windows Filtering Platform
 * Each callout monitors a specific network layer and IP version
 */
NTSTATUS RegisterWfpCallouts()
{
	NTSTATUS Status = STATUS_SUCCESS;
	FWPS_CALLOUT callout = { 0 };
	DEVICE_OBJECT* deviceObject = NULL;

	DbgInfo("Registering WFP callouts");

	// Get device object from driver
	deviceObject = g_pDeviceObject;

	if (!deviceObject) {
		DbgError("Device object not available");
		return STATUS_UNSUCCESSFUL;
	}

	// =======================================================================
	// Register ALE Connect V4 Callout (Outbound IPv4 Connections)
	// =======================================================================
	RtlZeroMemory(&callout, sizeof(callout));
	callout.calloutKey = ANUBIS_ALE_CONNECT_CALLOUT_V4;
	callout.classifyFn = NetworkConnectClassifyFn;
	callout.notifyFn = NetworkNotifyFn;
	callout.flowDeleteFn = NULL;  // Not needed for ALE layer

	Status = FwpsCalloutRegister(
		deviceObject,
		&callout,
		&g_NetworkMonitor->AleConnectCalloutIdV4
	);

	if (!NT_SUCCESS(Status)) {
		DbgError("Failed to register ALE connect V4 callout: 0x%x", Status);
		return Status;
	}

	// =======================================================================
	// Register ALE Connect V6 Callout (Outbound IPv6 Connections)
	// =======================================================================
	callout.calloutKey = ANUBIS_ALE_CONNECT_CALLOUT_V6;
	Status = FwpsCalloutRegister(
		deviceObject,
		&callout,
		&g_NetworkMonitor->AleConnectCalloutIdV6
	);

	if (!NT_SUCCESS(Status)) {
		DbgError("Failed to register ALE connect V6 callout: 0x%x", Status);
		return Status;
	}


	// =======================================================================
// Register ALE Receive/Accept V4 Callout (Inbound IPv4 Connections)
// =======================================================================
	callout.calloutKey = ANUBIS_ALE_RECV_ACCEPT_CALLOUT_V4;
	callout.classifyFn = NetworkConnectClassifyFn;  // Same function, different layer

	Status = FwpsCalloutRegister(
		deviceObject,
		&callout,
		&g_NetworkMonitor->AleRecvAcceptCalloutIdV4
	);

	if (!NT_SUCCESS(Status)) {
		DbgError("Failed to register ALE recv/accept V4 callout: 0x%x", Status);
		return Status;
	}


	// =======================================================================
// Register ALE Receive/Accept V6 Callout (Inbound IPv6 Connections)
// =======================================================================
	callout.calloutKey = ANUBIS_ALE_RECV_ACCEPT_CALLOUT_V6;
	Status = FwpsCalloutRegister(
		deviceObject,
		&callout,
		&g_NetworkMonitor->AleRecvAcceptCalloutIdV6
	);

	if (!NT_SUCCESS(Status)) {
		DbgError("Failed to register ALE recv/accept V6 callout: 0x%x", Status);
		return Status;
	}


	// =======================================================================
	// Register Stream V4 Callout (TCP Data Inspection IPv4)
	// =======================================================================
	callout.calloutKey = ANUBIS_STREAM_CALLOUT_V4;
	callout.classifyFn = NetworkStreamClassifyFn;
	callout.flowDeleteFn = NetworkFlowDeleteFn;  // Cleanup when connection closes

	Status = FwpsCalloutRegister(
		deviceObject,
		&callout,
		&g_NetworkMonitor->StreamCalloutIdV4
	);

	if (!NT_SUCCESS(Status)) {
		DbgError("Failed to register stream V4 callout: 0x%x", Status);
		return Status;
	}
	DbgInfo("Registered Stream V4 callout, ID: %d",
		g_NetworkMonitor->StreamCalloutIdV4);


	// =======================================================================
	// Register Stream V6 Callout (TCP Data Inspection IPv6)
	// =======================================================================
	callout.calloutKey = ANUBIS_STREAM_CALLOUT_V6;
	Status = FwpsCalloutRegister(
		deviceObject,
		&callout,
		&g_NetworkMonitor->StreamCalloutIdV6
	);

	if (!NT_SUCCESS(Status)) {
		DbgError("Failed to register stream V6 callout: 0x%x", Status);
		return Status;
	}

	// =======================================================================
	// Register Datagram V4 Callout (UDP Packet Inspection IPv4)
	// =======================================================================
	callout.calloutKey = ANUBIS_DATAGRAM_CALLOUT_V4;
	callout.classifyFn = NetworkDatagramClassifyFn;
	callout.flowDeleteFn = NULL;  // UDP is connectionless

	Status = FwpsCalloutRegister(
		deviceObject,
		&callout,
		&g_NetworkMonitor->DatagramCalloutIdV4
	);

	if (!NT_SUCCESS(Status)) {
		DbgError("Failed to register datagram V4 callout: 0x%x", Status);
		return Status;
	}
	DbgInfo("Registered Datagram V4 callout, ID: %d",
		g_NetworkMonitor->DatagramCalloutIdV4);

	// =======================================================================
	// Register Datagram V6 Callout (UDP Packet Inspection IPv6)
	// =======================================================================
	callout.calloutKey = ANUBIS_DATAGRAM_CALLOUT_V6;
	Status = FwpsCalloutRegister(
		deviceObject,
		&callout,
		&g_NetworkMonitor->DatagramCalloutIdV6
	);

	if (!NT_SUCCESS(Status)) {
		DbgError("Failed to register datagram V6 callout: 0x%x", Status);
		return Status;
	}

	DbgInfo("All WFP callouts registered successfully");

	// Now add filters to direct traffic to our callouts
	Status = AddWfpFilters();

	return Status;
}

/*
 * AddWfpFilters
 *
 * Add filters to WFP that direct network traffic to our callouts
 * Filters determine which traffic is sent to which callout
 */
NTSTATUS AddWfpFilters()
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE engineHandle = NULL;
	FWPM_SESSION Session = { 0 };

	DbgInfo("Adding WFP filters");

	// =======================================================================
	// Open WFP Filter Engine
	// =======================================================================
	Session.flags = FWPM_SESSION_FLAG_DYNAMIC; // Filters removed on close

	status = FwpmEngineOpen(
		NULL,                    // Local engine
		RPC_C_AUTHN_WINNT,      // Windows authentication
		NULL,                    // Default security
		&Session,                // Session configuration
		&engineHandle            // Output handle
	);

	if (!NT_SUCCESS(status)) {
		DbgError("Failed to open WFP engine: 0x%x", status);
		return status;
	}

	// =======================================================================
	// Begin Transaction (for atomic filter addition)
	// =======================================================================
	status = FwpmTransactionBegin(engineHandle, 0);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to begin transaction: 0x%x", status);
		FwpmEngineClose(engineHandle);
		return status;
	}

	// =======================================================================
	// Add ALE Connect Filters (Outbound Connections)
	// =======================================================================
	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION condition = { 0 };
	UINT64 filterId = 0;

	// IPv4 Outbound Connection Filter
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.displayData.name = L"Anubis EDR - Monitor Outbound IPv4 Connections";
	filter.displayData.description = L"Monitors all outbound IPv4 connection attempts";
	filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;  // Send to our callout
	filter.action.calloutKey = ANUBIS_ALE_CONNECT_CALLOUT_V4;
	filter.weight.type = FWP_EMPTY;  // Default weight

	// Monitor all protocols (no conditions = match all)
	filter.numFilterConditions = 0;
	filter.filterCondition = NULL;

	status = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to add ALE connect V4 filter: 0x%x", status);
		goto abort_transaction;
	}
	DbgInfo("Added ALE Connect V4 filter, ID: %lld", filterId);

	// IPv6 Outbound Connection Filter
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	filter.displayData.name = L"Anubis EDR - Monitor Outbound IPv6 Connections";
	filter.action.calloutKey = ANUBIS_ALE_CONNECT_CALLOUT_V6;

	status = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to add ALE connect V6 filter: 0x%x", status);
		goto abort_transaction;
	}

	// =======================================================================
	// Add ALE Receive/Accept Filters (Inbound Connections)
	// =======================================================================
	// IPv4 Inbound Connection Filter
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
	filter.displayData.name = L"Anubis EDR - Monitor Inbound IPv4 Connections";
	filter.displayData.description = L"Monitors incoming connection attempts";
	filter.action.calloutKey = ANUBIS_ALE_RECV_ACCEPT_CALLOUT_V4;

	status = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to add ALE recv/accept V4 filter: 0x%x", status);
		goto abort_transaction;
	}

	// IPv6 Inbound Connection Filter
	filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
	filter.displayData.name = L"Anubis EDR - Monitor Inbound IPv6 Connections";
	filter.action.calloutKey = ANUBIS_ALE_RECV_ACCEPT_CALLOUT_V6;

	status = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to add ALE recv/accept V6 filter: 0x%x", status);
		goto abort_transaction;
	}

	// =======================================================================
	// Add Stream Filters (TCP Data Inspection)
	// =======================================================================

	//TODO:: add conditions here to only inspect HTTP/HTTPS traffic
	// to reduce performance impact

	// IPv4 TCP Stream Filter
	filter.layerKey = FWPM_LAYER_STREAM_V4;
	filter.displayData.name = L"Anubis EDR - Inspect IPv4 TCP Streams";
	filter.displayData.description = L"Inspects TCP data for HTTP and other protocols";
	filter.action.calloutKey = ANUBIS_STREAM_CALLOUT_V4;

	//TODO:: Only inspect common application protocols
	filter.numFilterConditions = 0;  // Inspect all for now

	status = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to add stream V4 filter: 0x%x", status);
		goto abort_transaction;
	}
	DbgInfo("Added Stream V4 filter, ID: %lld", filterId);

	// IPv6 TCP Stream Filter
	filter.layerKey = FWPM_LAYER_STREAM_V6;
	filter.displayData.name = L"Anubis EDR - Inspect IPv6 TCP Streams";
	filter.action.calloutKey = ANUBIS_STREAM_CALLOUT_V6;

	status = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to add stream V6 filter: 0x%x", status);
		goto abort_transaction;
	}


	// =======================================================================
	// Add Datagram Filters (UDP Packet Inspection)
	// =======================================================================

	// IPv4 UDP Filter - Focus on DNS traffic
	filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
	filter.displayData.name = L"Anubis EDR - Inspect IPv4 UDP Packets";
	filter.displayData.description = L"Inspects UDP packets for DNS and other protocols";
	filter.action.calloutKey = ANUBIS_DATAGRAM_CALLOUT_V4;

	// Add condition for DNS port to reduce overhead
	condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
	condition.matchType = FWP_MATCH_EQUAL;
	condition.conditionValue.type = FWP_UINT16;
	condition.conditionValue.uint16 = 53;  // DNS port

	filter.filterCondition = &condition;
	filter.numFilterConditions = 1;

	status = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to add datagram V4 filter: 0x%x", status);
		goto abort_transaction;
	}
	DbgInfo("Added Datagram V4 filter for DNS, ID: %lld", filterId);

	// Also monitor all UDP traffic (remove condition)
	filter.numFilterConditions = 0;
	filter.filterCondition = NULL;
	filter.displayData.name = L"Anubis EDR - Inspect All IPv4 UDP";

	status = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to add general datagram V4 filter: 0x%x", status);
		goto abort_transaction;
	}


	// IPv6 UDP Filter
	filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V6;
	filter.displayData.name = L"Anubis EDR - Inspect IPv6 UDP Packets";
	filter.action.calloutKey = ANUBIS_DATAGRAM_CALLOUT_V6;

	status = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to add datagram V6 filter: 0x%x", status);
		goto abort_transaction;
	}


	// =======================================================================
	// Commit Transaction
	// =======================================================================
	status = FwpmTransactionCommit(engineHandle);
	if (!NT_SUCCESS(status)) {
		DbgError("Failed to commit transaction: 0x%x", status);
		FwpmTransactionAbort(engineHandle);
	}
	else {
		DbgInfo("Successfully committed all WFP filters");
	}

	FwpmEngineClose(engineHandle);
	return status;

abort_transaction:
	FwpmTransactionAbort(engineHandle);
	FwpmEngineClose(engineHandle);
	return status;
}


// =============================================================================
// MONITORING CONTROL
// =============================================================================

/*
 * StartNetworkMonitoring
 *
 * Enable active network monitoring
 * Sets the monitoring flag that callouts check
 */
NTSTATUS StartNetworkMonitoring()
{
	if (!g_NetworkMonitor || !g_NetworkMonitor->IsInitialized) {
		DbgError("Network monitor not initialized");
		return STATUS_UNSUCCESSFUL;
	}

	if (g_NetworkMonitor->IsMonitoring) {
		DbgError("Network monitoring already active");
		return STATUS_SUCCESS;
	}

	g_NetworkMonitor->IsMonitoring = TRUE;
	DbgInfo("Network monitoring started");

	return STATUS_SUCCESS;
}

/*
 * StopNetworkMonitoring
 *
 * Disable network monitoring
 * Callouts will pass through traffic without inspection
 */
NTSTATUS StopNetworkMonitoring()
{

	if (!g_NetworkMonitor) {
		return STATUS_UNSUCCESSFUL;
	}

	if (!g_NetworkMonitor->IsMonitoring) {
		DbgError("Network monitoring already stopped");
		return STATUS_SUCCESS;
	}

	g_NetworkMonitor->IsMonitoring = FALSE;

	// Clear event queue to free memory
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_NetworkMonitor->QueueLock, &oldIrql);
	ULONG clearedEvents = 0;
	while (!IsListEmpty(&g_NetworkMonitor->EventQueue))
	{
		PLIST_ENTRY entry = RemoveHeadList(&g_NetworkMonitor->EventQueue);
		PNETWORK_EVENT_QUEUE_ITEM queueItem = CONTAINING_RECORD(
			entry,
			NETWORK_EVENT_QUEUE_ITEM,
			ListEntry
		);
		if (entry)
		{
			ExFreePoolWithTag(queueItem, EDR_MEMORY_TAG);
			clearedEvents++;
		}
	}

	KeReleaseSpinLock(&g_NetworkMonitor->QueueLock, oldIrql);

	DbgInfo("Network monitoring stopped, cleared %d queued events", clearedEvents);
	return STATUS_SUCCESS;
}

// =============================================================================
// WFP CALLOUT IMPLEMENTATIONS
// =============================================================================
/*
 * NetworkConnectClassifyFn
 *
 * Main inspection function for connection attempts
 * Called for both outbound (CONNECT) and inbound (RECV_ACCEPT) connections
 *
 * This is where we:
 * - Extract connection metadata
 * - Check against security policies
 * - Generate connection events
 * - Block suspicious connections
 */
VOID NTAPI NetworkConnectClassifyFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	// Quick exit if not monitoring
	if (!g_NetworkMonitor || !g_NetworkMonitor->IsMonitoring) {
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}

	// Check if re-authorization (we've already seen this)
	if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
		// We can make a decision
	}
	else {
		// Can't make decision, just continue
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}

	// Allocate event structure
	PNETWORK_EVENT_QUEUE_ITEM queueItem = (PNETWORK_EVENT_QUEUE_ITEM)
		ExAllocatePoolWithTag(
			NonPagedPool,
			sizeof(NETWORK_EVENT_QUEUE_ITEM),
			EDR_MEMORY_TAG
		);


	if (!queueItem) {
		// Memory allocation failed, allow connection but log
		DbgError("Failed to allocate connection event");
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}

	RtlZeroMemory(queueItem, sizeof(NETWORK_EVENT_QUEUE_ITEM));
	queueItem->EventType = kEventType::NetworkConnect;

	PNETWORK_CONNECTION_EVENT event = &queueItem->Event.ConnectionEvent;
	event->Header.EventType = kEventType::NetworkConnect;
	event->Header.TimeStamp = GetCurrentTimeStamp();

	// =======================================================================
	// Extract Connection Information
	// =======================================================================

	// Determine layer to get correct field indices
	UINT16 layerId = inFixedValues->layerId;
	BOOLEAN isIPv6 = FALSE;
	BOOLEAN isInbound = FALSE;

	// Determine IPv4 vs IPv6 and direction
	switch (layerId)
	{
	case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
		isIPv6 = FALSE;
		isInbound = FALSE;
		break;
	case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
		isIPv6 = TRUE;
		isInbound = FALSE;
		break;
	case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
		isIPv6 = FALSE;
		isInbound = TRUE;
		break;
	case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
		isIPv6 = TRUE;
		isInbound = TRUE;
		break;
	default:
		DbgError("Unknown layer ID: %d", layerId);
		ExFreePoolWithTag(queueItem, EDR_MEMORY_TAG);
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}

	event->IsIpv6 = isIPv6;
	event->Direction = isInbound ? NetworkDirection::Inbound : NetworkDirection::Outbound;

	// Get protocol (TCP/UDP/ICMP/etc)
	UINT8 protocol = 0;
	if (isInbound)
	{
		protocol = inFixedValues->incomingValue[
			isIPv6 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL :
				FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL
		].value.uint8;
	}
	else {
		protocol = inFixedValues->incomingValue[
			isIPv6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL :
				FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL
		].value.uint8;
	}

	event->Protocol = (NetworkProtocol)protocol;


	// Get port information
	if (isInbound)
	{
		event->LocalPort = inFixedValues->incomingValue[
			isIPv6 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT :
				FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT
		].value.uint16;

		event->RemotePort = inFixedValues->incomingValue[
			isIPv6 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT :
				FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT
		].value.uint16;
	}else {
		event->LocalPort = inFixedValues->incomingValue[
			isIPv6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT :
				FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT
		].value.uint16;

		event->RemotePort = inFixedValues->incomingValue[
			isIPv6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT :
				FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT
		].value.uint16;
	}

	// Get IP addresses
	if (!isIPv6) {
		// IPv4 addresses
		if (isInbound) {
			event->LocalIpAddress = inFixedValues->incomingValue[
				FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS
			].value.uint32;

			event->RemoteIpAddress = inFixedValues->incomingValue[
				FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS
			].value.uint32;
		}
		else {
			event->LocalIpAddress = inFixedValues->incomingValue[
				FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS
			].value.uint32;

			event->RemoteIpAddress = inFixedValues->incomingValue[
				FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS
			].value.uint32;
		}

		// Check for loopback
		event->IsLoopback = (event->LocalIpAddress == event->RemoteIpAddress) ||
			(event->RemoteIpAddress == 0x0100007F); // 127.0.0.1 in network order
	}
	else {

		// IPv6 addresses
		if (isInbound) {

			RtlCopyMemory(
				event->LocalIpv6Address,
				inFixedValues->incomingValue[
					FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS
				].value.byteArray16,
				16);

			RtlCopyMemory(
				event->RemoteIpv6Address,
				inFixedValues->incomingValue[
					FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS
				].value.byteArray16,
				16);
		}
		else
		{
			RtlCopyMemory(
				event->LocalIpv6Address,
				inFixedValues->incomingValue[
					FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS
				].value.byteArray16,
				16);

			RtlCopyMemory(
				event->RemoteIpv6Address,
				inFixedValues->incomingValue[
					FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS
				].value.byteArray16,
				16);
		}

		// Check for IPv6 loopback (::1)
		UINT8 ipv6Loopback[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
		event->IsLoopback = RtlEqualMemory(event->RemoteIpv6Address, ipv6Loopback, 16);
	}


	// =======================================================================
	// Get Process Information
	// =======================================================================
	if (inMetaValues->processId != 0) {

		event->Header.ProcessId = (ULONG)inMetaValues->processId;


		// Get process path if available
		if (inMetaValues->processPath)
		{

			// processPath is a UNICODE_STRING*
			SIZE_T copyLength = min(
				inMetaValues->processPath->size,
				sizeof(event->ProcessPath) - sizeof(WCHAR)
			);

			RtlCopyMemory(
				event->ProcessPath,
				inMetaValues->processPath->data,
				copyLength
			);

			// Ensure null termination
			event->ProcessPath[copyLength / sizeof(WCHAR)] = L'\0';
		}
	}

	// =======================================================================
	// Security Checks and Decisions
	// =======================================================================
	BOOLEAN shouldBlock = FALSE;
	BOOLEAN isSuspicious = FALSE;

	// TODO:: Base security check out of configured rules
	// 
	// Check 1: Known backdoor ports
	if (event->RemotePort == 4444 
		|| event->RemotePort == 1337 
		|| event->RemotePort == 31337) {  // Elite port
		isSuspicious = TRUE;
		DbgInfo("Connection to known backdoor port %d detected", event->RemotePort);

		// Block outbound connections to backdoor ports
		if (!isInbound && protocol == IPPROTO_TCP) {
			shouldBlock = TRUE;
		}


	}

	// Check 2: Suspicious process names
	if (event->ProcessPath[0] != L'\0')
	{
		// Check for suspicious patterns in process path
		if (wcsstr(event->ProcessPath, L"\\temp\\") != NULL ||
			wcsstr(event->ProcessPath, L"\\tmp\\") != NULL ||
			wcsstr(event->ProcessPath, L"\\appdata\\local\\temp\\") != NULL) {
			isSuspicious = TRUE;
			DbgInfo("Connection from temporary directory: %ws", event->ProcessPath);
		}

		// Check for known malicious process names
		if (wcsstr(event->ProcessPath, L"nc.exe") != NULL ||      // netcat
			wcsstr(event->ProcessPath, L"ncat.exe") != NULL ||    // nmap netcat
			wcsstr(event->ProcessPath, L"mimikatz") != NULL) {    // credential dumper
			isSuspicious = TRUE;
			shouldBlock = TRUE;
			DbgInfo("Connection from known malicious tool: %ws", event->ProcessPath);
		}
	}

	// Check 3: High-risk inbound services
	if (isInbound) 
	{
		switch (event->LocalPort)
		{
		case 22:    // SSH
		case 23:    // Telnet
		case 3389:  // RDP
		case 5900:  // VNC
			isSuspicious = TRUE;
			DbgInfo("Inbound connection to remote access service on port %d",
				event->LocalPort);
			break;
		case 445:   // SMB
		case 139:   // NetBIOS
			// SMB from internet is always suspicious
			if (!IsPrivateIp(event->RemoteIpAddress)) {
				isSuspicious = TRUE;
				shouldBlock = TRUE;
				DbgInfo("SMB connection from internet IP");
			}
			break;
		}
	}

	// Check 4: Beaconing detection (requires state tracking)
	// TODO: Implement connection frequency analysis

	// =======================================================================
	// Make Decision
	// =======================================================================
	if (shouldBlock) 
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;  // Clear write flag

		InterlockedIncrement64(&g_NetworkMonitor->BlockedConnections);
		DbgInfo("Blocked %s connection: %ws -> %d.%d.%d.%d:%d",
			isInbound ? "inbound" : "outbound",
			event->ProcessPath,
			(event->RemoteIpAddress >> 0) & 0xFF,
			(event->RemoteIpAddress >> 8) & 0xFF,
			(event->RemoteIpAddress >> 16) & 0xFF,
			(event->RemoteIpAddress >> 24) & 0xFF,
			event->RemotePort);
	}
	else
	{
		classifyOut->actionType = FWP_ACTION_CONTINUE;
	}


	// =======================================================================
	// Queue Event for User Mode
	// =======================================================================
	NTSTATUS status = QueueNetworkEvent(queueItem);
	if (!NT_SUCCESS(status)) {
		// Failed to queue, free memory
		ExFreePoolWithTag(queueItem, EDR_MEMORY_TAG);
	}
	else {
		InterlockedIncrement64(&g_NetworkMonitor->TotalConnections);
	}
}

/*
 * NetworkStreamClassifyFn
 *
 * TCP stream data inspection
 * Analyzes actual data flowing through TCP connections
 *
 * Primary uses:
 * - HTTP header extraction
 * - Data exfiltration detection
 * - Protocol identification
 * - Malware communication patterns
 */
VOID NTAPI NetworkStreamClassifyFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(inMetaValues);

	// Quick exit if not monitoring
	if (!g_NetworkMonitor || !g_NetworkMonitor->IsMonitoring) {
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}

	// Get stream data
	FWPS_STREAM_CALLOUT_IO_PACKET* streamPacket =
		(FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;

	if (!streamPacket || !streamPacket->streamData) {
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}

	// Get connection information for context
	UINT16 localPort = 0;
	UINT16 remotePort = 0;
	UINT32 remoteIp = 0;

	// Determine if IPv4 or IPv6
	BOOLEAN isIPv6 = (inFixedValues->layerId == FWPS_LAYER_STREAM_V6);
	if (!isIPv6) {
		localPort = inFixedValues->incomingValue[
			FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT
		].value.uint16;

		remotePort = inFixedValues->incomingValue[
			FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT
		].value.uint16;

		remoteIp = inFixedValues->incomingValue[
			FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS
		].value.uint32;
	}

	// Check if this is HTTP/HTTPS traffic
	if (IsHttpPort(remotePort) || IsHttpPort(localPort))
	{
		FWPS_STREAM_DATA* streamData = streamPacket->streamData;
		SIZE_T dataLength = streamData->dataLength;

		// Reasonable size check for HTTP headers (typically < 8KB)
		if (dataLength > 0 && dataLength < 8192)
		{
			// Allocate buffer for stream data
			PVOID data = ExAllocatePoolWithTag(
				NonPagedPool,
				dataLength + 1,  // +1 for null terminator
				EDR_MEMORY_TAG
			);

			if (data)
			{
				// Copy stream data to our buffer
				SIZE_T bytesCopied = 0;
				FwpsCopyStreamDataToBuffer(
					streamData,
					data,
					dataLength,
					&bytesCopied
				);

				// Null terminate for string operations
				((PCHAR)data)[bytesCopied] = '\0';

				// Check for method
				if (bytesCopied >= 4) {
					if (RtlCompareMemory(data, "GET ", 4) == 4 ||
						RtlCompareMemory(data, "POST ", 5) == 5 ||
						RtlCompareMemory(data, "PUT ", 4) == 4 ||
						RtlCompareMemory(data, "HEAD ", 5) == 5 ||
						RtlCompareMemory(data, "DELETE ", 7) == 7)
					{
						// This is an HTTP request - parse it
						PNETWORK_EVENT_QUEUE_ITEM queueItem =
							(PNETWORK_EVENT_QUEUE_ITEM)ExAllocatePoolWithTag(
								NonPagedPool,
								sizeof(NETWORK_EVENT_QUEUE_ITEM),
								EDR_MEMORY_TAG
							);

						if (queueItem)
						{
							// Parse HTTP request
							if (NT_SUCCESS(ParseHttpRequest(
								data,
								(UINT32)bytesCopied,
								&queueItem->Event.HttpEvent)))
							{
								queueItem->Event.HttpEvent.RemoteIp = remoteIp;
								queueItem->Event.HttpEvent.RemotePort = remotePort;
								queueItem->Event.HttpEvent.IsHttps = (remotePort == 443);
								queueItem->Event.HttpEvent.Header.ProcessId =
									(ULONG)inMetaValues->processId;

								// Queue the event
								if (!NT_SUCCESS(QueueNetworkEvent(queueItem))) {
									ExFreePoolWithTag(queueItem, EDR_MEMORY_TAG);
								}
								else {
									InterlockedIncrement64(&g_NetworkMonitor->HttpRequests);
								}
							}
							else {
								ExFreePoolWithTag(queueItem, EDR_MEMORY_TAG);
							}
						}
					}
					else if (RtlCompareMemory(data, "HTTP/", 5) == 5) {
						// This is an HTTP response
						// TODO: Parse response for status codes, content-type, etc.
					}
				}
				ExFreePoolWithTag(data, EDR_MEMORY_TAG);
			}
		}
	}

	// Update statistics
	InterlockedAdd64(&g_NetworkMonitor->TotalBytes, streamPacket->streamData->dataLength);
	InterlockedIncrement64(&g_NetworkMonitor->TotalPackets);

	// Always allow stream data (inspection only)
	classifyOut->actionType = FWP_ACTION_CONTINUE;
}

/*
 * NetworkDatagramClassifyFn
 *
 * UDP packet inspection
 * Primary use: DNS query monitoring
 *
 * Detects:
 * - DNS tunneling
 * - DGA domains
 * - C2 over DNS TXT records
 * - DNS hijacking
 */
VOID NTAPI NetworkDatagramClassifyFn(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	// Quick exit if not monitoring
	if (!g_NetworkMonitor || !g_NetworkMonitor->IsMonitoring) {
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}

	// Get the NET_BUFFER_LIST containing the packet
	NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerData;
	if (!netBufferList) {
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}

	// Get port information to identify protocol
	BOOLEAN isIPv6 = (inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6);

	UINT16 localPort = 0;
	UINT16 remotePort = 0;
	UINT32 remoteIp = 0;

	if (!isIPv6) {
		localPort = inFixedValues->incomingValue[
			FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT
		].value.uint16;

		remotePort = inFixedValues->incomingValue[
			FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT
		].value.uint16;

		remoteIp = inFixedValues->incomingValue[
			FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS
		].value.uint32;
	}

	// Check if this is DNS traffic
	if (IsDnsPort(localPort) || IsDnsPort(remotePort))
	{
		// Get the first NET_BUFFER from the list
		NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
		if (netBuffer)
		{
			UINT32 dataLength = NET_BUFFER_DATA_LENGTH(netBuffer);

			// DNS packets are typically small (< 512 bytes for standard queries)
			if (dataLength >= sizeof(DNS_HEADER) && dataLength < 1024)
			{
				// Allocate buffer for packet data
				PVOID data = ExAllocatePoolWithTag(
					NonPagedPool,
					dataLength,
					EDR_MEMORY_TAG
				);

				if (data)
				{
					// Copy packet data to our buffer
					PVOID dataBuffer = NdisGetDataBuffer(
						netBuffer,
						dataLength,
						data,
						1,      // AlignMultiple
						0       // AlignOffset
					);

					if (dataBuffer)
					{
						// Create DNS event
						PNETWORK_EVENT_QUEUE_ITEM queueItem =
							(PNETWORK_EVENT_QUEUE_ITEM)ExAllocatePoolWithTag(
								NonPagedPool,
								sizeof(NETWORK_EVENT_QUEUE_ITEM),
								EDR_MEMORY_TAG
							);

						if (queueItem)
						{
							RtlZeroMemory(queueItem, sizeof(NETWORK_EVENT_QUEUE_ITEM));
							queueItem->EventType = kEventType::NetworkDns;

							// Parse DNS packet
							if (NT_SUCCESS(ParseDnsPacket(
								dataBuffer,
								dataLength,
								&queueItem->Event.DnsEvent)))
							{
								// Fill additional information
								queueItem->Event.DnsEvent.Header.ProcessId =
									(ULONG)inMetaValues->processId;
								queueItem->Event.DnsEvent.DnsServerIp = remoteIp;
								queueItem->Event.DnsEvent.IsIpv6 = FALSE;

								// Check for suspicious domains
								BOOLEAN shouldBlock = FALSE;

								// Check 1: DGA detection
								if (IsSuspiciousDomain(queueItem->Event.DnsEvent.DomainName)) {
									DbgInfo("Suspicious DGA-like domain: %ws",
										queueItem->Event.DnsEvent.DomainName);
									shouldBlock = TRUE;
								}

								// Check 2: DNS tunneling detection (long domains)
								SIZE_T domainLen = wcslen(queueItem->Event.DnsEvent.DomainName);
								if (domainLen > 50) {  // Unusually long domain
									DbgInfo("Possible DNS tunneling - long domain: %ws",
										queueItem->Event.DnsEvent.DomainName);
									shouldBlock = TRUE;
								}

								// Check 3: TXT record queries (often used for C2)
								if (queueItem->Event.DnsEvent.QueryType == DnsQueryType::TXT) {
									DbgInfo("DNS TXT query detected: %ws",
										queueItem->Event.DnsEvent.DomainName);
									// Don't block TXT queries by default, but log them
								}

								// Set block status
								queueItem->Event.DnsEvent.IsBlocked = shouldBlock;

								if (shouldBlock) {
									// Block the DNS query
									classifyOut->actionType = FWP_ACTION_BLOCK;
									classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

									DbgInfo("Blocked DNS query to: %ws",
										queueItem->Event.DnsEvent.DomainName);
								}

								if (!NT_SUCCESS(QueueNetworkEvent(queueItem))) {
									ExFreePoolWithTag(queueItem, EDR_MEMORY_TAG);
								}
								else {
									InterlockedIncrement64(&g_NetworkMonitor->DnsQueries);
								}
							}
						}
						ExFreePoolWithTag(data, EDR_MEMORY_TAG);
					}
				}
			}
		}
		// Update statistics
		InterlockedIncrement64(&g_NetworkMonitor->TotalPackets);
		// Continue processing if not blocked
		if (classifyOut->actionType != FWP_ACTION_BLOCK) {
			classifyOut->actionType = FWP_ACTION_CONTINUE;
		}
	}

}

// =============================================================================
// PARSING FUNCTIONS
// =============================================================================


/*
 * ParseDnsPacket
 *
 * Extract DNS query information from raw packet
 * Handles DNS name compression and multiple labels
 */
NTSTATUS ParseDnsPacket(
	_In_ PVOID PacketData,
	_In_ UINT32 DataLength,
	_Out_ PDNS_EVENT DnsEvent
)
{
	if (DataLength < sizeof(DNS_HEADER)) {
		return STATUS_BUFFER_TOO_SMALL;
	}

	PDNS_HEADER dnsHeader = (PDNS_HEADER)PacketData;
	PUCHAR queryStart = (PUCHAR)PacketData + sizeof(DNS_HEADER);
	PUCHAR queryEnd = (PUCHAR)PacketData + DataLength;

	// Initialize event
	RtlZeroMemory(DnsEvent, sizeof(DNS_EVENT));
	DnsEvent->Header.EventType = kEventType::NetworkDns;
	DnsEvent->Header.TimeStamp = GetCurrentTimeStamp();

	// Network byte order conversion
	DnsEvent->QueryId = RtlUshortByteSwap(dnsHeader->TransactionId);

	// Parse DNS flags
	UINT16 flags = RtlUshortByteSwap(dnsHeader->Flags);
	BOOLEAN isResponse = (flags & 0x8000) ? TRUE : FALSE;

	// Parse domain name from query section
	PUCHAR p = queryStart;
	WCHAR domainName[256] = { 0 };
	SIZE_T domainIndex = 0;

	while (p < queryEnd && *p != 0 && domainIndex < 255)
	{
		UCHAR labelLength = *p++;

		// Check for compression pointer (starts with 0xC0)
		if ((labelLength & 0xC0) == 0xC0) {
			// DNS compression not handled in this simple parser
			// Would need to follow pointer to decompress
			break;
		}

		if (p + labelLength > queryEnd) {
			return STATUS_BUFFER_TOO_SMALL;
		}

		// Add dot separator between labels (except first)
		if (domainIndex > 0 && domainIndex < 255) {
			domainName[domainIndex++] = L'.';
		}

		// Copy label characters
		for (UCHAR i = 0; i < labelLength && domainIndex < 255; i++) {
			// Convert ASCII to Unicode
			domainName[domainIndex++] = (WCHAR)p[i];
		}

		p += labelLength;
	}

	// Skip null terminator
	if (p < queryEnd && *p == 0) {
		p++;
	}

	// Get query type and class (if we have room)
	if (p + 4 <= queryEnd) {
		UINT16 queryType = RtlUshortByteSwap(*(PUINT16)p);
		DnsEvent->QueryType = (DnsQueryType)queryType;
		p += 2;

		UINT16 queryClass = RtlUshortByteSwap(*(PUINT16)p);
		p += 2;
		// queryClass should be 1 (IN - Internet) for normal queries
	}

	// Copy domain name to event
	RtlStringCbCopyW(DnsEvent->DomainName, sizeof(DnsEvent->DomainName), domainName);


	if (isResponse)
	{
		DnsEvent->ResponseCode = flags & 0x000F;  // RCODE in lower 4 bits

		// Parse answer section if present
		UINT16 answerCount = RtlUshortByteSwap(dnsHeader->AnswerRRs);
		if (answerCount > 0 && p < queryEnd) {
			// Simple indication that we got answers
			// Full parsing would extract the IP addresses
			RtlStringCbCopyW(
				DnsEvent->ResolvedAddresses,
				sizeof(DnsEvent->ResolvedAddresses),
				L"<answers present>"
			);
		}
	}

	return STATUS_SUCCESS;
}

/*
*ParseHttpRequest
*
* Extract HTTP request information from TCP stream
* Parses method, URL, host, and other headers
*/
NTSTATUS ParseHttpRequest(
	_In_ PVOID StreamData,
	_In_ UINT32 DataLength,
	_Out_ PHTTP_EVENT HttpEvent
)
{
	PCHAR data = (PCHAR)StreamData;
	PCHAR dataEnd = data + DataLength;
	PCHAR line = data;
	PCHAR lineEnd;

	// Initialize event
	RtlZeroMemory(HttpEvent, sizeof(HTTP_EVENT));
	HttpEvent->Header.EventType = kEventType::NetworkHttp;
	HttpEvent->Header.TimeStamp = GetCurrentTimeStamp();

	// Find end of first line (request line)
	lineEnd = (PCHAR)RtlFindCharInString(line, '\r', dataEnd - line);
	if (!lineEnd || lineEnd >= dataEnd - 1 || lineEnd[1] != '\n') {
		return STATUS_INVALID_PARAMETER;
	}

	// Parse request line: "METHOD URL HTTP/x.x"
	PCHAR space1 = (PCHAR)RtlFindCharInString(line, ' ', lineEnd - line);
	if (!space1) {
		return STATUS_INVALID_PARAMETER;
	}

	// Extract method
	SIZE_T methodLen = min(space1 - line, 15);
	ANSI_STRING ansiMethod;
	ansiMethod.Buffer = line;
	ansiMethod.Length = (USHORT)methodLen;
	ansiMethod.MaximumLength = (USHORT)methodLen;

	UNICODE_STRING unicodeMethod;
	unicodeMethod.Buffer = HttpEvent->Method;
	unicodeMethod.MaximumLength = sizeof(HttpEvent->Method);

	RtlAnsiStringToUnicodeString(&unicodeMethod, &ansiMethod, FALSE);

	// Extract URL
	line = space1 + 1;
	PCHAR space2 = (PCHAR)RtlFindCharInString(line, ' ', lineEnd - line);
	if (space2) {
		SIZE_T urlLen = min(space2 - line, 511);
		ANSI_STRING ansiUrl;
		ansiUrl.Buffer = line;
		ansiUrl.Length = (USHORT)urlLen;
		ansiUrl.MaximumLength = (USHORT)urlLen;

		UNICODE_STRING unicodeUrl;
		unicodeUrl.Buffer = HttpEvent->Url;
		unicodeUrl.MaximumLength = sizeof(HttpEvent->Url);

		RtlAnsiStringToUnicodeString(&unicodeUrl, &ansiUrl, FALSE);
	}

	// Move to headers (skip \r\n)
	line = lineEnd + 2;

	// Parse headers until we hit empty line or end of data
	while (line < dataEnd && *line != '\r') {
		// Find end of this header line
		lineEnd = (PCHAR)RtlFindCharInString(line, '\r', dataEnd - line);
		if (!lineEnd) break;

		// Look for specific headers

		// Host header
		if (RtlCompareMemory(line, "Host: ", 6) == 6) {
			SIZE_T hostLen = min(lineEnd - line - 6, 255);
			ANSI_STRING ansiHost;
			ansiHost.Buffer = line + 6;
			ansiHost.Length = (USHORT)hostLen;
			ansiHost.MaximumLength = (USHORT)hostLen;

			UNICODE_STRING unicodeHost;
			unicodeHost.Buffer = HttpEvent->Host;
			unicodeHost.MaximumLength = sizeof(HttpEvent->Host);

			RtlAnsiStringToUnicodeString(&unicodeHost, &ansiHost, FALSE);
		}
		// User-Agent header
		else if (RtlCompareMemory(line, "User-Agent: ", 12) == 12) {
			SIZE_T uaLen = min(lineEnd - line - 12, 255);
			ANSI_STRING ansiUA;
			ansiUA.Buffer = line + 12;
			ansiUA.Length = (USHORT)uaLen;
			ansiUA.MaximumLength = (USHORT)uaLen;

			UNICODE_STRING unicodeUA;
			unicodeUA.Buffer = HttpEvent->UserAgent;
			unicodeUA.MaximumLength = sizeof(HttpEvent->UserAgent);

			RtlAnsiStringToUnicodeString(&unicodeUA, &ansiUA, FALSE);
		}
		// Referer header
		else if (RtlCompareMemory(line, "Referer: ", 9) == 9) {
			SIZE_T refLen = min(lineEnd - line - 9, 255);
			ANSI_STRING ansiRef;
			ansiRef.Buffer = line + 9;
			ansiRef.Length = (USHORT)refLen;
			ansiRef.MaximumLength = (USHORT)refLen;

			UNICODE_STRING unicodeRef;
			unicodeRef.Buffer = HttpEvent->Referer;
			unicodeRef.MaximumLength = sizeof(HttpEvent->Referer);

			RtlAnsiStringToUnicodeString(&unicodeRef, &ansiRef, FALSE);
		}
		// Content-Length header
		else if (RtlCompareMemory(line, "Content-Length: ", 16) == 16) {
			// Parse numeric value
			PCHAR numStart = line + 16;
			ULONG contentLength = 0;
			while (numStart < lineEnd && *numStart >= '0' && *numStart <= '9') {
				contentLength = contentLength * 10 + (*numStart - '0');
				numStart++;
			}
			HttpEvent->ContentLength = contentLength;
		}
		// Content-Type header
		else if (RtlCompareMemory(line, "Content-Type: ", 14) == 14) {
			SIZE_T ctLen = min(lineEnd - line - 14, 127);
			ANSI_STRING ansiCT;
			ansiCT.Buffer = line + 14;
			ansiCT.Length = (USHORT)ctLen;
			ansiCT.MaximumLength = (USHORT)ctLen;

			UNICODE_STRING unicodeCT;
			unicodeCT.Buffer = HttpEvent->ContentType;
			unicodeCT.MaximumLength = sizeof(HttpEvent->ContentType);

			RtlAnsiStringToUnicodeString(&unicodeCT, &ansiCT, FALSE);
		}

		// Move to next line
		line = lineEnd + 2;  // Skip \r\n
	}

	return STATUS_SUCCESS;
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/*
 * QueueNetworkEvent
 *
 * Thread-safe queuing of network events for user-mode consumption
 * Implements overflow protection
 */
NTSTATUS QueueNetworkEvent(_In_ PNETWORK_EVENT_QUEUE_ITEM Event)
{
	if (!g_NetworkMonitor || !Event) {
		return STATUS_INVALID_PARAMETER;
	}

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_NetworkMonitor->QueueLock, &oldIrql);

	// Check queue size to prevent memory exhaustion
	ULONG queueSize = 0;
	PLIST_ENTRY entry = g_NetworkMonitor->EventQueue.Flink;
	while (entry != &g_NetworkMonitor->EventQueue) {
		queueSize++;
		entry = entry->Flink;
	}

	if (queueSize >= MAX_QUEUED_EVENTS) {
		// Queue is full, drop oldest event
		PLIST_ENTRY oldest = RemoveHeadList(&g_NetworkMonitor->EventQueue);
		PNETWORK_EVENT_QUEUE_ITEM oldItem = CONTAINING_RECORD(
			oldest,
			NETWORK_EVENT_QUEUE_ITEM,
			ListEntry
		);
		ExFreePoolWithTag(oldItem, EDR_MEMORY_TAG);
		DbgInfo("Network event queue full, dropping oldest event");
	}

	// Queue the new event
	InsertTailList(&g_NetworkMonitor->EventQueue, &Event->ListEntry);

	KeReleaseSpinLock(&g_NetworkMonitor->QueueLock, oldIrql);

	return STATUS_SUCCESS;
}

/*
 * GetNetworkEvent
 *
 * Retrieve queued event for user-mode
 * Called via IOCTL
 */
NTSTATUS GetNetworkEvent(PVOID Buffer, ULONG BufferSize, PULONG BytesWritten)
{
	if (!g_NetworkMonitor || !Buffer || !BytesWritten) {
		return STATUS_INVALID_PARAMETER;
	}

	if (BufferSize < sizeof(EVENT_HEADER)) {
		return STATUS_BUFFER_TOO_SMALL;
	}

	*BytesWritten = 0;

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_NetworkMonitor->QueueLock, &oldIrql);

	if (IsListEmpty(&g_NetworkMonitor->EventQueue)) {
		KeReleaseSpinLock(&g_NetworkMonitor->QueueLock, oldIrql);
		return STATUS_NO_MORE_ENTRIES;
	}

	// Remove event from queue
	PLIST_ENTRY entry = RemoveHeadList(&g_NetworkMonitor->EventQueue);
	PNETWORK_EVENT_QUEUE_ITEM queueItem = CONTAINING_RECORD(
		entry,
		NETWORK_EVENT_QUEUE_ITEM,
		ListEntry
	);

	KeReleaseSpinLock(&g_NetworkMonitor->QueueLock, oldIrql);

	// Determine event size and copy
	SIZE_T copySize = 0;
	PVOID sourceData = NULL;

	switch (queueItem->EventType) {
	case kEventType::NetworkConnect:
		copySize = sizeof(NETWORK_CONNECTION_EVENT);
		sourceData = &queueItem->Event.ConnectionEvent;
		break;

	case kEventType::NetworkDns:
		copySize = sizeof(DNS_EVENT);
		sourceData = &queueItem->Event.DnsEvent;
		break;

	case kEventType::NetworkHttp:
		copySize = sizeof(HTTP_EVENT);
		sourceData = &queueItem->Event.HttpEvent;
		break;

	default:
		ExFreePoolWithTag(queueItem, EDR_MEMORY_TAG);
		return STATUS_INVALID_PARAMETER;
	}

	if (BufferSize < copySize) {
		// Re-queue the event since buffer is too small
		KeAcquireSpinLock(&g_NetworkMonitor->QueueLock, &oldIrql);
		InsertHeadList(&g_NetworkMonitor->EventQueue, &queueItem->ListEntry);
		KeReleaseSpinLock(&g_NetworkMonitor->QueueLock, oldIrql);
		return STATUS_BUFFER_TOO_SMALL;
	}

	// Copy event to user buffer
	RtlCopyMemory(Buffer, sourceData, copySize);
	*BytesWritten = (ULONG)copySize;

	// Free queue item
	ExFreePoolWithTag(queueItem, EDR_MEMORY_TAG);

	return STATUS_SUCCESS;
}

/*
 * IsHttpPort
 *
 * Check if port is commonly used for HTTP/HTTPS
 */
BOOLEAN IsHttpPort(UINT16 Port)
{
	return (Port == 80 ||    // HTTP
		Port == 443 ||   // HTTPS
		Port == 8080 ||  // HTTP alternate
		Port == 8000 ||  // HTTP alternate
		Port == 8443 ||  // HTTPS alternate
		Port == 3000 ||  // Node.js common
		Port == 5000);   // Flask/development
}

/*
 * IsDnsPort
 *
 * Check if port is DNS (53)
 */
BOOLEAN IsDnsPort(UINT16 Port)
{
	return (Port == 53);
}

/*
 * IdentifyApplicationProtocol
 *
 * Map port number to known application protocol
 */
ApplicationProtocol IdentifyApplicationProtocol(UINT16 Port)
{
	switch (Port) {
		// Web protocols
	case 80: return ApplicationProtocol::HTTP;
	case 443: return ApplicationProtocol::HTTPS;
	case 8080: return ApplicationProtocol::HTTP_ALT;
	case 8443: return ApplicationProtocol::HTTPS_ALT;

		// Email protocols
	case 25: return ApplicationProtocol::SMTP;
	case 465: return ApplicationProtocol::SMTPS;
	case 110: return ApplicationProtocol::POP3;
	case 995: return ApplicationProtocol::POP3S;
	case 143: return ApplicationProtocol::IMAP;
	case 993: return ApplicationProtocol::IMAPS;

		// File transfer
	case 21: return ApplicationProtocol::FTP;
	case 990: return ApplicationProtocol::FTPS;

		// Remote access
	case 22: return ApplicationProtocol::SSH;
	case 23: return ApplicationProtocol::TELNET;
	case 3389: return ApplicationProtocol::RDP;

		// Network services
	case 53: return ApplicationProtocol::DNS;

		// Directory services
	case 389: return ApplicationProtocol::LDAP;
	case 636: return ApplicationProtocol::LDAPS;

		// File sharing
	case 445: return ApplicationProtocol::SMB;

		// Known malicious
	case 4444: return ApplicationProtocol::BACKDOOR1;
	case 1337: return ApplicationProtocol::BACKDOOR2;

	default: return ApplicationProtocol::Unknown;
	}
}


/*
 * IsSuspiciousDomain
 *
 * Heuristic detection of DGA (Domain Generation Algorithm) domains
 * Checks for:
 * - High consonant to vowel ratio
 * - Excessive length
 * - Suspicious TLDs
 * - Known patterns
 */
BOOLEAN IsSuspiciousDomain(_In_ PCWSTR DomainName)
{
	if (!DomainName || *DomainName == L'\0') {
		return FALSE;
	}

	SIZE_T length = wcslen(DomainName);

	// Check for suspicious TLDs
	if (wcsstr(DomainName, L".tk") != NULL ||      // Tokelau - free domains
		wcsstr(DomainName, L".ml") != NULL ||      // Mali - free domains
		wcsstr(DomainName, L".ga") != NULL ||      // Gabon - free domains
		wcsstr(DomainName, L".cf") != NULL ||      // Central African Republic
		wcsstr(DomainName, L".bit") != NULL ||     // Blockchain DNS
		wcsstr(DomainName, L".onion") != NULL) {   // Tor hidden service
		return TRUE;
	}

	// Count vowels and consonants for entropy analysis
	int vowelCount = 0;
	int consonantCount = 0;
	int digitCount = 0;

	// Only analyze the domain part (before first dot)
	PCWSTR firstDot = wcschr(DomainName, L'.');
	SIZE_T analyzeLength = firstDot ? (firstDot - DomainName) : length;

	for (SIZE_T i = 0; i < analyzeLength; i++) {
		WCHAR ch = towlower(DomainName[i]);

		if (ch >= L'0' && ch <= L'9') {
			digitCount++;
		}
		else if (ch == L'a' || ch == L'e' || ch == L'i' ||
			ch == L'o' || ch == L'u' || ch == L'y') {
			vowelCount++;
		}
		else if (ch >= L'a' && ch <= L'z') {
			consonantCount++;
		}
	}

	// DGA domains often have very high consonant to vowel ratios
	if (vowelCount > 0 && consonantCount > 0) {
		float ratio = (float)consonantCount / vowelCount;
		if (ratio > 4.0) {  // Normal English is around 1.5-2.0
			return TRUE;
		}
	}

	// DGA domains often have many consecutive consonants
	int maxConsecutiveConsonants = 0;
	int currentConsecutive = 0;

	for (SIZE_T i = 0; i < analyzeLength; i++) {
		WCHAR ch = towlower(DomainName[i]);

		if (ch >= L'a' && ch <= L'z' &&
			ch != L'a' && ch != L'e' && ch != L'i' &&
			ch != L'o' && ch != L'u' && ch != L'y') {
			currentConsecutive++;
			if (currentConsecutive > maxConsecutiveConsonants) {
				maxConsecutiveConsonants = currentConsecutive;
			}
		}
		else {
			currentConsecutive = 0;
		}
	}

	// More than 4 consecutive consonants is suspicious
	if (maxConsecutiveConsonants > 4) {
		return TRUE;
	}

	// Very long domain names (possible DNS tunneling)
	if (analyzeLength > 30) {
		return TRUE;
	}

	// High percentage of digits
	if (analyzeLength > 0 && digitCount > analyzeLength / 2) {
		return TRUE;
	}

	return FALSE;
}

/*
 * IsPrivateIp
 *
 * Check if IP address is in private range (RFC1918)
 * Used to detect internal vs external connections
 */
BOOLEAN IsPrivateIp(_In_ UINT32 IpAddress)
{
	// Network byte order
	UCHAR octet1 = (UCHAR)(IpAddress & 0xFF);
	UCHAR octet2 = (UCHAR)((IpAddress >> 8) & 0xFF);

	// 10.0.0.0/8
	if (octet1 == 10) {
		return TRUE;
	}

	// 172.16.0.0/12
	if (octet1 == 172 && octet2 >= 16 && octet2 <= 31) {
		return TRUE;
	}

	// 192.168.0.0/16
	if (octet1 == 192 && octet2 == 168) {
		return TRUE;
	}

	// 127.0.0.0/8 (loopback)
	if (octet1 == 127) {
		return TRUE;
	}

	return FALSE;
}

/*
 * RtlFindCharInString
 *
 * Helper to find character in string with bounds checking
 */
static PCHAR RtlFindCharInString(PCHAR String, CHAR Char, SIZE_T MaxLength)
{
	for (SIZE_T i = 0; i < MaxLength; i++) {
		if (String[i] == Char) {
			return &String[i];
		}
		if (String[i] == '\0') {
			break;
		}
	}
	return NULL;
}

// =============================================================================
// WFP CALLBACK STUBS
// =============================================================================

/*
 * NetworkNotifyFn
 *
 * Called when filters are added/removed
 * Currently just a stub - could be used for filter-specific initialization
 */
NTSTATUS NTAPI NetworkNotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER* filter
)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}


/*
 * NetworkFlowDeleteFn
 *
 * Called when TCP connection terminates
 * Could be used to generate connection summary events
 */
VOID NTAPI NetworkFlowDeleteFn(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext
)
{
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);

	// TODO: Generate connection termination event with statistics
	// flowContext could point to per-connection state structure
}





































































































































































































