#pragma once
#include <ntddk.h>

/*
    Dispatcher for Application-Layer Protocols

    Routes TCP/UDP packets to protocol-specific parsers like HTTP and DNS.
    Called from within the transport-layer parsing logic.
*/

// Used when protocol is determined to be HTTP based on port
VOID DispatchHTTP(
    _In_reads_bytes_(Length) PUCHAR Payload,
    _In_ SIZE_T Length,
    _In_ UINT32 SourceIp,
    _In_ UINT32 DestIp,
    _In_ UINT16 SourcePort,
    _In_ UINT16 DestPort
);

// Used when protocol is determined to be DNS based on port
VOID DispatchDNS(
    _In_reads_bytes_(Length) PUCHAR Payload,
    _In_ SIZE_T Length,
    _In_ UINT32 SourceIp,
    _In_ UINT32 DestIp,
    _In_ UINT16 SourcePort,
    _In_ UINT16 DestPort
);