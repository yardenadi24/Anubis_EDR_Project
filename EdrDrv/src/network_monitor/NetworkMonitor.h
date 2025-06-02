#pragma once
/*
 * NetworkMonitor.h
 *
 * Purpose: Windows Filtering Platform (WFP) based network monitoring for Anubis EDR
 *
 * This module implements kernel-level network traffic inspection using WFP callouts
 * to monitor TCP/UDP connections, DNS queries, and HTTP/HTTPS traffic.
 *
 * Architecture:
 *   - Registers WFP callouts at different network layers
 *   - Inspects network packets and connections
 *   - Generates security events for suspicious activity
 *   - Queues events for user-mode consumption
 */

 // Windows kernel headers
#include <ntifs.h>
#include <fwpsk.h>      // WFP kernel-mode API
#include <fwpmk.h>      // WFP management kernel-mode API
#include <ws2ipdef.h>   // IP protocol definitions
#include <in6addr.h>    // IPv6 structures
#include <ip2string.h>  // IP address string conversion

// Project headers
#include "../commons/commons.h"
#include "../utils/KUtils.h"

typedef struct _NETWORK_MONITOR NETWORK_MONITOR, * PNETWORK_MONITOR;
typedef struct _NETWORK_EVENT_QUEUE_ITEM NETWORK_EVENT_QUEUE_ITEM, * PNETWORK_EVENT_QUEUE_ITEM;

/*
 * Layer 4 (Transport Layer) Protocol Identifiers
 * These values match the official IANA protocol numbers
 * 
 * "https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml"
 */

enum class NetworkProtocol : UINT16 {
    TCP = 6,        // Transmission Control Protocol - Reliable, ordered delivery
    UDP = 17,       // User Datagram Protocol - Fast, unreliable delivery
    ICMP = 1,       // Internet Control Message Protocol - Network diagnostics (ping)
    Unknown = 0xFFFF
};

/*
 * Network Traffic Direction
 * Used to distinguish between outgoing and incoming connections
 */
enum class NetworkDirection : UINT8 {
    Outbound = 0,   // Local system initiating connection to remote
    Inbound = 1     // Remote system connecting to local
};


 /*
  * Layer 7 (Application Layer) Protocol Identifiers
  * Port numbers used to identify common application protocols
  */
enum class ApplicationProtocol : UINT16 {
    Unknown = 0,

    // Web protocols
    HTTP = 80,      // HyperText Transfer Protocol - Unencrypted web traffic
    HTTPS = 443,    // HTTP Secure - Encrypted web traffic using TLS/SSL
    HTTP_ALT = 8080, // Alternative HTTP port - Often used for proxies
    HTTPS_ALT = 8443, // Alternative HTTPS port

    // Email protocols
    SMTP = 25,      // Simple Mail Transfer Protocol - Sending email (unencrypted)
    SMTPS = 465,    // SMTP Secure - Encrypted email sending
    POP3 = 110,     // Post Office Protocol v3 - Retrieving email (downloads and deletes)
    POP3S = 995,    // POP3 Secure - Encrypted email retrieval
    IMAP = 143,     // Internet Message Access Protocol - Email synchronization
    IMAPS = 993,    // IMAP Secure - Encrypted email synchronization

    // File transfer
    FTP = 21,       // File Transfer Protocol - Control channel (commands)
    FTPS = 990,     // FTP Secure - Encrypted file transfer

    // Remote access (HIGH RISK - Often targeted by attackers)
    SSH = 22,       // Secure Shell - Encrypted terminal access (Linux/Unix)
    TELNET = 23,    // Telnet - UNENCRYPTED terminal access (DEPRECATED - security risk!)
    RDP = 3389,     // Remote Desktop Protocol - Windows remote desktop

    // Network services
    DNS = 53,       // Domain Name System - Translates domains to IPs (critical for C2)
    DHCP = 67,      // Dynamic Host Configuration Protocol - Network configuration

    // Directory services
    LDAP = 389,     // Lightweight Directory Access Protocol - Active Directory queries
    LDAPS = 636,    // LDAP Secure - Encrypted directory queries

    // File sharing (Often abused for lateral movement)
    SMB = 445,      // Server Message Block - Windows file/printer sharing

    // Database ports (Data exfiltration targets)
    MYSQL = 3306,   // MySQL database
    MSSQL = 1433,   // Microsoft SQL Server
    POSTGRESQL = 5432, // PostgreSQL database

    // Known malicious ports
    BACKDOOR1 = 4444, // Common backdoor port (Metasploit default)
    BACKDOOR2 = 1337  // "Leet" backdoor port
};

/*
 * DNS Query Types
 * Different types of DNS resource records that can be queried
 */
enum class DnsQueryType : UINT16 {
    A = 1,          // IPv4 Address - Maps hostname to IPv4 (example.com -> 93.184.216.34)
    NS = 2,         // Name Server - Authoritative DNS servers for domain
    CNAME = 5,      // Canonical Name - Alias record (www.example.com -> example.com)
    SOA = 6,        // Start of Authority - Primary DNS server info
    PTR = 12,       // Pointer - Reverse DNS (IP -> hostname) used in email validation
    MX = 15,        // Mail Exchange - Email server for domain
    TXT = 16,       // Text - Arbitrary text (SPF records, domain verification, C2 commands!)
    AAAA = 28,      // IPv6 Address - Maps hostname to IPv6
    SRV = 33        // Service - Service location (used in Active Directory)
};

#pragma pack(push, 1)  // Ensure no padding for network protocols
/*
 * DNS Header Structure
 * First 12 bytes of any DNS packet
 */
typedef struct _DNS_HEADER {
    UINT16 TransactionId;    // Random ID to match queries with responses
    UINT16 Flags;           // Query/Response, OpCode, Response Code
    UINT16 Questions;       // Number of questions
    UINT16 AnswerRRs;       // Number of answer resource records
    UINT16 AuthorityRRs;    // Number of authority resource records
    UINT16 AdditionalRRs;   // Number of additional resource records
} DNS_HEADER, * PDNS_HEADER;

// DNS Flags breakdown:
// Bit 15: QR (0=Query, 1=Response)
// Bits 14-11: OpCode (0=Standard query)
// Bit 10: AA (Authoritative Answer)
// Bit 9: TC (Truncated)
// Bit 8: RD (Recursion Desired)
// Bit 7: RA (Recursion Available)
// Bits 6-4: Z (Reserved)
// Bits 3-0: RCODE (Response Code: 0=No error, 3=NXDOMAIN)

#pragma pack(pop)

// HTTP Methods for detection
#define HTTP_METHOD_GET     "GET"      // Read data
#define HTTP_METHOD_POST    "POST"     // Submit data (potential exfiltration)
#define HTTP_METHOD_PUT     "PUT"      // Upload file (potential malware drop)
#define HTTP_METHOD_DELETE  "DELETE"   // Delete resource
#define HTTP_METHOD_HEAD    "HEAD"     // Headers only
#define HTTP_METHOD_OPTIONS "OPTIONS"  // Allowed methods
#define HTTP_METHOD_CONNECT "CONNECT"  // Establish tunnel (proxy)


/*
 * Unique identifiers for our WFP callouts
 * These must be globally unique - generate new GUIDs for production!
 *
 * Layer explanation:
 * - ALE (Application Layer Enforcement): Connection-level decisions
 * - STREAM: TCP data inspection after connection established
 * - DATAGRAM: UDP packet inspection
 */


 // Outbound connection monitoring (detect C2, exfiltration)
DEFINE_GUID(ANUBIS_ALE_CONNECT_CALLOUT_V4,
    0x494b2a97, 0x4bd2, 0x4c15, 0xb7, 0x78, 0x14, 0xcd, 0x9f, 0xa5, 0x12, 0x4d);
DEFINE_GUID(ANUBIS_ALE_CONNECT_CALLOUT_V6,
    0x1bc6955a, 0x84ac, 0x4488, 0x87, 0x87, 0xad, 0x53, 0x2d, 0x25, 0x35, 0x15);

// Inbound connection monitoring (detect reverse shells, backdoors)
DEFINE_GUID(ANUBIS_ALE_RECV_ACCEPT_CALLOUT_V4,
    0xebba83f9, 0x1af2, 0x491b, 0xbd, 0x42, 0x5, 0x45, 0xb3, 0x1e, 0x13, 0x3f);
DEFINE_GUID(ANUBIS_ALE_RECV_ACCEPT_CALLOUT_V6,
    0x7d1a8b13, 0x6c03, 0x452a, 0x8c, 0xee, 0x4a, 0xc6, 0xe, 0x49, 0x8, 0x11);

// TCP stream inspection (HTTP parsing, data exfiltration detection)
DEFINE_GUID(ANUBIS_STREAM_CALLOUT_V4,
        0x6feb08fa, 0x6fcd, 0x4c12, 0x97, 0x91, 0x89, 0x3d, 0x7d, 0x9b, 0x9b, 0xc2);
DEFINE_GUID(ANUBIS_STREAM_CALLOUT_V6,
        0xa41db051, 0xf455, 0x4bba, 0xaa, 0xc3, 0xef, 0xf4, 0x80, 0xd4, 0x47, 0x64);

// UDP packet inspection (DNS monitoring, C2 over DNS)
DEFINE_GUID(ANUBIS_DATAGRAM_CALLOUT_V4,
        0xd632d1af, 0xc5f6, 0x4c69, 0x82, 0x18, 0x10, 0x50, 0x4, 0xe9, 0x1, 0x56);
DEFINE_GUID(ANUBIS_DATAGRAM_CALLOUT_V6,
        0x80d5bed9, 0x9c7a, 0x4db6, 0x89, 0xca, 0xd7, 0x44, 0x44, 0x8e, 0x3c, 0xc5);

// =============================================================================
// NETWORK EVENT STRUCTURES
// =============================================================================

/*
 * Network Connection Event
 * Generated when a process initiates or accepts a network connection
 */
typedef struct _NETWORK_CONNECTION_EVENT {

    EVENT_HEADER Header;         // Standard event header with timestamp, PID
    NetworkProtocol Protocol;    // TCP/UDP/ICMP
    NetworkDirection Direction;  // Inbound/Outbound

    // IPv4 addresses (network byte order)
    UINT32 LocalIpAddress;
    UINT32 RemoteIpAddress;

    // IPv6 addresses (only used if IsIpv6 = TRUE)
    UINT8 LocalIpv6Address[16];
    UINT8 RemoteIpv6Address[16];

    // Port information
    UINT16 LocalPort;           // Source port for outbound, dest for inbound
    UINT16 RemotePort;          // Dest port for outbound, source for inbound

    // Process information
    WCHAR ProcessPath[260];     // Full path of process making connection

    // Connection metadata
    BOOLEAN IsIpv6;             // TRUE if IPv6 connection
    BOOLEAN IsLoopback;         // TRUE if localhost connection

    // Traffic statistics (filled on connection close)
    UINT64 BytesSent;
    UINT64 BytesReceived;

} NETWORK_CONNECTION_EVENT, * PNETWORK_CONNECTION_EVENT;

/*
 * DNS Query/Response Event
 * Generated for DNS lookups - critical for detecting C2 and exfiltration
 */
typedef struct _DNS_EVENT {

    EVENT_HEADER Header;
    WCHAR DomainName[256];      // Domain being queried (e.g., "malware.com")
    UINT32 QueryId;             // DNS transaction ID
    DnsQueryType QueryType;     // A, AAAA, TXT, etc.

    // DNS server information
    UINT32 DnsServerIp;         // IPv4 DNS server
    UINT8 DnsServerIpv6[16];    // IPv6 DNS server
    BOOLEAN IsIpv6;

    // Response information (if available)
    WCHAR ResolvedAddresses[512]; // Comma-separated IP addresses
    BOOLEAN IsBlocked;          // TRUE if we blocked this query
    UINT32 ResponseCode;        // 0=Success, 3=NXDOMAIN

} DNS_EVENT, * PDNS_EVENT;

/*
 * HTTP Request Event
 * Generated for HTTP/HTTPS requests - monitors web traffic and data exfiltration
 */
typedef struct _HTTP_EVENT {
    EVENT_HEADER Header;
    WCHAR Url[512];            // Request path (e.g., "/api/upload")
    WCHAR Host[256];           // Target host (e.g., "c2server.com")
    WCHAR Method[16];          // GET, POST, PUT, etc.
    WCHAR UserAgent[256];      // Browser/tool identification
    WCHAR Referer[256];        // Source page (can reveal browsing chain)

    // Response information
    UINT16 StatusCode;         // 200=OK, 404=Not Found, etc.
    UINT32 ContentLength;      // Size of response/upload
    WCHAR ContentType[128];    // MIME type (e.g., "application/octet-stream")

    // Connection information
    BOOLEAN IsHttps;           // TRUE if HTTPS (port 443)
    UINT32 RemoteIp;
    UINT16 RemotePort;

} HTTP_EVENT, * PHTTP_EVENT;

#define IOCTL_GET_NETWORK_EVENT     EDR_CTL_CODE_BUFFERED(0x810)  // Retrieve queued events
#define IOCTL_POST_NETWORK_VERDICT  EDR_CTL_CODE_BUFFERED(0x811)  // Allow/block decision

// =============================================================================
// NETWORK MONITOR STATE STRUCTURE
// =============================================================================

/*
 * Main network monitor context
 * Singleton instance managing all network monitoring
 */

typedef struct _NETWORK_MONITOR {

    // Event queue management
    LIST_ENTRY EventQueue;      // Linked list of pending events
    KSPIN_LOCK QueueLock;      // Synchronization for queue access
    KIRQL OldIrql;             // Saved IRQL for spinlock

    // State flags
    BOOLEAN IsMonitoring;       // TRUE when actively monitoring
    BOOLEAN IsInitialized;      // TRUE after successful init

    // WFP handles
    HANDLE EngineHandle;        // WFP filter engine handle

    // Registered callout IDs (used for unregistration)
    UINT32 AleConnectCalloutIdV4;
    UINT32 AleConnectCalloutIdV6;
    UINT32 AleRecvAcceptCalloutIdV4;
    UINT32 AleRecvAcceptCalloutIdV6;
    UINT32 StreamCalloutIdV4;
    UINT32 StreamCalloutIdV6;
    UINT32 DatagramCalloutIdV4;
    UINT32 DatagramCalloutIdV6;

    // Performance statistics
    LONG64 TotalConnections;    // Total connections monitored
    LONG64 TotalPackets;        // Total packets inspected
    LONG64 TotalBytes;          // Total bytes processed
    LONG64 BlockedConnections;  // Connections blocked
    LONG64 DnsQueries;          // DNS queries monitored
    LONG64 HttpRequests;        // HTTP requests parsed

} NETWORK_MONITOR, * PNETWORK_MONITOR;

/*
 * Event queue entry
 * Wraps different event types for queuing
 */

typedef struct _NETWORK_EVENT_QUEUE_ITEM {
    LIST_ENTRY ListEntry;       // For linking in queue
    kNetworkEventType EventType;       // Type of event
    union {
        NETWORK_CONNECTION_EVENT ConnectionEvent;
        DNS_EVENT DnsEvent;
        HTTP_EVENT HttpEvent;
    } Event;
} NETWORK_EVENT_QUEUE_ITEM, * PNETWORK_EVENT_QUEUE_ITEM;

/*
 * Initialize the network monitor subsystem
 * Called once during driver initialization
 *
 * Returns: STATUS_SUCCESS or appropriate error code
 */
NTSTATUS
InitializeNetworkMonitor();

/*
 * Cleanup and uninitialize network monitor
 * Called during driver unload
 */
VOID
UninitializeNetworkMonitor();

/*
 * Start active network monitoring
 * Enables all registered callouts
 *
 * Returns: STATUS_SUCCESS or error code
 */
NTSTATUS
StartNetworkMonitoring();

/*
 * Stop network monitoring
 * Disables callouts but keeps registration
 *
 * Returns: STATUS_SUCCESS or error code
 */
NTSTATUS
StopNetworkMonitoring();

/*
 * Retrieve next network event from queue
 * Called by user-mode via IOCTL
 *
 * Parameters:
 *   Buffer - Output buffer for event data
 *   BufferSize - Size of output buffer
 *   BytesWritten - Actual bytes written
 *
 * Returns: STATUS_SUCCESS, STATUS_NO_MORE_ENTRIES, or error
 */
NTSTATUS
GetNetworkEvent(
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesWritten
);

// =============================================================================
// WFP CALLOUT FUNCTIONS
// =============================================================================

/*
 * Connection-level inspection callout
 * Called when process initiates network connection
 *
 * Primary detection point for:
 * - C2 communication attempts
 * - Data exfiltration connections
 * - Lateral movement (SMB, RDP)
 * - Reverse shell connections
 */
VOID
NTAPI
NetworkConnectClassifyFn(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

/*
 * TCP stream data inspection callout
 * Called for TCP data after connection established
 *
 * Primary detection point for:
 * - HTTP header analysis
 * - Data exfiltration content
 * - Protocol violations
 * - Encrypted traffic patterns
 */
VOID
NTAPI
NetworkStreamClassifyFn(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

/*
 * UDP packet inspection callout
 * Called for each UDP packet
 *
 * Primary detection point for:
 * - DNS tunneling/exfiltration
 * - Malicious DNS queries
 * - UDP-based C2 protocols
 * - Network scanning
 */
VOID
NTAPI
NetworkDatagramClassifyFn(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

/*
 * Filter state notification callback
 * Called when filters are added/removed
 */
NTSTATUS 
NTAPI 
NetworkNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER* filter
);

/*
 * Flow/connection cleanup callback
 * Called when TCP connection closes
 * Used to generate connection summary events
 */
VOID 
NTAPI 
NetworkFlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
);

// =============================================================================
// INTERNAL HELPER FUNCTIONS
// =============================================================================
/*
 * Register all WFP callouts
 * Internal initialization helper
 */
NTSTATUS
RegisterWfpCallouts();

/*
 * Add WFP filters to direct traffic to callouts
 * Internal initialization helper
 */
NTSTATUS
AddWfpFilters();

/*
 * Parse DNS packet and extract query information
 *
 * Parameters:
 *   PacketData - Raw DNS packet data
 *   DataLength - Length of packet
 *   DnsEvent - Output event structure
 *
 * Returns: STATUS_SUCCESS or STATUS_BUFFER_TOO_SMALL
 */
NTSTATUS
ParseDnsPacket(
    _In_ PVOID PacketData,
    _In_ UINT32 DataLength,
    _Out_ PDNS_EVENT DnsEvent
);

/*
 * Parse HTTP request headers
 *
 * Parameters:
 *   StreamData - TCP stream data containing HTTP
 *   DataLength - Length of data
 *   HttpEvent - Output event structure
 *
 * Returns: STATUS_SUCCESS or parsing error
 */
NTSTATUS
ParseHttpRequest(
    _In_ PVOID StreamData,
    _In_ UINT32 DataLength,
    _Out_ PHTTP_EVENT HttpEvent
);

/*
 * Check if port typically used for HTTP/HTTPS
 */
BOOLEAN
IsHttpPort(UINT16 Port);

/*
 * Check if port is DNS (53)
 */
BOOLEAN
IsDnsPort(UINT16 Port);

/*
 * Identify application protocol by port number
 */
ApplicationProtocol
IdentifyApplicationProtocol(UINT16 Port);

/*
 * Queue event for user-mode consumption
 * Thread-safe event queuing
 */
NTSTATUS
QueueNetworkEvent(
    _In_ PNETWORK_EVENT_QUEUE_ITEM Event
);

/*
 * Check if domain appears to be DGA-generated
 * Heuristic detection for random domains
 */
BOOLEAN
IsSuspiciousDomain(
    _In_ PCWSTR DomainName
);

/*
 * Check if IP is in private range (RFC1918)
 */
BOOLEAN 
IsPrivateIp(
    _In_ UINT32 IpAddress
);

static PCHAR RtlFindCharInString(PCHAR String, CHAR Char, SIZE_T MaxLength);