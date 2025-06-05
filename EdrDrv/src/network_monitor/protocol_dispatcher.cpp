#include "protocol_dispatcher.h"
#include <ntstrsafe.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Helper to convert safe ASCII string
static void LogString(const char* label, const char* start, size_t maxLen) {
    char buffer[256] = { 0 };
    size_t len = MIN(maxLen, sizeof(buffer) - 1);
    for (size_t i = 0; i < len && start[i] != '\r' && start[i] != '\n'; ++i) {
        buffer[i] = start[i];
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EDR] %s: %s\n", label, buffer);
}

VOID
DispatchHTTP(
    PUCHAR Payload,
    SIZE_T Length,
    UINT32 SourceIp,
    UINT32 DestIp,
    UINT16 SourcePort,
    UINT16 DestPort
)
{
    UNREFERENCED_PARAMETER(SourcePort);
    UNREFERENCED_PARAMETER(DestPort);

    if (Length == 0 || Payload == NULL)
        return;

    // Simple check: Does payload start with HTTP method?
    if (Length >= 4 &&
        (RtlCompareMemory(Payload, "GET ", 4) == 4 ||
        RtlCompareMemory(Payload, "POST", 4) == 4 ||
        RtlCompareMemory(Payload, "HEAD", 4) == 4 ||
        RtlCompareMemory(Payload, "PUT ", 4) == 4)) 
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[EDR] HTTP request detected (SrcIP: %08X, DstIP: %08X)\n",
            SourceIp, DestIp);
    }
}


VOID
DispatchDNS(
    PUCHAR Payload,
    SIZE_T Length,
    UINT32 SourceIp,
    UINT32 DestIp,
    UINT16 SourcePort,
    UINT16 DestPort
)
{
    if (Length < 12) 
        return; // DNS header is 12 bytes

    // First 2 bytes: Transaction ID
    UINT16 transactionId = (Payload[0] << 8) | Payload[1];

    // Byte 2-3: Flags (query/response, opcodes, etc.)
    UINT16 flags = (Payload[2] << 8) | Payload[3];
    BOOLEAN isResponse = (flags & 0x8000) != 0;

    // Simple log for query detection
    if (!isResponse) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[EDR] DNS query detected: TransactionID=%04x, SrcIP=%08X -> DstIP=%08X\n",
            transactionId, SourceIp, DestIp);
    }

}