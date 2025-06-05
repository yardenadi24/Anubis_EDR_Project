#pragma once
#include <ntddk.h>

#pragma pack(push, 1)
/*
  The following diagram illustrates the place of the internet protocol
  in the protocol hierarchy:


                 +------+ +-----+ +-----+     +-----+
                 |Telnet| | FTP | | TFTP| ... | ... |
                 +------+ +-----+ +-----+     +-----+
                       |   |         |           |
                      +-----+     +-----+     +-----+
                      | TCP |     | UDP | ... | ... |
                      +-----+     +-----+     +-----+
                         |           |           |
                      +--------------------------+----+
                      |    Internet Protocol & ICMP   |
                      +--------------------------+----+
                                     |
                        +---------------------------+
                        |   Local Network Protocol  |
                        +---------------------------+
*/



/*
	IPv4 Header Structure � Based on RFC 791

	Used for identifying:
	source/destination IPs,
	fragmentation,
	TTL-based evasion,
	and protocol dispatching (TCP, UDP, ICMP).

        0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Version:                 4 bits The Version field indicates the format of the internet header.  This document describes version 4.
   IHL:                     4 bits Internet Header Length is the length of the internet header in 32 bit words,
                                    and thus points to the beginning of the data.  Note that
                                    the minimum value for a correct header is 5.
   Type of Service:         8 bits The Type of Service provides an indication of the abstract parameters of the quality of service desired.
   Total Length:            16 bits Total Length is the length of the datagram, measured in octets, including internet header and data.  This field allows the length of a datagram to be up to 65,535 octets
   Identification:          16 bits
   Flags:                   3 bits
   Time to Live:            8 bits  This field indicates the maximum time the datagram is allowed to remain in the internet system.
   Protocol:                8 bits  This field indicates the next level protocol used in the data
                                    portion of the internet datagram.  The values for various protocols
                                    are specified in "Assigned Numbers"
   Header Checksum:         16 bits
   Source Address:          32 bits
   Destination Address:     32 bits

*/

typedef struct _IPv4Header {
    UINT8  Version : 4;             // 4 bits � IP version, should be 4
    UINT8  HeaderLength : 4;        // 4 bits � number of 32-bit words in header (usually 5)

    UINT8  TypeOfService;           // 1 byte  � Differentiated services (DSCP/ECN)
    UINT16 TotalLength;             // 2 bytes � Total length of packet (header + data)

    UINT16 Identification;          // 2 bytes � Used for fragmentation tracking
    UINT16 FlagsAndOffset;          // 2 bytes � Flags (3 bits) + Fragment offset (13 bits)

    UINT8  TimeToLive;              // 1 byte  � Decremented each hop, detects loops
    UINT8  Protocol;                // 1 byte  � Upper layer protocol (e.g., TCP = 6)
    UINT16 HeaderChecksum;          // 2 bytes � Checksum for header only

    UINT32 SourceAddress;           // 4 bytes � Source IPv4 address
    UINT32 DestinationAddress;      // 4 bytes � Destination IPv4 address

    // Options may follow if HeaderLength > 5
} IPv4Header, * PIPv4Header;



/*
    IPv6 Header Structure � Based on RFC 8200

    IPv6 header is fixed at 40 bytes, followed by extension headers if any.

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   Version              4-bit Internet Protocol version number = 6.
   Traffic Class        8-bit Traffic Class field
   Flow Label           20-bit flow label
   Payload Length       16-bit unsigned integer.Length of the IPv6 payload, i.e., the rest of the packet  following this IPv6 header
   Next Header          8-bit selector.  Identifies the type of header immediately following the IPv6 header
   Hop Limit            8-bit unsigned integer.  Decremented by 1 by each node that forwards the packet.
   Source Address       128-bit address of the originator of the packet.
   Destination Address  128-bit address of the intended recipient of the packet
*/
typedef struct _IPv6Header {
    UINT32 Version : 4;  // 4 bits  � IP version, should be 6
    UINT32 TrafficClass : 8;  // 8 bits  � DSCP + ECN
    UINT32 FlowLabel : 20; // 20 bits � Identifies flow of packets

    UINT16 PayloadLength;         // 2 bytes � Length of payload following the header
    UINT8  NextHeader;            // 1 byte  � Type of next header (e.g., TCP/UDP/ICMPv6)
    UINT8  HopLimit;              // 1 byte  � Same as TTL in IPv4

    UINT8  SourceAddress[16];     // 16 bytes � Source IPv6 address
    UINT8  DestinationAddress[16];// 16 bytes � Destination IPv6 address
} IPv6Header, * PIPv6Header;



/*
    TCP Header � RFC 793

    Used for connection-oriented communication like HTTP, SMB, etc.

        0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Source Port:  16 bits
   Destination Port:  16 bits
   Sequence Number:  32 bits
   Acknowledgment Number:  32 bits
   Data Offset:  4 bits
   Reserved:  6 bits
   Control Bits:  6 bits
   Window:  16 bits
   Checksum:  16 bits


*/
typedef struct _TCPHeader {
    UINT16 SourcePort;         // 2 bytes � Source port
    UINT16 DestinationPort;    // 2 bytes � Destination port

    UINT32 SequenceNumber;     // 4 bytes � Position in byte stream
    UINT32 AcknowledgmentNumber; // 4 bytes � Acknowledgment for received data

    UINT8  DataOffset : 4; // 4 bits � Header size in 32-bit words
    UINT8  Reserved : 4; // 4 bits � Reserved for future use

    UINT8  Flags;                // 1 byte � Control flags (SYN, ACK, FIN, etc.)
    UINT16 WindowSize;          // 2 bytes � Flow control window
    UINT16 Checksum;            // 2 bytes � Header + data checksum
    UINT16 UrgentPointer;       // 2 bytes � Urgent data offset (if URG flag is set)

    // TCP options follow if DataOffset > 5
} TCPHeader, * PTCPHeader;

/*
    UDP Header � RFC 768

    Stateless transport, commonly used by DNS, SNMP, DHCP, etc.


                  0      7 8     15 16    23 24    31
                 +--------+--------+--------+--------+
                 |     Source      |   Destination   |
                 |      Port       |      Port       |
                 +--------+--------+--------+--------+
                 |                 |                 |
                 |     Length      |    Checksum     |
                 +--------+--------+--------+--------+
                 |                                   |
                 |          data octets ...          |
                 +-----------------------------------+


*/
typedef struct _UDPHeader {
    UINT16 SourcePort;       // 2 bytes � Source port
    UINT16 DestinationPort;  // 2 bytes � Destination port
    UINT16 Length;           // 2 bytes � Length of UDP header + payload
    UINT16 Checksum;         // 2 bytes � Optional, used for error detection
} UDPHeader, * PUDPHeader;



/*
    ICMP Header (Echo Request/Reply) � RFC 792

    Used for diagnostic and control (e.g., ping).

        0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+





*/
typedef struct _ICMPHeader {
    UINT8  Type;             // 1 byte � ICMP message type (e.g., 8 = Echo Request)
    UINT8  Code;             // 1 byte � Subtype for the Type
    UINT16 Checksum;         // 2 bytes � Header + data checksum

    UINT16 Identifier;       // 2 bytes � Echo identifier (usually process ID)
    UINT16 SequenceNumber;   // 2 bytes � Sequence number for ping matching
} ICMPHeader, * PICMPHeader;

#pragma pack(pop)


// Known Protocol Numbers (used in IPv4.Protocol or IPv6.NextHeader)
#define IPPROTO_ICMP     1
#define IPPROTO_TCP      6
#define IPPROTO_UDP      17
#define IPPROTO_ICMPV6   58

// Parsing Entry Points
BOOLEAN ParseIPv4Packet(_In_reads_bytes_(Length) PUCHAR Buffer, _In_ SIZE_T Length);
BOOLEAN ParseIPv6Packet(_In_reads_bytes_(Length) PUCHAR Buffer, _In_ SIZE_T Length);