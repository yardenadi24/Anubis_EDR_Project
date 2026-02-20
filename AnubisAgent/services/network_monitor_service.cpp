#include <winsock2.h>
#include <ws2tcpip.h>

#include "network_monitor_service.h"
#include "monitoring_event_service.h"
#include "service_manager.h"
#include "security_event_service.h"
#include "strings_utils.h"
#include "commons.h"

#include <sstream>

#pragma comment(lib, "ws2_32.lib")

NetworkMonitorService::NetworkMonitorService()
    : m_state(ServiceState::STOPPED)
    , m_hDevice(INVALID_HANDLE_VALUE)
    , m_isRunning(false)
    , m_serviceManager(nullptr)
    , m_logger(Logger::GetInstance())
    , m_enableBlocking(false)
    , m_defaultVerdict(true)
{
}

NetworkMonitorService::~NetworkMonitorService()
{
    Stop();
    if (m_hDevice != INVALID_HANDLE_VALUE)
        CloseHandle(m_hDevice);
}

bool NetworkMonitorService::Initialize()
{
    m_logger.Info(m_name, "Initializing network monitor service");

    m_hDevice = CreateFileW(
        L"\\\\.\\AnubisEdrDevice",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (m_hDevice == INVALID_HANDLE_VALUE)
    {
        m_logger.Error(m_name,
            "Failed to open device. Error: " + std::to_string(GetLastError()));
        m_state = ServiceState::FAILED;
        return false;
    }

    m_logger.Info(m_name, "Successfully connected to the driver");

    if (!LoadRules())
        m_logger.Warning(m_name, "Failed to load rules, using default configuration");

    m_state = ServiceState::STOPPED;
    return true;
}

bool NetworkMonitorService::Start()
{
    if (m_state == ServiceState::RUNNING)
    {
        m_logger.Warning(m_name, "Service already running");
        return true;
    }

    m_logger.Info(m_name, "Starting network monitor service");
    m_state = ServiceState::STARTING;
    m_isRunning = true;

    m_pollingThread = std::thread(&NetworkMonitorService::PollingThreadProc, this);

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hDevice,
        IOCTL_START_NET_MONITORING,
        NULL, 0, NULL, 0,
        &bytesReturned, NULL);

    m_state = ServiceState::RUNNING;

    if (!success)
    {
        m_logger.Error(m_name,
            "Error starting kernel monitoring: " + std::to_string(GetLastError()));
        Stop();
        return false;
    }

    m_logger.Info(m_name, "Network monitor service started");
    return true;
}

void NetworkMonitorService::Stop()
{
    if (m_state != ServiceState::RUNNING)
        return;

    m_logger.Info(m_name, "Stopping network monitor service");
    m_state = ServiceState::STOPPING;
    m_isRunning = false;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hDevice,
        IOCTL_STOP_NET_MONITORING,
        NULL, 0, NULL, 0,
        &bytesReturned, NULL);

    if (!success)
        m_logger.Error(m_name,
            "Error stopping kernel monitoring: " + std::to_string(GetLastError()));

    if (m_pollingThread.joinable())
        m_pollingThread.join();

    m_state = ServiceState::STOPPED;
    m_logger.Info(m_name, "Network monitor service stopped");
}

bool NetworkMonitorService::Configure(const std::map<std::string, std::string>& config)
{
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_config = config;
    return LoadRulesUnsafe();
}

void NetworkMonitorService::PollingThreadProc()
{
    m_logger.Info(m_name, "Polling thread started");

    while (m_isRunning)
    {
        AGENT_NET_EVENT netEvent = { 0 };
        DWORD bytesReturned = 0;

        BOOL success = DeviceIoControl(
            m_hDevice,
            IOCTL_GET_NET_EVENT,
            NULL, 0,
            &netEvent, sizeof(AGENT_NET_EVENT),
            &bytesReturned, NULL);

        if (!success)
        {
            DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS)
            {
                Sleep(100);
                continue;
            }
            m_logger.Error(m_name,
                "Error polling for network events: " + std::to_string(error));
            Sleep(1000);
            continue;
        }

        if (bytesReturned == 0)
        {
            Sleep(100);
            continue;
        }
        
        std::wstring procNameW(netEvent.ProcessName);
        std::string  procNameA = WideToAnsi(procNameW, m_name);

        std::ostringstream desc;
        desc << EventTypeToString(netEvent.EventType)
            << " | " << ProtocolToString(netEvent.Protocol)
            << " | " << DirectionToString(netEvent.Direction)
            << " | " << procNameA
            << " (PID:" << netEvent.ProcessId << ")"
            << " | " << IpToString(netEvent.LocalAddress)
            << ":" << netEvent.LocalPort
            << " -> " << IpToString(netEvent.RemoteAddress)
            << ":" << netEvent.RemotePort;

        m_logger.Info(m_name, "Network event: " + desc.str());

        if (m_serviceManager) {
            auto monSvc = std::dynamic_pointer_cast<MonitoringEventService>(
                m_serviceManager->GetService("MonitoringEvents"));
            if (monSvc) {
                std::map<std::string, std::string> fields;
                fields["ProcessId"] = std::to_string(netEvent.ProcessId);
                fields["ProcessName"] = procNameA;
                fields["Protocol"] = ProtocolToString(netEvent.Protocol);
                fields["Direction"] = DirectionToString(netEvent.Direction);
                fields["LocalAddress"] = IpToString(netEvent.LocalAddress);
                fields["LocalPort"] = std::to_string(netEvent.LocalPort);
                fields["RemoteAddress"] = IpToString(netEvent.RemoteAddress);
                fields["RemotePort"] = std::to_string(netEvent.RemotePort);
                monSvc->RecordEvent(m_name, EventTypeToString(netEvent.EventType), fields);
            }
        }

        if (!m_enableBlocking)
        {
            continue;  // Don't analyze, don't post verdict, don't create security events
        }

        bool verdict = AnalyzeNetEvent(netEvent);

        m_logger.Info(m_name,
            "Verdict posted: " + std::string(verdict ? "ALLOW" : "BLOCK") +
            " for " + procNameA);
       
        if (!verdict)
        {
			// Network blocked - raise a security event
            auto secSvc = std::dynamic_pointer_cast<SecurityEventService>(
                m_serviceManager->GetService("SecurityEvent"));
            std::map<std::string, std::string> metadata;
            metadata["ProcessId"] = std::to_string(netEvent.ProcessId);
            metadata["ProcessName"] = procNameA;
            metadata["EventType"] = EventTypeToString(netEvent.EventType);
            metadata["Protocol"] = ProtocolToString(netEvent.Protocol);
            metadata["Direction"] = DirectionToString(netEvent.Direction);
            metadata["LocalIP"] = IpToString(netEvent.LocalAddress);
            metadata["LocalPort"] = std::to_string(netEvent.LocalPort);
            metadata["RemoteIP"] = IpToString(netEvent.RemoteAddress);
            metadata["RemotePort"] = std::to_string(netEvent.RemotePort); 
            metadata["Verdict"] = verdict ? "ALLOW" : "DETECTED";
            SecurityEventSeverity severity = SecurityEventSeverity::HIGH;
            bool shouldAlert = true;
            secSvc->CreateEvent(
                m_name,
                EventTypeToString(netEvent.EventType),
                desc.str() + " | Verdict: " + (verdict ? "ALLOW" : "DETECTED"),
                "",
                "",
                severity,
                metadata,
                shouldAlert);
        }
    }

    m_logger.Info(m_name, "Polling thread exited");
}

bool NetworkMonitorService::AnalyzeNetEvent(const AGENT_NET_EVENT& evt)
{
    // Observe-only mode — never block, just log
    if (!m_enableBlocking)
        return true;

    std::lock_guard<std::mutex> lock(m_configMutex);

    // Blocked remote ports — applies to outbound connect events
    if (evt.EventType == NET_EVENT_CONNECT || evt.EventType == NET_EVENT_ESTABLISHED)
    {
        if (m_blockedRemotePorts.count(evt.RemotePort))
        {
            m_logger.Warning(m_name,
                "BLOCK: remote port " + std::to_string(evt.RemotePort));
            return false;
        }
    }

    // 3. Blocked local ports — applies to bind / inbound accept
    if (evt.EventType == NET_EVENT_BIND || evt.EventType == NET_EVENT_ACCEPT)
    {
        if (m_blockedLocalPorts.count(evt.LocalPort))
        {
            m_logger.Warning(m_name,
                "BLOCK: local port " + std::to_string(evt.LocalPort) +
                " (rogue listener rule)");
            return false;
        }
    }

    // 4. Blocked remote IPs
    // RemoteAddress is in network byte order; we store rules in host byte order
    if (m_blockedRemoteIPs.count(ntohl(evt.RemoteAddress)))
    {
        m_logger.Warning(m_name,
            "BLOCK: remote IP " + IpToString(evt.RemoteAddress));
        return false;
    }

    return m_defaultVerdict;
}

bool NetworkMonitorService::LoadRules()
{
    std::lock_guard<std::mutex> lock(m_configMutex);
    return LoadRulesUnsafe();
}

bool NetworkMonitorService::LoadRulesUnsafe()
{
    m_blockedRemotePorts.clear();
    m_blockedLocalPorts.clear();
    m_blockedRemoteIPs.clear();
    m_blockedProcessNames.clear();

    // Helper: read a boolean config key
    auto getBool = [&](const std::string& key, bool def) -> bool {
        auto it = m_config.find(key);
        if (it == m_config.end()) return def;
        return (it->second == "true");
        };

    m_enableBlocking = getBool("EnableBlocking", false);
    m_defaultVerdict = getBool("DefaultVerdict", true);

    // Helper: parse comma-separated port list
    auto loadPorts = [&](const std::string& key, std::set<USHORT>& out) {
        auto it = m_config.find(key);
        if (it == m_config.end()) return;
        std::istringstream iss(it->second);
        std::string tok;
        while (std::getline(iss, tok, ','))
        {
            tok.erase(0, tok.find_first_not_of(" \t"));
            tok.erase(tok.find_last_not_of(" \t") + 1);
            if (!tok.empty())
                out.insert(static_cast<USHORT>(std::stoul(tok)));
        }
        };

    loadPorts("BlockedRemotePorts", m_blockedRemotePorts);
    loadPorts("BlockedLocalPorts", m_blockedLocalPorts);

    // Blocked remote IPs — dotted-decimal, stored in host byte order
    {
        auto it = m_config.find("BlockedRemoteIPs");
        if (it != m_config.end())
        {
            std::istringstream iss(it->second);
            std::string tok;
            while (std::getline(iss, tok, ','))
            {
                tok.erase(0, tok.find_first_not_of(" \t"));
                tok.erase(tok.find_last_not_of(" \t") + 1);
                if (!tok.empty())
                {
                    struct in_addr addr = {};
                    if (inet_pton(AF_INET, tok.c_str(), &addr) == 1)
                        m_blockedRemoteIPs.insert(ntohl(addr.s_addr)); // store as host order
                }
            }
        }
    }

    m_logger.Info(m_name,
        "Rules loaded:"
        " BlockedRemotePorts=" + std::to_string(m_blockedRemotePorts.size()) +
        " BlockedLocalPorts=" + std::to_string(m_blockedLocalPorts.size()) +
        " BlockedIPs=" + std::to_string(m_blockedRemoteIPs.size()) +
        " Blocking=" + (m_enableBlocking ? "ON" : "OFF") +
        " Default=" + (m_defaultVerdict ? "ALLOW" : "BLOCK"));

    return true;
}

std::string NetworkMonitorService::EventTypeToString(NET_EVENT_TYPE type)
{
    switch (type)
    {
    case NET_EVENT_BIND:        return "PortListening";
    case NET_EVENT_CONNECT:     return "ConnectRequest";
    case NET_EVENT_ACCEPT:      return "ConnectionAccepted";
    case NET_EVENT_ESTABLISHED: return "ConnectionEstablished";
    case NET_EVENT_DISCONNECT:  return "Disconnected";
    default:                    return "Unknown";
    }
}

std::string NetworkMonitorService::ProtocolToString(NET_PROTOCOL proto)
{
    switch (proto)
    {
    case NET_PROTO_TCP: return "TCP";
    case NET_PROTO_UDP: return "UDP";
    default:            return "Other";
    }
}

std::string NetworkMonitorService::DirectionToString(NET_DIRECTION dir)
{
    return (dir == NET_DIR_OUTBOUND) ? "Outbound" : "Inbound";
}

std::string NetworkMonitorService::IpToString(ULONG ipHostOrder)
{
    struct in_addr addr;
    addr.s_addr = htonl(ipHostOrder);  // WFP gives host order; inet_ntop expects network order
    char buf[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}