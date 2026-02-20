#pragma once
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <set>
#include <string>

#include "service_interface.h"
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "logger.h"
#include "configuration_manager.h"
#include "commons.h"

class NetworkMonitorService : public IService
{
private:
    const std::string   m_name = "NetworkMonitor";
    ServiceState        m_state;
    HANDLE              m_hDevice;
    std::thread         m_pollingThread;
    std::atomic<bool>   m_isRunning;
    std::map<std::string, std::string> m_config;
    std::mutex          m_configMutex;
    ServiceManager* m_serviceManager;
    Logger& m_logger;

    // ---- Enforcement ----
    bool m_enableBlocking;      // false = observe-only (always permit)
    bool m_defaultVerdict;      // true = allow when no rule matches

    // ---- Rules ----
    std::set<USHORT>          m_blockedRemotePorts;   // block outbound to these ports
    std::set<USHORT>          m_blockedLocalPorts;    // block listening on these ports
    std::set<ULONG>           m_blockedRemoteIPs;     // IPv4 in host byte order
    std::vector<std::wstring> m_blockedProcessNames;  // substring match

public:
    NetworkMonitorService();
    ~NetworkMonitorService();

    const std::string& GetName()  const override { return m_name; }
    bool  Initialize()                   override;
    bool  Start()                        override;
    void  Stop()                         override;
    bool  Configure(const std::map<std::string, std::string>& config) override;
    ServiceState GetState() const        override { return m_state; }
    void SetServiceManager(ServiceManager* manager) override { m_serviceManager = manager; }

private:
    void PollingThreadProc();
    bool AnalyzeNetEvent(const AGENT_NET_EVENT& evt);
    bool LoadRules();
    bool LoadRulesUnsafe();

    static std::string EventTypeToString(NET_EVENT_TYPE type);
    static std::string ProtocolToString(NET_PROTOCOL proto);
    static std::string DirectionToString(NET_DIRECTION dir);
    static std::string IpToString(ULONG ipNetOrder);
};