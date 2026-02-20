#pragma once

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <filesystem>
#include <fstream>

#include "commons.h" // This contains the shared structures

#include "service_manager.h"
#include "configuration_manager.h"
#include "logger.h" 

// Configuration structure for the agent
struct AgentConfig {
    std::vector<std::wstring> blockedProcessNames;
    std::vector<std::wstring> blockedPaths;
    bool defaultVerdict; // true = allow, false = deny
};

class AnubisAgent
{
private:
    std::unique_ptr<ServiceManager> m_serviceManager;
    std::unique_ptr<ConfigurationManager> m_configManager;
    Logger& m_Logger;
    std::atomic<bool> m_isRunning;
    std::thread m_mainThread;
    std::mutex m_agentMutex;

public:
    AnubisAgent();
    ~AnubisAgent();

    bool Initialize(const std::string& configPath);
    bool Start();
    void Stop();
    bool ReloadConfiguration();

    ServiceManager* GetServiceManager() const { return m_serviceManager.get(); }
    ConfigurationManager* GetConfigManager() const { return m_configManager.get(); }
    Logger& GetLogger() const { return m_Logger; }

private:
    void MainThreadProc();
};
