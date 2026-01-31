#pragma once

#include "IService.h"
#include "Logger.h"
#include "SharedCommonsFs.h"
#include <Windows.h>
#include <fltuser.h>  // For minifilter communication
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <map>
#include "SecurityEvent.h"
#pragma comment(lib, "fltlib.lib")  // Link against filter manager library

class ServiceManager;

class FilesystemMonitorService : public IService
{
public:
    FilesystemMonitorService();
    ~FilesystemMonitorService() override;

    // IService interface
    bool Initialize() override;
    bool Start() override;
    void Stop() override;
    bool Configure(const std::map<std::string, std::string>& config) override;
    ServiceState GetState() const override { return m_state; }
    const std::string& GetName() const override { return m_name; }

    void SetServiceManager(ServiceManager* manager) { m_serviceManager = manager; }

private:
    // Communication
    HANDLE m_hPort;                          // Filter communication port handle

    // Threading
    std::thread m_pollingThread;
    std::atomic<bool> m_isRunning;

    // State
    ServiceState m_state;
    std::string m_name = "FileMonitor";
    ServiceManager* m_serviceManager;
    Logger& m_logger;

    // Configuration
    std::mutex m_configMutex;
    std::map<std::string, std::string> m_config;

    // Monitoring settings
    bool m_monitorExecutableFiles;
    bool m_monitorDocumentFiles;
    bool m_monitorSystemFiles;
    bool m_monitorSuspiciousPaths;

    // Methods
    void PollingThreadProc();
    void ProcessFileEvent(const FILE_SYSTEM_EVENT& fileEvent);
    bool LoadConfiguration();
    void LogFileEvent(const FILE_SYSTEM_EVENT& fileEvent);

    SecurityEventSeverity DetermineSeverity(const FILE_SYSTEM_EVENT& fileEvent);
    std::string GetOperationName(FILE_OPERATION_TYPE operation);
    std::string GetFlagsDescription(ULONG flags);
    std::string ToHexString(NTSTATUS status);
};