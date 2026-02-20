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
#include "logger.h"
#include "configuration_manager.h"
#include "commons.h"


class FilesystemMonitorService : public IService
{
private:
    const std::string m_name = "FilesystemMonitor";
    ServiceState m_state;
    HANDLE m_hPort;                         // Communication port handle to the minifilter
    std::thread m_pollingThread;
    std::atomic<bool> m_isRunning;
    std::map<std::string, std::string> m_config;
    std::mutex m_configMutex;
    ServiceManager* m_serviceManager;
    Logger& m_logger;

    // Monitored operations configuration
    bool m_monitorCreate;
    bool m_monitorWrite;
    bool m_monitorRename;
    bool m_monitorDelete;
    bool m_monitorSetInfo;

    // Scanning configuration
    bool m_scanOnCreate;                    // Scan files on IRP_MJ_CREATE
    bool m_scanOnWrite;                     // Scan files after write completion
    bool m_enableBlocking;

    // Paths to monitor / exclude
    std::vector<std::wstring> m_excludedPaths;
    std::vector<std::wstring> m_excludedExtensions;
    std::vector<std::wstring> m_protectedPaths;

    // Default verdict when scan times out or fails
    bool m_defaultVerdict;

public:
    FilesystemMonitorService();
    ~FilesystemMonitorService();

    // IService interface implementation
    const std::string& GetName() const override { return m_name; }
    bool Initialize() override;
    bool Start() override;
    void Stop() override;
    bool Configure(const std::map<std::string, std::string>& config) override;
    ServiceState GetState() const override { return m_state; }
    void SetServiceManager(ServiceManager* manager) override { m_serviceManager = manager; }

private:
    void PollingThreadProc();
    bool AnalyzeFileEvent(const AGENT_FS_EVENT& fsEvent);
    bool ShouldMonitorFile(const std::wstring& filePath);
    bool IsExcludedExtension(const std::wstring& filePath);
    bool LoadRules();
    bool LoadRulesUnsafe();
    std::string FileOperationToString(ULONG operation);
};