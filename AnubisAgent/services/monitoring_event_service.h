#pragma once
#include "service_interface.h"
#include "Logger.h"
#include "filesystem_utils.h"
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <map>
#include <chrono>

// A generic monitoring event — just key/value pairs with a source and timestamp.
// Each monitor (process, filesystem, network) fills in whatever fields it has.
struct MonitoringEvent {
    std::string source;                                    // "ProcessMonitor", "FilesystemMonitor", "NetworkMonitor"
    std::string eventType;                                 // Short label: "ProcessCreate", "FileDelete", "ConnectRequest", etc.
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> fields;             // Arbitrary key-value data
};

class MonitoringEventService : public IService {
private:
    const std::string m_name = "MonitoringEvents";
    ServiceState m_state;
    ServiceManager* m_serviceManager;
    Logger& m_logger;
    std::map<std::string, std::string> m_config;
    std::mutex m_configMutex;

    // Event queue and processing thread
    std::queue<MonitoringEvent> m_eventQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCondition;
    std::thread m_writeThread;
    std::atomic<bool> m_isRunning;

    // Configuration
    std::string m_eventDirectory;

    // ---- Cyclic file buffer ----
    static const size_t MAX_FILE_SIZE = 50 * 1024 * 1024;  // 50 MB per file
    static const int    MAX_FILE_COUNT = 10;

    int    m_currentFileIndex;
    size_t m_currentFileSize;
    std::mutex m_fileMutex;

public:
    MonitoringEventService();
    ~MonitoringEventService();

    // IService interface
    const std::string& GetName() const override { return m_name; }
    bool  Initialize() override;
    bool  Start() override;
    void  Stop() override;
    bool  Configure(const std::map<std::string, std::string>& config) override;
    ServiceState GetState() const override { return m_state; }
    void  SetServiceManager(ServiceManager* manager) override { m_serviceManager = manager; }

    // ---- Public API for monitors ----
    // Thread-safe, non-blocking (queues internally).
    void RecordEvent(const std::string& source,
        const std::string& eventType,
        const std::map<std::string, std::string>& fields);

private:
    void WriteThreadProc();
    bool LoadConfiguration();

    // Cyclic file helpers
    std::string GetFilePath(int index) const;
    bool  AppendEventToFile(const std::string& eventJson);
    void  DetermineCurrentFile();
    size_t GetFileSize(const std::string& path) const;
    std::string SerializeEvent(const MonitoringEvent& evt);
};