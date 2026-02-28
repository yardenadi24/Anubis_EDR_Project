#pragma once
#include "service_interface.h"
#include "Logger.h"
#include "filesystem_utils.h"
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/prettywriter.h>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include "commons.h"
#include <functional>

// Callback type for post-save notifications
typedef std::function<void(const SecurityEvent&)> EventSavedCallback;


class EventPersistenceService : public IService {
private:
    const std::string m_name = "EventPersistence";
    ServiceState m_state;
    ServiceManager* m_serviceManager;
    Logger& m_logger;
    std::map<std::string, std::string> m_config;
    std::mutex m_configMutex;

    // Event queue and processing thread
    std::queue<SecurityEvent> m_eventQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCondition;
    std::thread m_saveThread;
    std::atomic<bool> m_isRunning;

    // Configuration
    std::string m_eventDirectory;

    EventSavedCallback m_onEventSaved;
    std::mutex m_callbackMutex;
public:
    EventPersistenceService();
    ~EventPersistenceService();

    // IService interface implementation
    const std::string& GetName() const override { return m_name; }
    bool Initialize() override;
    bool Start() override;
    void Stop() override;
    bool Configure(const std::map<std::string, std::string>& config) override;
    ServiceState GetState() const override { return m_state; }
    void SetServiceManager(ServiceManager* manager) override { m_serviceManager = manager; }

    // Event persistence
    bool SaveEvent(const SecurityEvent& event);
    void SetOnEventSavedCallback(EventSavedCallback callback);

private:
    void SaveThreadProc();
    bool LoadConfiguration();
    bool SerializeEventToJson(const SecurityEvent& event, std::string& jsonStr);
    bool WriteEventToFile(const SecurityEvent& event, const std::string& jsonStr);
    std::string GenerateFilename(const SecurityEvent& event);
    std::string SeverityToString(SecurityEventSeverity severity);
};