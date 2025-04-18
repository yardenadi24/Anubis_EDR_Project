// SecurityEventService.h
#pragma once
#include "../IService.h"
#include "../../commons/logger/Logger.h"
#include "..\..\events\security_event\SecurityEvent.h"
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <functional>

// Callback for event handling
typedef std::function<void(const SecurityEvent&)> EventCallback;

class SecurityEventService : public IService {
private:
    const std::string m_name = "SecurityEvent";
    ServiceState m_state;
    ServiceManager* m_serviceManager;
    Logger& m_logger;
    std::map<std::string, std::string> m_config;
    std::mutex m_configMutex;

    // Event alert queue and processing
    std::queue<SecurityEvent> m_alertQueue;
    std::mutex m_alertQueueMutex;
    std::condition_variable m_alertCondition;
    std::thread m_alertThread;
    std::atomic<bool> m_isRunning;

    // Configuration
    bool m_showAlerts;

    // Event ID counter
    std::atomic<unsigned long> m_eventIdCounter;

    // Registered callbacks for event notifications
    std::vector<EventCallback> m_eventCallbacks;
    std::mutex m_callbackMutex;

public:
    SecurityEventService();
    ~SecurityEventService();

    // IService interface implementation
    const std::string& GetName() const override { return m_name; }
    bool Initialize() override;
    bool Start() override;
    void Stop() override;
    bool Configure(const std::map<std::string, std::string>& config) override;
    ServiceState GetState() const override { return m_state; }
    void SetServiceManager(ServiceManager* manager) override { m_serviceManager = manager; }

    // Event creation and management
    std::string CreateEvent(
        const std::string& source,
        const std::string& type,
        const std::string& description,
        const std::string& details,
        const std::string& filePath,
        SecurityEventSeverity severity,
        const std::map<std::string, std::string>& metadata = {},
        bool shouldAlert = false
    );

    // Register a callback for event notifications
    void RegisterEventCallback(EventCallback callback);

private:
    bool LoadConfiguration();
    void AlertThreadProc();
    std::string GenerateEventId();
    std::string ExtractFileName(const std::string& filePath);
};