#include "security_event_service.h"
#include "service_manager.h"
#include "event_persistence_service.h"
#include "security_alert.h"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <filesystem>

SecurityEventService::SecurityEventService()
    :m_state(ServiceState::STOPPED),
    m_serviceManager(nullptr),
    m_logger(Logger::GetInstance()),
    m_isRunning(false),
    m_showAlerts(true),
    m_eventIdCounter(0)
{
}

SecurityEventService::~SecurityEventService()
{
    Stop();
}

bool SecurityEventService::Initialize() 
{

    m_logger.Info(m_name, "Initializing security event service");

    if (!LoadConfiguration()) {
        m_logger.Warning(m_name, "Failed to load configuration, using defaults");
    }

    m_state = ServiceState::STOPPED;
    return true;
}

bool SecurityEventService::Start() 
{
    if (m_state == ServiceState::RUNNING) {
        m_logger.Warning(m_name, "Service already running");
        return true;
    }

    m_logger.Info(m_name, "Starting security event service");

    m_state = ServiceState::STARTING;
    m_isRunning = true;

    //// Start alert thread if alerts are enabled
    //if (m_showAlerts) {
    //    m_alertThread = std::thread(&SecurityEventService::AlertThreadProc, this);
    //}

    m_state = ServiceState::RUNNING;
    m_logger.Info(m_name, "Security event service started");
    return true;
}

void SecurityEventService::Stop() 
{
    if (m_state != ServiceState::RUNNING) {
        return;
    }

    m_logger.Info(m_name, "Stopping security event service");

    m_state = ServiceState::STOPPING;
    m_isRunning = false;

    // Wake up alert thread
    m_alertCondition.notify_all();

    if (m_alertThread.joinable()) {
        m_alertThread.join();
    }

    SecurityAlertWindow::Shutdown();

    m_state = ServiceState::STOPPED;
    m_logger.Info(m_name, "Security event service stopped");
}

bool SecurityEventService::Configure(const std::map<std::string, std::string>& config) 
{
    std::lock_guard<std::mutex> lock(m_configMutex);

    m_logger.Info(m_name, "Configuring security event service");

    // Store configuration
    m_config = config;

    // Apply configuration
    return LoadConfiguration();
}

std::string SecurityEventService::CreateEvent(
    const std::string& source,
    const std::string& type,
    const std::string& description,
    const std::string& details,
    const std::string& filePath,
    SecurityEventSeverity severity,
    const std::map<std::string, std::string>& metadata,
    bool shouldAlert) 
{
    if (m_state != ServiceState::RUNNING) {
        m_logger.Warning(m_name, "Cannot create event - service not running");
        return "";
    }

    // Create security event
    SecurityEvent event;
    event.id = GenerateEventId();
    event.source = source;
    event.type = type;
    event.description = description;
    event.details = details;
    event.filePath = filePath;
    event.fileName = ExtractFileName(filePath);
    event.publisher = "Unknown";  // This could be determined from file metadata in a real implementation
    event.severity = severity;
    event.timestamp = std::chrono::system_clock::now();
    event.metadata = metadata;
    event.shouldAlert = shouldAlert;

    m_logger.Info(m_name, "Created security event: " + event.id + ", Type: " + type + ", Source: " + source);

    // Save event using EventPersistenceService
    if (m_serviceManager) {
        auto eventPersistenceService = std::dynamic_pointer_cast<EventPersistenceService>(
            m_serviceManager->GetService("EventPersistence"));

        if (eventPersistenceService) {
            if (eventPersistenceService->SaveEvent(event)) {
                m_logger.Info(m_name, "Event sent to persistence service: " + event.id);
            }
            else {
                m_logger.Warning(m_name, "Failed to send event to persistence service: " + event.id);
            }
        }
        else {
            m_logger.Warning(m_name, "EventPersistence service not available");
        }
    }

    // Queue alert if needed (direct alert from detection path)
    if (shouldAlert && m_showAlerts) {
        QueueAlert(event);
    }

    // Notify registered callbacks
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        for (const auto& callback : m_eventCallbacks) {
            try {
                callback(event);
            }
            catch (const std::exception& e) {
                m_logger.Error(m_name, "Event callback exception: " + std::string(e.what()));
            }
        }
    }

    return event.id;
}

void SecurityEventService::QueueAlert(const SecurityEvent& event)
{
    if (!m_showAlerts || !m_isRunning) return;

    {
        std::lock_guard<std::mutex> lock(m_alertQueueMutex);
        m_alertQueue.push(event);
    }
    m_alertCondition.notify_one();
    m_logger.Info(m_name, "Event queued for alert: " + event.id);
}

void SecurityEventService::AlertThreadProc()
{
    m_logger.Info(m_name, "Alert thread started");

    while (m_isRunning) 
    {
        SecurityEvent event;
        bool hasEvent = false;

        {
            std::unique_lock<std::mutex> lock(m_alertQueueMutex);

            // Wait for an alert event or stop signal
            m_alertCondition.wait(lock, [this]() {
                return !m_isRunning || !m_alertQueue.empty();
                });

            // Check for shutdown
            if (!m_isRunning && m_alertQueue.empty()) {
                break;
            }

            // Dequeue next alert
            if (!m_alertQueue.empty()) {
                event = m_alertQueue.front();
                m_alertQueue.pop();
                hasEvent = true;
            }
        }

        if (hasEvent) {
            m_logger.Info(m_name, "Showing alert for event: " + event.id
                + " [Severity: " + std::to_string(static_cast<int>(event.severity)) + "]");

            // Show the Win32 alert window (non-blocking - spawns its own UI thread)
            SecurityAlertWindow::ShowAlert(event);

            // Small delay between alerts to avoid overwhelming the user
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    m_logger.Info(m_name, "Alert thread exited");
}

void SecurityEventService::RegisterEventCallback(EventCallback callback) 
{
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_eventCallbacks.push_back(callback);
}

bool SecurityEventService::LoadConfiguration() 
{
    // Check if alerts should be shown
    auto it = m_config.find("ShowAlerts");
    if (it != m_config.end()) {
        m_showAlerts = (it->second == "true" || it->second == "1" || it->second == "yes");
    }

    it = m_config.find("AlertTimeoutMs");
    if (it != m_config.end()) {
        try {
            UINT timeout = std::stoul(it->second);
            SecurityAlertWindow::SetAutoCloseTimeoutMs(timeout);
        }
        catch (...) {
            m_logger.Warning(m_name, "Invalid AlertTimeoutMs value, using default");
        }
    }

    it = m_config.find("MaxConcurrentAlerts");
    if (it != m_config.end()) {
        try {
            int maxAlerts = std::stoi(it->second);
            SecurityAlertWindow::SetMaxConcurrentAlerts(maxAlerts);
        }
        catch (...) {
            m_logger.Warning(m_name, "Invalid MaxConcurrentAlerts value, using default");
        }
    }

    m_logger.Info(m_name, "Configuration loaded: ShowAlerts=" + std::string(m_showAlerts ? "true" : "false"));

    return true;
}

std::string SecurityEventService::GenerateEventId() {
    // Format: AFX-NNNNNN (where N is a number)
    std::ostringstream id;
    id << "ANUBIS-" << std::setw(6) << std::setfill('0') << m_eventIdCounter++;
    return id.str();
}


std::string SecurityEventService::ExtractFileName(const std::string& filePath) {
    try {
        // Use C++17 filesystem to extract filename
        return std::filesystem::path(filePath).filename().string();
    }
    catch (...) {
        // Fallback to manual extraction if filesystem fails
        size_t lastSlash = filePath.find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            return filePath.substr(lastSlash + 1);
        }
        return filePath; // Return the whole path if no slash is found
    }
}
