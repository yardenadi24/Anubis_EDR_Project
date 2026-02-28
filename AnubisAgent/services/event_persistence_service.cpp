#include "event_persistence_service.h"
#include "service_manager.h"
#include "commons.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

EventPersistenceService::EventPersistenceService()
    :m_state(ServiceState::STOPPED),
    m_serviceManager(nullptr),
    m_logger(Logger::GetInstance()),
    m_isRunning(false),
    m_eventDirectory("C:\\ProgramData\\Anubis\\Events\\SecurityEvents")
{
}

EventPersistenceService::~EventPersistenceService() 
{
    Stop();
}

bool EventPersistenceService::Initialize() 
{
    m_logger.Info(m_name, "Initializing event persistence service");

    // Load configuration
    if (!LoadConfiguration()) {
        m_logger.Warning(m_name, "Failed to load configuration, using defaults");
    }

    // Create event directory if it doesn't exist
    if (!CreateDirectoryPath(m_eventDirectory, m_name)) {
        m_logger.Warning(m_name, "Failed to create event directory: " + m_eventDirectory);
        return false;
    }

    m_state = ServiceState::STOPPED;
    return true;
}

bool EventPersistenceService::Start() {
    if (m_state == ServiceState::RUNNING) {
        m_logger.Warning(m_name, "Service already running");
        return true;
    }

    m_logger.Info(m_name, "Starting event persistence service");

    m_state = ServiceState::STARTING;
    m_saveThread = std::thread(&EventPersistenceService::SaveThreadProc, this);
    m_isRunning = true;

    m_state = ServiceState::RUNNING;
    m_logger.Info(m_name, "Event persistence service started");
    return true;
}

void EventPersistenceService::Stop()
{
    if (m_state != ServiceState::RUNNING) {
        return;
    }

    m_logger.Info(m_name, "Stopping event persistence service");

    m_state = ServiceState::STOPPING;
    m_isRunning = false;

    // Wake up the save thread
    m_queueCondition.notify_all();

    if (m_saveThread.joinable()) {
        m_saveThread.join();
    }

    m_state = ServiceState::STOPPED;
    m_logger.Info(m_name, "Event persistence service stopped");
}

bool EventPersistenceService::Configure(const std::map<std::string, std::string>& config) 
{
    std::lock_guard<std::mutex> lock(m_configMutex);

    m_logger.Info(m_name, "Configuring event persistence service");

    // Store configuration
    m_config = config;

    // Apply configuration
    return LoadConfiguration();
}

bool EventPersistenceService::LoadConfiguration()
{
    // Get event directory
    auto it = m_config.find("EventDirectory");
    if (it != m_config.end()) {
        m_eventDirectory = it->second;
    }

    m_logger.Info(m_name, "Configuration loaded: EventDirectory=" + m_eventDirectory);

    return true;
}

bool EventPersistenceService::SaveEvent(const SecurityEvent& event) 
{
    if (m_state != ServiceState::RUNNING) {
        m_logger.Warning(m_name, "Cannot save event - service not running");
        return false;
    }

    m_logger.Info(m_name, "Queueing security event: " + event.id);

    // Add to queue
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_eventQueue.push(event);
    }

    // Notify save thread
    m_queueCondition.notify_one();

    return true;
}

void EventPersistenceService::SetOnEventSavedCallback(EventSavedCallback callback)
{
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_onEventSaved = callback;
}

void EventPersistenceService::SaveThreadProc() 
{
    m_logger.Info(m_name, "Save thread started");

    while (m_isRunning) {
        SecurityEvent event;
        bool hasEvent = false;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            // Wait for event or stop signal
            m_queueCondition.wait(lock, [this]() {
                return !m_isRunning || !m_eventQueue.empty();
                });

            // Check for shutdown
            if (!m_isRunning && m_eventQueue.empty()) {
                break;
            }

            // Get the next event
            if (!m_eventQueue.empty()) {
                event = m_eventQueue.front();
                m_eventQueue.pop();
                hasEvent = true;
            }
        }

        // Process the event
        if (hasEvent) {
            std::string jsonStr;
            if (SerializeEventToJson(event, jsonStr)) {
                if (WriteEventToFile(event, jsonStr)) {
                    m_logger.Info(m_name, "Successfully saved event to file: " + event.id);
                    {
                        std::lock_guard<std::mutex> lock(m_callbackMutex);
                        if (m_onEventSaved) {
                            try {
                                m_onEventSaved(event);
                            }
                            catch (const std::exception& e) {
                                m_logger.Error(m_name, "On-save callback error: " + std::string(e.what()));
                            }
                        }
                    }
                }
                else {
                    m_logger.Error(m_name, "Failed to write event to file: " + event.id);
                }
            }
            else {
                m_logger.Error(m_name, "Failed to serialize event to JSON: " + event.id);
            }
        }
    }

    m_logger.Info(m_name, "Save thread exited");
}

bool EventPersistenceService::SerializeEventToJson(const SecurityEvent& event, std::string& jsonStr) 
{
    try {
        rapidjson::Document document;
        document.SetObject();

        // Use the document's allocator for creating values
        auto& allocator = document.GetAllocator();

        // Add properties to JSON
        document.AddMember("id", rapidjson::Value(event.id.c_str(), allocator), allocator);
        document.AddMember("source", rapidjson::Value(event.source.c_str(), allocator), allocator);
        document.AddMember("type", rapidjson::Value(event.type.c_str(), allocator), allocator);
        document.AddMember("description", rapidjson::Value(event.description.c_str(), allocator), allocator);
        document.AddMember("details", rapidjson::Value(event.details.c_str(), allocator), allocator);
        document.AddMember("filePath", rapidjson::Value(event.filePath.c_str(), allocator), allocator);
        document.AddMember("fileName", rapidjson::Value(event.fileName.c_str(), allocator), allocator);
        document.AddMember("publisher", rapidjson::Value(event.publisher.c_str(), allocator), allocator);
        document.AddMember("severity", rapidjson::Value(SeverityToString(event.severity).c_str(), allocator), allocator);
        document.AddMember("shouldAlert", event.shouldAlert, allocator);

        // Timestamp
        auto time_t_value = std::chrono::system_clock::to_time_t(event.timestamp);
        std::tm tm_value;
        localtime_s(&tm_value, &time_t_value);
        char timeBuffer[64];
        strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%dT%H:%M:%S", &tm_value);
        document.AddMember("timestamp", rapidjson::Value(timeBuffer, allocator), allocator);

        // Metadata
        rapidjson::Value metadataObj(rapidjson::kObjectType);
        for (const auto& pair : event.metadata) {
            metadataObj.AddMember(
                rapidjson::Value(pair.first.c_str(), allocator),
                rapidjson::Value(pair.second.c_str(), allocator),
                allocator
            );
        }
        document.AddMember("metadata", metadataObj, allocator);

        // Serialize to string
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        document.Accept(writer);

        jsonStr = buffer.GetString();
        return true;
    }
    catch (const std::exception& e) {
        m_logger.Error(m_name, "JSON serialization error: " + std::string(e.what()));
        return false;
    }
}

std::string EventPersistenceService::SeverityToString(SecurityEventSeverity severity) 
{
    switch (severity) {
    case SecurityEventSeverity::INFO:    return "INFO";
    case SecurityEventSeverity::LOW:     return "LOW";
    case SecurityEventSeverity::MEDIUM:  return "MEDIUM";
    case SecurityEventSeverity::HIGH:    return "HIGH";
    case SecurityEventSeverity::CRITICAL:return "CRITICAL";
    default:                             return "UNKNOWN";
    }
}

std::string EventPersistenceService::GenerateFilename(const SecurityEvent& event) 
{
    // Format: YYYY-MM-DD_HH-MM-SS_EventID_Type.json
    auto time_t_value = std::chrono::system_clock::to_time_t(event.timestamp);
    std::tm tm_value;
    localtime_s(&tm_value, &time_t_value);

    std::ostringstream filename;
    filename << std::put_time(&tm_value, "%Y-%m-%d_%H-%M-%S_");
    filename << event.id << "_" << event.type << ".json";

    return filename.str();
}

bool EventPersistenceService::WriteEventToFile(const SecurityEvent& event, const std::string& jsonStr) 
{
    try {
        // Create filename based on event ID and timestamp
        std::string filename = GenerateFilename(event);
        std::string fullPath = m_eventDirectory + "\\" + filename;

        // Open file for writing
        std::ofstream file(fullPath, std::ios::out | std::ios::binary);
        if (!file.is_open()) {
            m_logger.Error(m_name, "Failed to open file for writing: " + fullPath);
            return false;
        }

        // Write JSON content
        file.write(jsonStr.c_str(), jsonStr.length());

        // Check for write errors
        if (file.fail()) {
            m_logger.Error(m_name, "Error writing to file: " + fullPath);
            file.close();
            return false;
        }

        file.close();
        return true;
    }
    catch (const std::exception& e) {
        m_logger.Error(m_name, "File write error: " + std::string(e.what()));
        return false;
    }
}