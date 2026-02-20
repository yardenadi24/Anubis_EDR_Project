#include "monitoring_event_service.h"
#include "service_manager.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>

// We use rapidjson for fast serialization
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

MonitoringEventService::MonitoringEventService()
    : m_state(ServiceState::STOPPED),
    m_serviceManager(nullptr),
    m_logger(Logger::GetInstance()),
    m_isRunning(false),
    m_eventDirectory("C:\\ProgramData\\Anubis\\Events\\MonitoringEvents"),
    m_currentFileIndex(0),
    m_currentFileSize(0)
{
}

MonitoringEventService::~MonitoringEventService()
{
    Stop();
}

bool MonitoringEventService::Initialize()
{
    m_logger.Info(m_name, "Initializing monitoring event service");

    if (!LoadConfiguration()) {
        m_logger.Warning(m_name, "Failed to load configuration, using defaults");
    }

    // Create output directory
    if (!CreateDirectoryPath(m_eventDirectory, m_name)) {
        m_logger.Error(m_name, "Failed to create event directory: " + m_eventDirectory);
        return false;
    }

    // Find which file to resume writing to
    DetermineCurrentFile();

    m_state = ServiceState::STOPPED;
    return true;
}

bool MonitoringEventService::Start()
{
    if (m_state == ServiceState::RUNNING) {
        m_logger.Warning(m_name, "Service already running");
        return true;
    }

    m_logger.Info(m_name, "Starting monitoring event service");

    m_state = ServiceState::STARTING;
    m_isRunning = true;
    m_writeThread = std::thread(&MonitoringEventService::WriteThreadProc, this);

    m_state = ServiceState::RUNNING;
    m_logger.Info(m_name, "Monitoring event service started");
    return true;
}

void MonitoringEventService::Stop()
{
    if (m_state != ServiceState::RUNNING) {
        return;
    }

    m_logger.Info(m_name, "Stopping monitoring event service");
    m_state = ServiceState::STOPPING;
    m_isRunning = false;

    m_queueCondition.notify_all();

    if (m_writeThread.joinable()) {
        m_writeThread.join();
    }

    m_state = ServiceState::STOPPED;
    m_logger.Info(m_name, "Monitoring event service stopped");
}

bool MonitoringEventService::Configure(const std::map<std::string, std::string>& config)
{
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_config = config;
    return LoadConfiguration();
}

bool MonitoringEventService::LoadConfiguration()
{
    auto it = m_config.find("MonitoringEventDirectory");
    if (it != m_config.end()) {
        m_eventDirectory = it->second;
    }

    m_logger.Info(m_name, "Configuration loaded: EventDirectory=" + m_eventDirectory);
    return true;
}

void MonitoringEventService::RecordEvent(
    const std::string& source,
    const std::string& eventType,
    const std::map<std::string, std::string>& fields)
{
    if (m_state != ServiceState::RUNNING) {
        return;  // Silently drop — monitoring events are best-effort
    }

    MonitoringEvent evt;
    evt.source = source;
    evt.eventType = eventType;
    evt.timestamp = std::chrono::system_clock::now();
    evt.fields = fields;

    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_eventQueue.push(std::move(evt));
    }
    m_queueCondition.notify_one();
}

void MonitoringEventService::WriteThreadProc()
{
    m_logger.Info(m_name, "Write thread started");

    while (m_isRunning) {
        MonitoringEvent evt;
        bool hasEvent = false;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            m_queueCondition.wait(lock, [this]() {
                return !m_isRunning || !m_eventQueue.empty();
                });

            if (!m_isRunning && m_eventQueue.empty()) {
                break;
            }

            if (!m_eventQueue.empty()) {
                evt = std::move(m_eventQueue.front());
                m_eventQueue.pop();
                hasEvent = true;
            }
        }

        if (hasEvent) {
            std::string json = SerializeEvent(evt);
            if (!json.empty()) {
                AppendEventToFile(json);
            }
        }
    }

    // Drain remaining events before exit
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        while (!m_eventQueue.empty()) {
            MonitoringEvent evt = std::move(m_eventQueue.front());
            m_eventQueue.pop();

            std::string json = SerializeEvent(evt);
            if (!json.empty()) {
                AppendEventToFile(json);
            }
        }
    }

    m_logger.Info(m_name, "Write thread exited");
}

std::string MonitoringEventService::SerializeEvent(const MonitoringEvent& evt)
{
    try {
        rapidjson::Document doc;
        doc.SetObject();
        auto& alloc = doc.GetAllocator();

        doc.AddMember("source",
            rapidjson::Value(evt.source.c_str(), alloc), alloc);
        doc.AddMember("eventType",
            rapidjson::Value(evt.eventType.c_str(), alloc), alloc);

        // Timestamp -> ISO 8601
        auto tt = std::chrono::system_clock::to_time_t(evt.timestamp);
        std::tm tm_val;
        localtime_s(&tm_val, &tt);
        char timeBuf[64];
        std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%dT%H:%M:%S", &tm_val);
        doc.AddMember("timestamp",
            rapidjson::Value(timeBuf, alloc), alloc);

        // All fields as a flat object
        rapidjson::Value fieldsObj(rapidjson::kObjectType);
        for (const auto& kv : evt.fields) {
            fieldsObj.AddMember(
                rapidjson::Value(kv.first.c_str(), alloc),
                rapidjson::Value(kv.second.c_str(), alloc),
                alloc);
        }
        doc.AddMember("fields", fieldsObj, alloc);

        rapidjson::StringBuffer buf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
        doc.Accept(writer);

        return buf.GetString();
    }
    catch (const std::exception& e) {
        m_logger.Error(m_name, "Serialization error: " + std::string(e.what()));
        return "";
    }
}

std::string MonitoringEventService::GetFilePath(int index) const
{
    std::ostringstream oss;
    oss << m_eventDirectory << "\\monitoring_"
        << std::setw(2) << std::setfill('0') << index
        << ".json";
    return oss.str();
}

size_t MonitoringEventService::GetFileSize(const std::string& path) const
{
    try {
        if (std::filesystem::exists(path)) {
            return static_cast<size_t>(std::filesystem::file_size(path));
        }
    }
    catch (...) {}
    return 0;
}

void MonitoringEventService::DetermineCurrentFile()
{
    std::lock_guard<std::mutex> lock(m_fileMutex);

    int bestIndex = -1;
    std::filesystem::file_time_type bestTime = (std::filesystem::file_time_type::min)();

    for (int i = 0; i < MAX_FILE_COUNT; i++)
    {
        std::string path = GetFilePath(i);
        size_t size = GetFileSize(path);

        if (size == 0) {
            // Empty or non-existent — use if nothing better found
            if (bestIndex == -1) {
                bestIndex = i;
            }
            continue;
        }

        if (size < MAX_FILE_SIZE) {
            // Partially filled — prefer the most recently modified
            try {
                auto mtime = std::filesystem::last_write_time(path);
                if (mtime > bestTime) {
                    bestTime = mtime;
                    bestIndex = i;
                }
            }
            catch (...) {
                if (bestIndex == -1) bestIndex = i;
            }
        }
    }

    if (bestIndex == -1) {
        // All full — wrap to 0
        bestIndex = 0;
    }

    m_currentFileIndex = bestIndex;
    m_currentFileSize = GetFileSize(GetFilePath(m_currentFileIndex));

    m_logger.Info(m_name, "Resuming at file index " + std::to_string(m_currentFileIndex) +
        " (size: " + std::to_string(m_currentFileSize / 1024) + " KB)");
}

bool MonitoringEventService::AppendEventToFile(const std::string& eventJson)
{
    std::lock_guard<std::mutex> lock(m_fileMutex);

    // Rotate if current file is full
    if (m_currentFileSize >= MAX_FILE_SIZE) {
        m_currentFileIndex = (m_currentFileIndex + 1) % MAX_FILE_COUNT;
        m_currentFileSize = 0;
        m_logger.Info(m_name, "Rotating to file index " + std::to_string(m_currentFileIndex));
    }

    std::string filePath = GetFilePath(m_currentFileIndex);

    try {
        bool fileExists = std::filesystem::exists(filePath) && m_currentFileSize > 0;

        if (!fileExists || m_currentFileSize == 0) {
            // ---- New / empty file: start fresh JSON array ----
            std::ofstream ofs(filePath, std::ios::out | std::ios::binary | std::ios::trunc);
            if (!ofs.is_open()) {
                m_logger.Error(m_name, "Failed to create file: " + filePath);
                return false;
            }

            std::string content = "[\n  " + eventJson + "\n]\n";
            ofs.write(content.c_str(), content.size());
            if (ofs.fail()) {
                m_logger.Error(m_name, "Write failed: " + filePath);
                return false;
            }
            ofs.close();
            m_currentFileSize = content.size();
        }
        else {
            // ---- Existing file: append to JSON array ----
            std::fstream fs(filePath, std::ios::in | std::ios::out | std::ios::binary);
            if (!fs.is_open()) {
                m_logger.Error(m_name, "Failed to open for append: " + filePath);
                return false;
            }

            // Find the closing ']' near end of file
            fs.seekg(0, std::ios::end);
            std::streampos fileEnd = fs.tellg();

            if (fileEnd < 2) {
                // Too small / corrupt — rewrite
                fs.close();
                std::ofstream ofs(filePath, std::ios::out | std::ios::binary | std::ios::trunc);
                std::string content = "[\n  " + eventJson + "\n]\n";
                ofs.write(content.c_str(), content.size());
                ofs.close();
                m_currentFileSize = content.size();
                return true;
            }

            // Read last few bytes to locate ']'
            int seekBack = 4;
            if (static_cast<int>(fileEnd) < seekBack) seekBack = static_cast<int>(fileEnd);

            fs.seekg(-seekBack, std::ios::end);
            char tail[4] = { 0 };
            fs.read(tail, seekBack);

            int bracketOffset = -1;
            for (int i = seekBack - 1; i >= 0; i--) {
                if (tail[i] == ']') {
                    bracketOffset = i;
                    break;
                }
            }

            if (bracketOffset == -1) {
                // No ']' — corrupt, rewrite
                m_logger.Warning(m_name, "Corrupt file (no ']'), rewriting: " + filePath);
                fs.close();
                std::ofstream ofs(filePath, std::ios::out | std::ios::binary | std::ios::trunc);
                std::string content = "[\n  " + eventJson + "\n]\n";
                ofs.write(content.c_str(), content.size());
                ofs.close();
                m_currentFileSize = content.size();
                return true;
            }

            // Overwrite from ']' position
            std::streampos bracketPos = static_cast<std::streampos>(
                static_cast<std::streamoff>(fileEnd) - seekBack + bracketOffset);

            fs.seekp(bracketPos);
            std::string appendStr = ",\n  " + eventJson + "\n]\n";
            fs.write(appendStr.c_str(), appendStr.size());

            if (fs.fail()) {
                m_logger.Error(m_name, "Append failed: " + filePath);
                fs.close();
                return false;
            }

            fs.close();
            m_currentFileSize = static_cast<size_t>(bracketPos) + appendStr.size();
        }

        return true;
    }
    catch (const std::exception& e) {
        m_logger.Error(m_name, "Exception: " + std::string(e.what()));
        return false;
    }
}