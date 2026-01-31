#include "FilesystemMonitorService.h"
#include "ServiceManager.h"
#include "EventPersistenceService.h"
#include "AntiMalwareService.h"
#include <sstream>
#include <iomanip>

FilesystemMonitorService::FilesystemMonitorService()
    : m_state(ServiceState::STOPPED),
    m_hPort(INVALID_HANDLE_VALUE),
    m_isRunning(false),
    m_serviceManager(nullptr),
    m_logger(Logger::GetInstance()),
    m_monitorExecutableFiles(true),
    m_monitorDocumentFiles(true),
    m_monitorSystemFiles(false),
    m_monitorSuspiciousPaths(true)
{
}

FilesystemMonitorService::~FilesystemMonitorService()
{
    Stop();
    if (m_hPort != INVALID_HANDLE_VALUE) {
        FilterClose(m_hPort);
    }
}

SecurityEventSeverity FilesystemMonitorService::DetermineSeverity(const FILE_SYSTEM_EVENT& fileEvent)
{
    // Critical severity for high-risk operations
    if (fileEvent.Flags & FILE_EVENT_FLAG_HIGH_RISK_OPERATION) {
        return SecurityEventSeverity::CRITICAL;
    }

    // High severity for suspicious or untrusted processes
    if (fileEvent.Flags & (FILE_EVENT_FLAG_SUSPICIOUS_PATH | FILE_EVENT_FLAG_PROCESS_UNTRUSTED)) {
        return SecurityEventSeverity::HIGH;
    }

    // High severity for sensitive file access
    if (fileEvent.Flags & FILE_EVENT_FLAG_SENSITIVE) {
        return SecurityEventSeverity::HIGH;
    }

    // Medium severity for executables, scripts, or system files
    if (fileEvent.Flags & (FILE_EVENT_FLAG_EXECUTABLE | FILE_EVENT_FLAG_SCRIPT | FILE_EVENT_FLAG_SYSTEM_FILE)) {
        return SecurityEventSeverity::MEDIUM;
    }

    // Low severity for documents
    if (fileEvent.Flags & FILE_EVENT_FLAG_DOCUMENT) {
        return SecurityEventSeverity::LOW;
    }

    // Default: INFO
    return SecurityEventSeverity::INFO;
}

std::string FilesystemMonitorService::ToHexString(NTSTATUS status)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(8) << static_cast<unsigned long>(status);
    return oss.str();
}

/*
* Initialize the file monitor service by connecting to the minifilter communication port
* and loading configuration settings.
* Returns true if initialization is successful, false otherwise.
*/
bool FilesystemMonitorService::Initialize()
{
    m_logger.Info(m_name, "Initializing file monitor service");

    // Connect to the minifilter communication port
    HRESULT hr = FilterConnectCommunicationPort(
        FILTER_PORT_NAME,
        0,                          // Options
        NULL,                       // Context
        0,                          // Context size
        NULL,                       // Security attributes
        &m_hPort                    // Port handle
    );

    if (FAILED(hr)) {
        m_logger.Error(m_name, "Failed to connect to filter port. HRESULT: 0x" +
            std::to_string(hr));
        m_state = ServiceState::FAILED;
        return false;
    }

    m_logger.Info(m_name, "Successfully connected to file monitor filter");

    // Load configuration
    if (!LoadConfiguration()) {
        m_logger.Warning(m_name, "Failed to load configuration, using defaults");
    }

    m_state = ServiceState::STOPPED;
    return true;
}

bool FilesystemMonitorService::Start()
{
    if (m_state == ServiceState::RUNNING) {
        m_logger.Warning(m_name, "Service already running");
        return true;
    }

    m_logger.Info(m_name, "Starting file monitor service");

    m_state = ServiceState::STARTING;
    m_isRunning = true;
    m_pollingThread = std::thread(&FilesystemMonitorService::PollingThreadProc, this);

    m_state = ServiceState::RUNNING;
    m_logger.Info(m_name, "File monitor service started");

    return true;
}

void FilesystemMonitorService::Stop()
{
    if (m_state != ServiceState::RUNNING) {
        return;
    }

    m_logger.Info(m_name, "Stopping file monitor service");

    m_state = ServiceState::STOPPING;
    m_isRunning = false;

    if (m_pollingThread.joinable()) {
        m_pollingThread.join();
    }

    m_state = ServiceState::STOPPED;
    m_logger.Info(m_name, "File monitor service stopped");
}

bool FilesystemMonitorService::Configure(const std::map<std::string, std::string>& config)
{
    std::lock_guard<std::mutex> lock(m_configMutex);
    m_logger.Info(m_name, "Configuring file monitor service");

    m_config = config;
    return LoadConfiguration();
}

bool FilesystemMonitorService::LoadConfiguration()
{
    // Load monitoring flags
    auto it = m_config.find("MonitorExecutableFiles");
    if (it != m_config.end()) {
        m_monitorExecutableFiles = (it->second == "true" || it->second == "1");
    }

    it = m_config.find("MonitorDocumentFiles");
    if (it != m_config.end()) {
        m_monitorDocumentFiles = (it->second == "true" || it->second == "1");
    }

    it = m_config.find("MonitorSystemFiles");
    if (it != m_config.end()) {
        m_monitorSystemFiles = (it->second == "true" || it->second == "1");
    }

    it = m_config.find("MonitorSuspiciousPaths");
    if (it != m_config.end()) {
        m_monitorSuspiciousPaths = (it->second == "true" || it->second == "1");
    }

    m_logger.Info(m_name, "Configuration loaded - Executables:" +
        std::to_string(m_monitorExecutableFiles) +
        " Documents:" + std::to_string(m_monitorDocumentFiles));

    return true;
}

void FilesystemMonitorService::PollingThreadProc()
{
    m_logger.Info(m_name, "Polling thread started");
    
    struct {
        FILTER_MESSAGE_HEADER MessageHeader;
        FILE_SYSTEM_EVENT Event;
    } message = { 0 };

    DWORD bytesReturned = 0;

    while (m_isRunning)
    {
        // Receive message from filter
        HRESULT hr = FilterGetMessage(
            m_hPort,
            &message.MessageHeader,
            sizeof(FILE_SYSTEM_EVENT),
            NULL  // Overlapped structure (NULL for synchronous)
        );

        if (SUCCEEDED(hr))
        {
            bytesReturned = sizeof(message);
            ProcessFileEvent(message.Event);
        }
        else if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
        {
            // No events available, sleep briefly
            Sleep(100);
        }
        else
        {
            DWORD error = HRESULT_CODE(hr);
            m_logger.Error(m_name, "Error receiving file events: 0x" +
                std::to_string(error));
            Sleep(1000);
        }
    }

    m_logger.Info(m_name, "Polling thread exited");
}

void FilesystemMonitorService::ProcessFileEvent(const FILE_SYSTEM_EVENT& fileEvent)
{
    // Log the event
    LogFileEvent(fileEvent);

    // Send to event persistence service if available
    if (m_serviceManager) {
        auto persistenceService = dynamic_cast<EventPersistenceService*>(
            m_serviceManager->GetService("EventPersistence").get());

        if (persistenceService) {
            // Convert to generic event and persist
            // Implementation depends on EventPersistenceService interface
        }
    }

    // Check if file needs to be scanned by anti-malware
    if (fileEvent.Operation == FILE_OP_CREATE ||
        fileEvent.Operation == FILE_OP_WRITE) {

        if (fileEvent.Flags & FILE_EVENT_FLAG_EXECUTABLE) {
            // Trigger anti-malware scan
            if (m_serviceManager) {
                auto antiMalwareService = dynamic_cast<AntiMalwareService*>(
                    m_serviceManager->GetService("AntiMalware").get());

                if (antiMalwareService) {
                    std::wstring wPath(fileEvent.FilePath);
                    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), -1, NULL, 0, NULL, NULL);
                    std::string path(sizeNeeded, 0);
                    WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), -1, &path[0], sizeNeeded, NULL, NULL);
                    path.resize(sizeNeeded - 1); // Remove null terminator
                    m_logger.Info(m_name, "Requesting scan for: " + path);

                    // Submit async scan request
                    antiMalwareService->ScanFile(path, nullptr, nullptr);
                }
            }
        }
    }
}

void FilesystemMonitorService::LogFileEvent(const FILE_SYSTEM_EVENT& fileEvent)
{
    std::wstring wPath(fileEvent.FilePath);
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), -1, NULL, 0, NULL, NULL);
    std::string path(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), -1, &path[0], sizeNeeded, NULL, NULL);
    path.resize(sizeNeeded - 1); // Remove null terminator
    std::string logMsg = "File " + GetOperationName(fileEvent.Operation) +
        ": " + path +
        " (PID: " + std::to_string(fileEvent.Header.ProcessId) +
        ", Flags: " + GetFlagsDescription(fileEvent.Flags) + ")";

    m_logger.Info(m_name, logMsg);
}

std::string FilesystemMonitorService::GetOperationName(FILE_OPERATION_TYPE operation)
{
    switch (operation) {
    case FILE_OP_CREATE: return "CREATE";
    case FILE_OP_WRITE: return "WRITE";
    case FILE_OP_READ: return "READ";
    case FILE_OP_DELETE: return "DELETE";
    case FILE_OP_RENAME: return "RENAME";
    case FILE_OP_SET_INFO: return "SET_INFO";
    case FILE_OP_SET_SECURITY: return "SET_SECURITY";
    default: return "UNKNOWN";
    }
}

std::string FilesystemMonitorService::GetFlagsDescription(ULONG  flags)
{
    std::string desc;
    if (flags & FILE_EVENT_FLAG_EXECUTABLE) desc += "EXE,";
    if (flags & FILE_EVENT_FLAG_SYSTEM_FILE) desc += "SYS,";
    if (flags & FILE_EVENT_FLAG_SCRIPT) desc += "SCRIPT,";
    if (flags & FILE_EVENT_FLAG_DOCUMENT) desc += "DOC,";
    if (flags & FILE_EVENT_FLAG_SUSPICIOUS_PATH) desc += "SUSP,";
    if (flags & FILE_EVENT_FLAG_HIGH_RISK_OPERATION) desc += "HIGH_RISK,";

    if (!desc.empty()) desc.pop_back(); // Remove trailing comma
    return desc.empty() ? "NONE" : desc;
}
