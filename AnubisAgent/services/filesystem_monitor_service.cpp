#include "filesystem_monitor_service.h"
#include "service_manager.h"
#include "anti_malware_service.h"
#include "commons.h"
#include "strings_utils.h"
#include "monitoring_event_service.h"

FilesystemMonitorService::FilesystemMonitorService()
    :m_state(ServiceState::STOPPED),
    m_hPort(INVALID_HANDLE_VALUE),
    m_isRunning(false),
    m_serviceManager(nullptr),
    m_logger(Logger::GetInstance()),
    m_monitorCreate(true),
    m_monitorWrite(true),
    m_monitorRename(true),
    m_monitorDelete(true),
    m_monitorSetInfo(false),
    m_scanOnCreate(true),
    m_scanOnWrite(true),
    m_enableBlocking(true),
    m_defaultVerdict(true) // Allow by default
{
}

FilesystemMonitorService::~FilesystemMonitorService()
{
    Stop();
    if (m_hPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPort);
    }
}

bool FilesystemMonitorService::Initialize()
{
    m_logger.Info(m_name, "Initializing filesystem monitor service");

    // Open a handle to the minifilter communication port
    m_hPort = CreateFileW(
        L"\\\\.\\AnubisEdrDevice",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (m_hPort == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Failed to open minifilter communication port. Error: " + std::to_string(error));
        m_state = ServiceState::FAILED;
        return false;
    }

    m_logger.Info(m_name, "Successfully connected to the minifilter driver");

    // Load rules from configuration
    if (!LoadRules()) {
        m_logger.Warning(m_name, "Failed to load rules, using default configuration");
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

    m_logger.Info(m_name, "Starting filesystem monitor service");

    m_state = ServiceState::STARTING;
    
    
    // Tell the minifilter to start sending filesystem events
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hPort,
        IOCTL_START_FS_MONITORING,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    
    if (!success) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Error starting filesystem monitoring, stopping service: " + std::to_string(error));
        Stop();
        return false;
    }
    
    // Start the polling thread
    m_pollingThread = std::thread(&FilesystemMonitorService::PollingThreadProc, this);
    m_isRunning = true;
    m_state = ServiceState::RUNNING;


    m_logger.Info(m_name, "Filesystem monitor service started");
    return true;
}

void FilesystemMonitorService::Stop()
{
    if (m_state != ServiceState::RUNNING) {
        return;
    }

    m_logger.Info(m_name, "Stopping filesystem monitor service");

    m_state = ServiceState::STOPPING;
    m_isRunning = false;

    // Tell the minifilter to stop sending filesystem events
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hPort,
        IOCTL_STOP_FS_MONITORING,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!success) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Error stopping filesystem monitoring: " + std::to_string(error));
    }

    if (m_pollingThread.joinable()) {
        m_pollingThread.join();
    }

    m_state = ServiceState::STOPPED;
    m_logger.Info(m_name, "Filesystem monitor service stopped");
}

bool FilesystemMonitorService::Configure(const std::map<std::string, std::string>& config)
{
    std::lock_guard<std::mutex> lock(m_configMutex);

    m_logger.Info(m_name, "Configuring filesystem monitor service");

    // Store the configuration
    m_config = config;

    // Apply configuration
    return LoadRulesUnsafe();
}

bool FilesystemMonitorService::LoadRules()
{
    std::lock_guard<std::mutex> lock(m_configMutex);
    return LoadRulesUnsafe();
}

bool FilesystemMonitorService::LoadRulesUnsafe()
{

    m_excludedPaths.clear();
    m_excludedExtensions.clear();
    m_protectedPaths.clear();

    // Load default verdict
    auto it = m_config.find("DefaultVerdict");
    if (it != m_config.end()) 
    {
        m_defaultVerdict =
            (it->second == "allow" || it->second == "true");
    }
    else {
        m_defaultVerdict = true;
    }

    // Load monitored operation flags
	// TODO:: Send configuration to the minifilter to avoid processing
    // events we don't care about at all
    it = m_config.find("MonitorCreate");
    if (it != m_config.end()) {
        m_monitorCreate = (it->second == "true");
    }

    it = m_config.find("MonitorWrite");
    if (it != m_config.end()) {
        m_monitorWrite = (it->second == "true");
    }

    it = m_config.find("MonitorRename");
    if (it != m_config.end()) {
        m_monitorRename = (it->second == "true");
    }

    it = m_config.find("MonitorDelete");
    if (it != m_config.end()) {
        m_monitorDelete = (it->second == "true" );
    }

    it = m_config.find("MonitorSetInfo");
    if (it != m_config.end()) {
        m_monitorSetInfo = (it->second == "true");
    }

    // Load scanning configuration
    it = m_config.find("ScanOnCreate");
    if (it != m_config.end()) {
        m_scanOnCreate = (it->second == "true");
    }

    it = m_config.find("ScanOnWrite");
    if (it != m_config.end()) {
        m_scanOnWrite = (it->second == "true");
    }

    it = m_config.find("EnableBlocking");
    if (it != m_config.end()) {
        m_enableBlocking = (it->second == "true");
    }

    // Load excluded paths (comma-separated)
    it = m_config.find("ExcludedPaths");
    if (it != m_config.end()) {
        std::istringstream iss(it->second);
        std::string path;
        while (std::getline(iss, path, ',')) {
            if (!path.empty()) {
                path.erase(0, path.find_first_not_of(" \t\n\r\f\v"));
                path.erase(path.find_last_not_of(" \t\n\r\f\v") + 1);

                int wsize = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
                std::wstring widePath(wsize, 0);
                MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, &widePath[0], wsize);
                widePath.resize(wsize - 1);

                m_excludedPaths.push_back(widePath);
            }
        }
    }

    // Load excluded extensions (comma-separated, e.g. ".log,.tmp,.sys")
    it = m_config.find("ExcludedExtensions");
    if (it != m_config.end()) {
        std::istringstream iss(it->second);
        std::string ext;
        while (std::getline(iss, ext, ',')) {
            if (!ext.empty()) {
                ext.erase(0, ext.find_first_not_of(" \t\n\r\f\v"));
                ext.erase(ext.find_last_not_of(" \t\n\r\f\v") + 1);

                int wsize = MultiByteToWideChar(CP_ACP, 0, ext.c_str(), -1, NULL, 0);
                std::wstring wideExt(wsize, 0);
                MultiByteToWideChar(CP_ACP, 0, ext.c_str(), -1, &wideExt[0], wsize);
                wideExt.resize(wsize - 1);

                m_excludedExtensions.push_back(wideExt);
            }
        }
    }

    it = m_config.find("ProtectedPaths");
    if (it != m_config.end()) {
        std::istringstream iss(it->second);
        std::string path;
        while (std::getline(iss, path, ',')) {
            if (!path.empty()) {
                path.erase(0, path.find_first_not_of(" \t\n\r\f\v"));
                path.erase(path.find_last_not_of(" \t\n\r\f\v") + 1);
                int wsize = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
                std::wstring widePath(wsize, 0);
                MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, &widePath[0], wsize);
                widePath.resize(wsize - 1);
                m_protectedPaths.push_back(widePath);
            }
        }
    }

    m_logger.Info(m_name, "Loaded rules: " +
        std::to_string(m_excludedPaths.size()) + " excluded paths, " +
        std::to_string(m_excludedExtensions.size()) + " excluded extensions, " +
        std::to_string(m_protectedPaths.size()) + " protected paths, " +
        "default verdict: " + (m_defaultVerdict ? "allow" : "deny") + ", " +
        "operations: create=" + (m_monitorCreate ? "yes" : "no") +
        " write=" + (m_monitorWrite ? "yes" : "no") +
        " rename=" + (m_monitorRename ? "yes" : "no") +
        " delete=" + (m_monitorDelete ? "yes" : "no"));

    return true;
}

void FilesystemMonitorService::PollingThreadProc()
{
    m_logger.Info(m_name, "Polling thread started");

    while (m_isRunning)
    {
        AGENT_FS_EVENT fsEvent = { 0 };
        DWORD bytesReturned = 0;

        // Poll the minifilter for filesystem events
        BOOL success = DeviceIoControl(
            m_hPort,
            IOCTL_GET_FS_EVENT,
            NULL,
            0,
            &fsEvent,
            sizeof(AGENT_FS_EVENT),
            &bytesReturned,
            NULL
        );

        if (!success) {
            DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) {
                // No events pending, sleep briefly and retry
                Sleep(100);
                continue;
            }
            else {
                m_logger.Error(m_name, "Error polling for filesystem events: " + std::to_string(error));
                Sleep(1000);
                continue;
            }
        }

        if (bytesReturned > 0)
        {

            // Skip system processes
            if (fsEvent.ProcessId == 0 || fsEvent.ProcessId == 4) {
                fsEvent.AllowOperation = TRUE;
                DeviceIoControl(m_hPort, IOCTL_POST_FS_VERDICT, &fsEvent,
                    sizeof(AGENT_FS_EVENT), NULL, 0, &bytesReturned, NULL);
                continue;
            }

            std::wstring filePath((const wchar_t*)fsEvent.FilePath);
            std::string ansiPath = WideToAnsi(filePath, m_name);

            if (m_serviceManager) {
                auto monSvc = std::dynamic_pointer_cast<MonitoringEventService>(
                    m_serviceManager->GetService("MonitoringEvents"));
                if (monSvc) {
                    std::map<std::string, std::string> fields;
                    fields["ProcessId"] = std::to_string(fsEvent.ProcessId);
                    fields["Operation"] = FileOperationToString(fsEvent.Operation);  // CREATE/WRITE/RENAME/DELETE/SET_INFO
                    fields["FilePath"] = WideToAnsi(std::wstring(fsEvent.FilePath), m_name);
                    fields["NewFilePath"] = WideToAnsi(std::wstring(fsEvent.NewFilePath), m_name);  // for renames
                    fields["FileSize"] = std::to_string(fsEvent.FileSize);
                    fields["IsDirectory"] = fsEvent.IsDirectory ? "true" : "false";
                    monSvc->RecordEvent(m_name, FileOperationToString(fsEvent.Operation), fields);
                }
            }

            // Check if we should monitor this operation type
            bool shouldProcess = false;
            switch (fsEvent.Operation) {
            case FS_OPERATION_CREATE:
                shouldProcess = m_monitorCreate;
                break;
            case FS_OPERATION_WRITE:
                shouldProcess = m_monitorWrite;
                break;
            case FS_OPERATION_RENAME:
                shouldProcess = m_monitorRename;
                break;
            case FS_OPERATION_DELETE:
                shouldProcess = m_monitorDelete;
                break;
            case FS_OPERATION_SET_INFO:
                shouldProcess = m_monitorSetInfo;
                break;
            default:
                shouldProcess = false;
                break;
            }

            if (!shouldProcess) {
                // Allow the operation without further analysis
                fsEvent.AllowOperation = TRUE;

                DeviceIoControl(
                    m_hPort,
                    IOCTL_POST_FS_VERDICT,
                    &fsEvent,
                    sizeof(AGENT_FS_EVENT),
                    NULL,
                    0,
                    &bytesReturned,
                    NULL
                );
                continue;
            }

            m_logger.Info(m_name, "Filesystem event received: " +
                FileOperationToString(fsEvent.Operation) +
                " on " + ansiPath +
                " (PID: " + std::to_string(fsEvent.ProcessId) + ")");


            // Check path inclusion/exclusion rules
            if (!ShouldMonitorFile(filePath)) {
                fsEvent.AllowOperation = TRUE;

                DeviceIoControl(
                    m_hPort,
                    IOCTL_POST_FS_VERDICT,
                    &fsEvent,
                    sizeof(AGENT_FS_EVENT),
                    NULL,
                    0,
                    &bytesReturned,
                    NULL
                );
                continue;
            }


            // Analyze and make a decision
            bool verdict = AnalyzeFileEvent(fsEvent);

            // Send the verdict back to the minifilter
            fsEvent.AllowOperation = verdict;

            success = DeviceIoControl(
                m_hPort,
                IOCTL_POST_FS_VERDICT,
                &fsEvent,
                sizeof(AGENT_FS_EVENT),
                NULL,
                0,
                &bytesReturned,
                NULL
            );

            if (!success) {
                m_logger.Error(m_name, "Failed to send filesystem verdict. Error: " + std::to_string(GetLastError()));
            }
            else {
                m_logger.Info(m_name, "Verdict sent: " + std::string(verdict ? "ALLOWED" : "BLOCKED") +
                    " for " + FileOperationToString(fsEvent.Operation) +
                    " on " + ansiPath);
            }
        }
    }

    m_logger.Info(m_name, "Polling thread exited");
}

bool FilesystemMonitorService::ShouldMonitorFile(const std::wstring& filePath)
{
    std::lock_guard<std::mutex> lock(m_configMutex);

    // Check excluded extensions first (fast check)
    if (IsExcludedExtension(filePath)) {
        return false;
    }

    // Check excluded paths
    for (const auto& excludedPath : m_excludedPaths) {
        if (filePath.find(excludedPath) != std::wstring::npos) {
            return false;
        }
    }

    // Not under any monitored path
    return false;
}

bool FilesystemMonitorService::IsExcludedExtension(const std::wstring& filePath)
{
    // Find the last dot in the file path
    size_t dotPos = filePath.find_last_of(L'.');
    if (dotPos == std::wstring::npos) {
        return false; // No extension
    }

    std::wstring extension = filePath.substr(dotPos);

    for (const auto& excludedExt : m_excludedExtensions) {
        if (_wcsicmp(extension.c_str(), excludedExt.c_str()) == 0) {
            return true;
        }
    }

    return false;
}

bool FilesystemMonitorService::AnalyzeFileEvent(const AGENT_FS_EVENT& fsEvent)
{
    std::wstring filePath((const wchar_t*)fsEvent.FilePath);
    std::string ansiPath = WideToAnsi(filePath, m_name);

    // Determine if this event type should trigger a scan
    bool shouldScan = false;
    switch (fsEvent.Operation) {
    case FS_OPERATION_CREATE:
        shouldScan = m_scanOnCreate;
        break;
    case FS_OPERATION_WRITE:
        shouldScan = m_scanOnWrite;
        break;
    case FS_OPERATION_DELETE:
    case FS_OPERATION_RENAME:
    case FS_OPERATION_SET_INFO:
        // For delete/rename/setinfo, we log but don't scan the file content
        shouldScan = false;
        break;
    default:
        shouldScan = false;
        break;
    }

    // For non-scannable operations (delete, rename)
	// Ensure we are not deleting/renaming protected paths
    if (!shouldScan) {
        // Check if delete is targeting a protected path
        if (fsEvent.Operation == FS_OPERATION_DELETE
            || fsEvent.Operation == FS_OPERATION_RENAME) {
            for (const auto& protectedPath : m_protectedPaths) {
                if (filePath.find(protectedPath) != std::wstring::npos) {
                    m_logger.Warning(m_name, "DELETE/RENAME BLOCKED - protected path: " + ansiPath);
                    return false;
                }
            }
        }
        return true;
    }

    // Request an anti-malware scan through the AntiMalwareService
    if (m_serviceManager) {
        auto antiMalwareService = dynamic_cast<AntiMalwareService*>(
            m_serviceManager->GetService("AntiMalware").get());

        if (antiMalwareService)
        {
            // Create an event for synchronization
            HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

            if (hEvent == NULL) {
                DWORD error = GetLastError();
                m_logger.Error(m_name, "Failed to create event: " + std::to_string(error));
                return m_defaultVerdict;
            }

            // Create context for callback
            ScanContext* context = (ScanContext*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ScanContext));
            if (!context) {
                DWORD error = GetLastError();
                m_logger.Error(m_name, "Failed to allocate scan context: " + std::to_string(error));
                CloseHandle(hEvent);
                return m_defaultVerdict;
            }

            context->hEvent = hEvent;
            context->verdict = TRUE; // Default allow
            // Create callback function
            VerdictCallback callback = [](BOOL verdict, void* ctx) 
            {
                ScanContext* scanContext = (ScanContext*)ctx;
                scanContext->verdict = verdict;
                SetEvent(scanContext->hEvent);
            };

            m_logger.Info(m_name, "Requesting anti-malware scan for: " + ansiPath);

            // Submit the scan request
            BOOL requestSubmitted = antiMalwareService->ScanFile(ansiPath, callback, context);

            if (requestSubmitted)
            {
                // Get timeout from anti-malware service
                DWORD timeout = antiMalwareService->GetScanTimeout();
                if (timeout == 0) {
                    timeout = 10000; // Default 10 seconds
                }

                // Wait for the scan to complete or timeout
                DWORD waitResult = WaitForSingleObject(hEvent, timeout);

                if (waitResult == WAIT_OBJECT_0)
                {
                    BOOL scanVerdict = context->verdict;

                    m_logger.Info(m_name, "Anti-malware scan verdict for file: " +
                        ansiPath + " is: " +
                        (scanVerdict ? "ALLOWED" : "BLOCKED"));

                    CloseHandle(context->hEvent);
                    HeapFree(GetProcessHeap(), 0, context);

                    if (!scanVerdict && m_enableBlocking) {
                        // Create a security event for the blocked operation
                        auto securityEventService = dynamic_cast<SecurityEventService*>(
                            m_serviceManager->GetService("SecurityEvent").get());

                        if (securityEventService) {
                            std::map<std::string, std::string> metadata;
                            metadata["operation"] = FileOperationToString(fsEvent.Operation);
                            metadata["process_id"] = std::to_string(fsEvent.ProcessId);
                            metadata["action"] = "BLOCKED";

                            securityEventService->CreateEvent(
                                "FilesystemMonitor",
                                "FS_OPERATION_BLOCKED",
                                "Filesystem operation blocked by anti-malware scan",
                                "Blocked " + FileOperationToString(fsEvent.Operation) + " on " + ansiPath,
                                ansiPath,
                                SecurityEventSeverity::HIGH,
                                metadata,
                                true // Show alert for blocked operations
                            );
                        }

                        return false; // Block
                    }

                    return true; // Allow (either scan passed or blocking disabled)
                }
                else if (waitResult == WAIT_TIMEOUT)
                {
                    m_logger.Warning(m_name, "Anti-malware scan timed out for file: " + ansiPath);
                    CloseHandle(context->hEvent);
                    HeapFree(GetProcessHeap(), 0, context);

                }
                else {
                    DWORD error = GetLastError();
                    m_logger.Error(m_name, "Wait failed: " + std::to_string(error));
                    CloseHandle(context->hEvent);
                    HeapFree(GetProcessHeap(), 0, context);

                }
            }
            else {
                m_logger.Warning(m_name, "Failed to submit anti-malware scan request");
                CloseHandle(context->hEvent);
                HeapFree(GetProcessHeap(), 0, context);
            }
        }
        else {
            m_logger.Warning(m_name, "AntiMalware service not available");
        }
    }

    // Apply default verdict
    return m_defaultVerdict;
}

std::string FilesystemMonitorService::FileOperationToString(ULONG operation)
{
    switch (operation) {
    case FS_OPERATION_CREATE:       return "CREATE";
    case FS_OPERATION_WRITE:        return "WRITE";
    case FS_OPERATION_RENAME:       return "RENAME";
    case FS_OPERATION_DELETE:       return "DELETE";
    case FS_OPERATION_SET_INFO:     return "SET_INFO";
    default:                        return "UNKNOWN(" + std::to_string(operation) + ")";
    }
}