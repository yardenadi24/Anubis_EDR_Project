#include "process_monitor_service.h"
#include "service_manager.h"
#include "anti_malware_service.h"
#include "commons.h"
#include "strings_utils.h"
#include "monitoring_event_service.h"

ProcessMonitorService::ProcessMonitorService()
    :m_state(ServiceState::STOPPED),
    m_hDevice(INVALID_HANDLE_VALUE),
    m_isRunning(false),
    m_serviceManager(nullptr),
    m_logger(Logger::GetInstance()),
    m_defaultVerdict(true) // Allow by default
{
}

ProcessMonitorService::~ProcessMonitorService() {
    Stop();
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
    }
}

bool ProcessMonitorService::Initialize()
{

    m_logger.Info(m_name, "Initializing process monitor service");

    // Open a handle to the driver
    m_hDevice = CreateFileW(
        L"\\\\.\\AnubisEdrDevice",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Failed to open device. Error: " + std::to_string(error));
        m_state = ServiceState::FAILED;
        return false;
    }

    m_logger.Info(m_name, "Successfully connected to the driver");

    // Load rules from configuration
    if (!LoadRules()) {
        m_logger.Warning(m_name, "Failed to load rules, using default configuration");
    }

    m_state = ServiceState::STOPPED;
    return true;
}

bool ProcessMonitorService::Start() 
{

    if (m_state == ServiceState::RUNNING) {
        m_logger.Warning(m_name, "Service already running");
        return true;
    }

    m_logger.Info(m_name, "Starting process monitor service");

    m_state = ServiceState::STARTING;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hDevice,
        IOCTL_START_PROCESS_MONITORING,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    
    if (!success) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Error starting kernel monitoring, stopping service: " + std::to_string(error));
        Stop();
        return false;
    }
    
    m_isRunning = true;
    m_pollingThread = std::thread(&ProcessMonitorService::PollingThreadProc, this);
    m_state = ServiceState::RUNNING;
    
    m_logger.Info(m_name, "Process monitor service started");
    return true;
}

void ProcessMonitorService::Stop() 
{
    if (m_state != ServiceState::RUNNING) {
        return;
    }

    m_logger.Info(m_name, "Stopping process monitor service");

    m_state = ServiceState::STOPPING;
    m_isRunning = false;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hDevice,
        IOCTL_STOP_PROCESS_MONITORING,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!success) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Error stopping kernel monitoring: " + std::to_string(error));
    }

    if (m_pollingThread.joinable()) {
        m_pollingThread.join();
    }

    m_state = ServiceState::STOPPED;
    m_logger.Info(m_name, "Process monitor service stopped");
}

bool ProcessMonitorService::Configure(const std::map<std::string, std::string>& config) 
{
    std::lock_guard<std::mutex> lock(m_configMutex);

    m_logger.Info(m_name, "Configuring process monitor service");

    // Store the configuration
    m_config = config;

    // Apply configuration
    return LoadRulesUnSafe();
}

bool ProcessMonitorService::LoadRules()
{
    std::lock_guard<std::mutex> lock(m_configMutex);
    return LoadRulesUnSafe();
}
bool ProcessMonitorService::LoadRulesUnSafe() {

    m_blockedProcessNames.clear();
    m_blockedPaths.clear();

    // Load default verdict
    auto it = m_config.find("DefaultVerdict");
    if (it != m_config.end()) {
        m_defaultVerdict = (it->second == "allow" || it->second == "true");
    }
    else {
        m_defaultVerdict = true; // Allow by default
    }

    // Load blocked processes
    it = m_config.find("BlockedProcesses");
    if (it != m_config.end()) {
        std::istringstream iss(it->second);
        std::string process;
        while (std::getline(iss, process, ',')) {
            if (!process.empty()) {
                // Trim whitespace
                process.erase(0, process.find_first_not_of(" \t\n\r\f\v"));
                process.erase(process.find_last_not_of(" \t\n\r\f\v") + 1);

                // Convert to wide string
                int wsize = MultiByteToWideChar(CP_ACP, 0, process.c_str(), -1, NULL, 0);
                std::wstring wideProcess(wsize, 0);
                MultiByteToWideChar(CP_ACP, 0, process.c_str(), -1, &wideProcess[0], wsize);
                wideProcess.resize(wsize - 1);  // Remove the null terminator from string size

                m_blockedProcessNames.push_back(wideProcess);
            }
        }
    }

    // Load blocked paths
    it = m_config.find("BlockedPaths");
    if (it != m_config.end()) {
        std::istringstream iss(it->second);
        std::string path;
        while (std::getline(iss, path, ',')) {
            if (!path.empty()) {
                // Trim whitespace
                path.erase(0, path.find_first_not_of(" \t\n\r\f\v"));
                path.erase(path.find_last_not_of(" \t\n\r\f\v") + 1);

                // Convert to wide string
                int wsize = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
                std::wstring widePath(wsize, 0);
                MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, &widePath[0], wsize);
                widePath.resize(wsize - 1);  // Remove the null terminator from string size

                m_blockedPaths.push_back(widePath);
            }
        }
    }

    m_logger.Info(m_name, "Loaded rules: " +
        std::to_string(m_blockedProcessNames.size()) + " blocked processes, " +
        std::to_string(m_blockedPaths.size()) + " blocked paths, " +
        "default verdict: " + (m_defaultVerdict ? "allow" : "deny"));

    return true;
}

void ProcessMonitorService::PollingThreadProc()
{
    m_logger.Info(m_name, "Polling thread started");

    while (m_isRunning)
    {
        AGENT_PROCESS_EVENT procEvent = { 0 };
        DWORD bytesReturned = 0;

        // Poll for process events
        BOOL success = DeviceIoControl(
            m_hDevice,
            IOCTL_GET_PROCESS_EVENT,
            NULL,
            0,
            &procEvent,
            sizeof(AGENT_PROCESS_EVENT),
            &bytesReturned,
            NULL
        );

        if (!success) {
            DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) {
                // No more events, sleep and try again
                Sleep(100);
                continue;
            }
            else {
                m_logger.Error(m_name, "Error polling for process events: " + std::to_string(error));
                Sleep(100);
                continue;
            }
        }


        if (bytesReturned > 0)
        {
            std::wstring processName((const wchar_t*)procEvent.ImageFileName);
            m_logger.Info(m_name, "Process event received: " +
                WideToAnsi(processName, m_name) +
                " (PID: " + std::to_string(procEvent.ProcessId) + ")");

            if (m_serviceManager) {
                auto monSvc = std::dynamic_pointer_cast<MonitoringEventService>(
                    m_serviceManager->GetService("MonitoringEvents"));
                if (monSvc) {
                    std::map<std::string, std::string> fields;
                    fields["ProcessId"] = std::to_string(procEvent.ProcessId);
                    fields["ImageFileName"] = WideToAnsi(processName, m_name);
                    monSvc->RecordEvent(m_name, "ProcessCreate", fields);
                }
            }


            // Analyze and make a decision
            bool verdict = AnalyzeProcess(procEvent);

            // Send the verdict back to the driver
            procEvent.AllowProcess = verdict;

            success = DeviceIoControl(
                m_hDevice,
                IOCTL_POST_PROCESS_VERDICT,
                &procEvent,
                sizeof(AGENT_PROCESS_EVENT),
                NULL,
                0,
                &bytesReturned,
                NULL
            );

            if (!success) {
                m_logger.Error(m_name, "Failed to send verdict. Error: " + std::to_string(GetLastError()));
            }
            else {
                m_logger.Info(m_name, "Verdict sent: " + std::string(verdict ? "ALLOWED" : "BLOCKED") +
                    " for process " + WideToAnsi(processName, m_name));
            }

        }

    }

    m_logger.Info(m_name, "Polling thread exited");
}

bool ProcessMonitorService::AnalyzeProcess(const AGENT_PROCESS_EVENT& procEvent)
{
    std::lock_guard<std::mutex> lock(m_configMutex);

    // Extract the process name from the full path
    std::wstring fullPath((const wchar_t*)procEvent.ImageFileName);
    // Strip NT path prefix for user-mode APIs
    if (fullPath.substr(0, 4) == L"\\??\\") {
        fullPath = fullPath.substr(4);
    }

    size_t lastSlash = fullPath.find_last_of(L'\\');
    std::wstring procName = (lastSlash != std::wstring::npos) ?
        fullPath.substr(lastSlash + 1) : fullPath;

    static const std::wstring systemProcs[] = {
        L"svchost.exe", L"csrss.exe", L"wininit.exe", L"services.exe",
        L"lsass.exe", L"smss.exe", L"winlogon.exe", L"dwm.exe",
        L"conhost.exe", L"RuntimeBroker.exe", L"SearchIndexer.exe",
        L"spoolsv.exe", L"WmiPrvSE.exe", L"taskhostw.exe",
        L"explorer.exe", L"sihost.exe", L"fontdrvhost.exe",
        L"System", L"Registry"
    };
    for (const auto& sysProc : systemProcs) {
        if (_wcsicmp(procName.c_str(), sysProc.c_str()) == 0) {
            return true; // Allow silently
        }
    }

    
    // Check if the process name is in the blocked list
    for (const auto& blockedProc : m_blockedProcessNames) {
        if (_wcsicmp(procName.c_str(), blockedProc.c_str()) == 0) {
            m_logger.Info(m_name, "Process blocked by name rule: " +
                WideToAnsi(procName, m_name));
            return false; // Block
        }
    }

    // Check if the process path matches any blocked paths
    for (const auto& blockedPath : m_blockedPaths) {
        if (fullPath.find(blockedPath) != std::wstring::npos) {
            m_logger.Info(m_name, "Process blocked by path rule: " +
                WideToAnsi(fullPath, m_name));
            return false; // Block
        }
    }

    // Check if anti-malware service is available through ServiceManager
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

            // Create context for callback using Windows heap allocation
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
            VerdictCallback callback = [](BOOL verdict, void* ctx) {
                ScanContext* scanContext = (ScanContext*)ctx;
                scanContext->verdict = verdict;
                SetEvent(scanContext->hEvent);
                };

            // Convert file path to ANSI for service
            std::string ansiPath = WideToAnsi(fullPath, m_name);

            m_logger.Info(m_name, "Requesting anti-malware scan for: " + ansiPath);

            // Submit the scan request to the anti-malware service
            BOOL requestSubmitted = antiMalwareService->ScanFile(ansiPath, callback, context);

            if (requestSubmitted)
            {
                // Get timeout from anti-malware service
                DWORD timeout = antiMalwareService->GetScanTimeout();
                if (timeout == 0) {
                    timeout = 10000; // Default 10 seconds if service returns 0
                }

                // Wait for the scan to complete or timeout
                DWORD waitResult = WaitForSingleObject(hEvent, timeout);

                if (waitResult == WAIT_OBJECT_0)
                {
                    // Scan completed
                    BOOL scanVerdict = context->verdict;

                    m_logger.Info(m_name, "Anti-malware scan verdict for process: " +
                        std::to_string(procEvent.ProcessId) + " is: " +
                        (scanVerdict ? "ALLOWED" : "BLOCKED"));

                    // Clean up
                   
                    CloseHandle(context->hEvent);
                    HeapFree(GetProcessHeap(), 0, context);
                    
                    if (!scanVerdict) {
                        return false; // Block based on anti-malware verdict
                    }
                }
                else if (waitResult == WAIT_TIMEOUT)
                {
                    m_logger.Warning(m_name, "Anti-malware scan timed out for process: " +
                        std::to_string(procEvent.ProcessId));

                    // Clean up
                    CloseHandle(context->hEvent);
                    HeapFree(GetProcessHeap(), 0, context);

                }
                else {
                    DWORD error = GetLastError();
                    m_logger.Error(m_name, "Wait failed: " + std::to_string(error));

                    // Clean
                    CloseHandle(context->hEvent);
                    HeapFree(GetProcessHeap(), 0, context);

                }
            }
            else {
                m_logger.Warning(m_name, "Failed to submit anti-malware scan request");

                // Clean up
                CloseHandle(context->hEvent);
                HeapFree(GetProcessHeap(), 0, context);
            }

        }
    }

    // Apply default verdict
    return m_defaultVerdict;
}

