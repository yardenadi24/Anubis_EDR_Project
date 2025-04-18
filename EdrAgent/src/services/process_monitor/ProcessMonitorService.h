#pragma once
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <fstream>
#include <atomic>
#include <sstream>      // std::istringstream
#include <mutex>
#include "..\IService.h"
#include <Windows.h>
#include "..\..\commons\logger\Logger.h"
#include "..\..\managers\configuration_manager\ConfigurationManager.h"
#include "..\..\Commons\SharedCommons.h" // This contains the shared structures

// Structure used for anti-malware scan callback
struct ScanContext {
	HANDLE hEvent;
	BOOL verdict; // TRUE = allow, FALSE = block
};

// Callback function type for anti-malware scanning
typedef void (*ScanResultCallback)(bool verdict, void* context);

class ProcessMonitorService : public IService
{
private:
	const std::string m_name = "ProcessMonitor";
	ServiceState m_state;
	HANDLE m_hDevice;
	std::thread m_pollingThread;
	std::atomic<bool> m_isRunning;
	std::map<std::string, std::string> m_config;
	std::mutex m_configMutex;
	ServiceManager* m_serviceManager;
	Logger& m_logger;

	std::vector<std::wstring> m_blockedProcessNames;
	std::vector<std::wstring> m_blockedPaths;

	bool m_defaultVerdict; // true = allow, false = deny

public:
	ProcessMonitorService();
	~ProcessMonitorService();

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
	bool AnalyzeProcess(const AGENT_PROCESS_EVENT& procEvent);
	bool LoadRules();
	bool LoadRulesUnSafe();
};

