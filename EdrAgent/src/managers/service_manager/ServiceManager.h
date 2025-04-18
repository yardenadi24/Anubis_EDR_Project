#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <memory>
#include <filesystem>
#include <fstream>

#include "..\..\commons\logger\Logger.h"
#include "..\..\services\IService.h"
#include "..\configuration_manager\ConfigurationManager.h"

// Service manager class to handle all services
class ServiceManager
{
private:
	std::map<std::string, std::shared_ptr<IService>> m_services;
	std::mutex m_servicesMutex;
	Logger& m_Logger;
	ConfigurationManager* m_ConfigManager;

public:
	ServiceManager(ConfigurationManager* configManager);
	~ServiceManager();

	bool RegisterService(const std::shared_ptr<IService>& service);
	bool UnregisterService(const std::string& serviceName);
	std::shared_ptr<IService> GetService(const std::string& serviceName);
	bool StartAllServices();
	bool StartService(const std::string& serviceName);
	void StopAllServices();
	void StopService(const std::string& serviceName);
	Logger& GetLogger() const { return m_Logger; }
	bool ConfigureService(const std::string& serviceName, const std::map<std::string, std::string>& config);
	std::vector<std::string> GetAllServiceNames();
};

