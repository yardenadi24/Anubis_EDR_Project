#pragma once

#include "logger.h"
#include "service_interface.h"
#include "configuration_manager.h"

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

	bool StartService(const std::string& serviceName);
	void StopService(const std::string& serviceName);
	bool StartAllServices();
	void StopAllServices();
	std::vector<std::string> GetAllServiceNames();
	bool ConfigureService(const std::string& serviceName, const std::map<std::string, std::string>& config);
	Logger& GetLogger() const { return m_Logger; }
};
