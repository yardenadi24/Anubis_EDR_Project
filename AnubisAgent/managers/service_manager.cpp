#include "service_manager.h"

ServiceManager::ServiceManager(ConfigurationManager* configManager)
    : m_Logger(Logger::GetInstance()),
    m_ConfigManager(configManager)
{}

ServiceManager::~ServiceManager()
{
    StopAllServices();
}

bool ServiceManager::RegisterService(const std::shared_ptr<IService>& service)
{
    std::lock_guard<std::mutex> lock(m_servicesMutex);

    // Validate pointer
    if (!service) {
        m_Logger.Error("ServiceManager", "Attempted to register null service");
        return false;
    }

    const std::string& name = service->GetName();

    // Check if allready registered
    if (m_services.find(name) != m_services.end()) {
        m_Logger.Warning("ServiceManager", "Service already registered: " + name);
        return false;
    }

    // Set its service manager pointer
    service->SetServiceManager(this);
    m_services[name] = service;

    // Configure the service with its settings
    auto config = m_ConfigManager->GetServiceConfig(name);
    if (!config.empty()) {
        service->Configure(config);
    }

    m_Logger.Info("ServiceManager", "Registered service: " + name);

    return true;
}

bool ServiceManager::UnregisterService(const std::string& serviceName)
{
    std::lock_guard<std::mutex> lock(m_servicesMutex);

    auto it = m_services.find(serviceName);
    if (it == m_services.end()) {
        m_Logger.Warning("ServiceManager", "Service not found for unregistration: " + serviceName);
        return false;
    }

    // Stop the service if it's running
    if (it->second->GetState() == IService::ServiceState::RUNNING) {
        it->second->Stop();
    }

    m_services.erase(it);
    m_Logger.Info("ServiceManager", "Unregistered service: " + serviceName);

    return true;
}

std::shared_ptr<IService> ServiceManager::GetService(const std::string& serviceName)
{
    std::lock_guard<std::mutex> lock(m_servicesMutex);

    auto it = m_services.find(serviceName);
    if (it == m_services.end()) {
        m_Logger.Warning("ServiceManager", "Service not found: " + serviceName);
        return nullptr;
    }

    return it->second;
}

bool ServiceManager::StartAllServices()
{

    std::lock_guard<std::mutex> lock(m_servicesMutex);
    bool allSuccess = true;

    for (auto& pair : m_services) {
        const std::string& name = pair.first;
        auto& service = pair.second;

        if (service->GetState() != IService::ServiceState::RUNNING) {
            m_Logger.Info("ServiceManager", "Starting service: " + name);

            if (!service->Initialize()) {
                m_Logger.Error("ServiceManager", "Failed to initialize service: " + name);
                allSuccess = false;
                continue;
            }

            if (!service->Start()) {
                m_Logger.Error("ServiceManager", "Failed to start service: " + name);
                allSuccess = false;
            }
            else {
                m_Logger.Info("ServiceManager", "Service started successfully: " + name);
            }
        }
    }

    return allSuccess;
}

void ServiceManager::StopAllServices()
{
    std::lock_guard<std::mutex> lock(m_servicesMutex);

    for (auto& pair : m_services) {
        const std::string& name = pair.first;
        auto& service = pair.second;

        if (service->GetState() == IService::ServiceState::RUNNING) {
            m_Logger.Info("ServiceManager", "Stopping service: " + name);
            service->Stop();
            m_Logger.Info("ServiceManager", "Service stopped: " + name);
        }
    }
}

bool ServiceManager::StartService(const std::string& serviceName)
{
    auto service = GetService(serviceName);
    if (!service) {
        m_Logger.Error("ServiceManager", "Service not found: " + serviceName);
        return false;
    }

    if (service->GetState() == IService::ServiceState::RUNNING) {
        m_Logger.Warning("ServiceManager", "Service already running: " + serviceName);
        return true;
    }

    m_Logger.Info("ServiceManager", "Starting service: " + serviceName);

    if (!service->Initialize()) {
        m_Logger.Error("ServiceManager", "Failed to initialize service: " + serviceName);
        return false;
    }

    if (!service->Start()) {
        m_Logger.Error("ServiceManager", "Failed to start service: " + serviceName);
        return false;
    }

    m_Logger.Info("ServiceManager", "Service started successfully: " + serviceName);
    return true;
}

void ServiceManager::StopService(const std::string& serviceName)
{
    auto service = GetService(serviceName);
    if (!service) {
        m_Logger.Error("ServiceManager", "Service not found: " + serviceName);
        return;
    }

    if (service->GetState() != IService::ServiceState::RUNNING) {
        m_Logger.Warning("ServiceManager", "Service not running: " + serviceName);
        return;
    }

    m_Logger.Info("ServiceManager", "Stopping service: " + serviceName);
    service->Stop();
    m_Logger.Info("ServiceManager", "Service stopped: " + serviceName);
}

bool ServiceManager::ConfigureService(const std::string& serviceName,
    const std::map<std::string, std::string>& config) 
{
    auto service = GetService(serviceName);
    if (!service) {
        m_Logger.Error("ServiceManager", "Service not found for configuration: " + serviceName);
        return false;
    }

    m_Logger.Info("ServiceManager", "Configuring service: " + serviceName);
    return service->Configure(config);
}

std::vector<std::string> ServiceManager::GetAllServiceNames()
{
    std::lock_guard<std::mutex> lock(m_servicesMutex);

    std::vector<std::string> names;
    names.reserve(m_services.size());

    for (const auto& pair : m_services) {
        names.push_back(pair.first);
    }

    return names;
}