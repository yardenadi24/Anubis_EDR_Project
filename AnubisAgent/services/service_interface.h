#pragma once
#include <string>
#include <map>

class ServiceManager; // Forward declaration

// Base service interface that all security services must implement
class IService
{

public:
    enum class ServiceState {
        STOPPED,
        RUNNING,
        STARTING,
        STOPPING,
        FAILED,
        UNKNOWN
    };

    virtual ~IService() = default;

    virtual const std::string& GetName() const = 0;
    virtual bool Initialize() = 0;
    virtual bool Start() = 0;
    virtual void Stop() = 0;
    virtual bool Configure(const std::map<std::string, std::string>& config) = 0;
    virtual ServiceState GetState() const = 0;
    virtual void SetServiceManager(ServiceManager* manager) = 0;
};