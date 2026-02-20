#pragma once
#include <Windows.h>
#include <string>
#include <map>
#include <vector>
#include <mutex>

// Forward declaration
class Logger;

class ConfigurationManager
{
private:
    std::string m_configPath;
    std::map<std::string, std::map<std::string, std::string>> m_configurations;
    std::mutex m_configMutex;
    Logger& m_logger;

    // Helper methods
    bool ReadIniFile(const std::string& filePath);
    bool ParseIniSection(const std::string& sectionName, const char* sectionData, DWORD dataLength);

public:
    ConfigurationManager();
    ~ConfigurationManager();

    // Load/save configuration
    bool LoadConfiguration(const std::string& configPath);
    bool SaveConfiguration(const std::string& configPath = "");

    // Service-specific configuration
    std::map<std::string, std::string> GetServiceConfig(const std::string& serviceName);
    bool SetServiceConfig(const std::string& serviceName, const std::map<std::string, std::string>& config);

    // Global configuration
    std::string GetGlobalConfig(const std::string& key);
    bool SetGlobalConfig(const std::string& key, const std::string& value);

    // Get all section names
    std::vector<std::string> GetSectionNames();
};