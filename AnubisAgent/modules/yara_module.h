#pragma once
#include "security_module_interface.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include "Logger.h"
#include <yara.h>


typedef struct YR_RULES YR_RULES;

// YARA-based security module for static analysis
class YaraModule : public ISecurityModule {

private:
    std::string m_name;
    Logger& m_logger;
    std::vector<YR_RULES*> m_rules;
    std::mutex m_moduleMutex;
    std::map<std::string, std::string> m_config;
    BOOL m_initialized;
    DWORD m_priority;

    // Yara settings
    std::string m_rulesDirectory;
    BOOL m_blockOnDetection;
    std::string m_namespace;

public:
    YaraModule(const std::string& name = "YaraModule");
    virtual ~YaraModule();

    // ISecurityModule implementation
    const std::string& GetName() const override { return m_name; }
    BOOL Initialize() override;
    void Shutdown() override;
    BOOL AnalyzeFile(const std::string& filePath, AnalysisResult& result) override;
    BOOL Configure(const std::map<std::string, std::string>& config) override;
    DWORD GetPriority() const override { return m_priority; }

private:
    // Helper methods
    BOOL InitializeYaraLibrary();
    void CleanupYaraLibrary();
    BOOL LoadRulesFromDirectory(const std::string& directoryPath);
    BOOL LoadRulesFromFile(const std::string& filePath);

    // Callback function for YARA matches
    static int YaraCallbackFunction(
        YR_SCAN_CONTEXT* context,
        int message,
        void* message_data,
        void* user_data);

};