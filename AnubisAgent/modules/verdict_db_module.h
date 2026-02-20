#pragma once
#include "security_module_interface.h"
#include "verdict_db_service.h"
#include "Logger.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>

// Forward declarations
class Logger;
class VerdictDbService;

// Hash database security module
class VerdictDbModule : public ISecurityModule {

private:
    const std::string m_name = "VerdictDbModule";
    Logger& m_logger;
    std::mutex m_moduleMutex;
    std::map<std::string, std::string> m_config;
    BOOL m_initialized;
    DWORD m_priority;
    std::shared_ptr<VerdictDbService> m_verdictDbService;

    // Module settings
    bool m_stopOnAllow;      // Whether to stop processing if allowed
    bool m_stopOnBlock;      // Whether to stop processing if blocked
    std::string m_hashAlgorithm; // Which hash algorithm to use (MD5, SHA1, SHA256)

public:
    VerdictDbModule();
    virtual ~VerdictDbModule();

    // ISecurityModule implementation
    const std::string& GetName() const override { return m_name; }
    BOOL Initialize() override;
    void Shutdown() override;
    BOOL AnalyzeFile(const std::string& filePath, AnalysisResult& result) override;
    BOOL Configure(const std::map<std::string, std::string>& config) override;
    DWORD GetPriority() const override { return m_priority; }

    // Set the VerdictDbService to use
    void SetVerdictDbService(std::shared_ptr<VerdictDbService> service);

private:
    // Helper methods
    std::string CalculateFileHash(const std::string& filePath);
    std::string CalculateFileSHA256(const std::string& filePath);
};