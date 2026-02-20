#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <map>

class AnalysisResult {
public:
    AnalysisResult() : shouldBlock(FALSE), shouldContinue(FALSE) {}
    ~AnalysisResult() = default;
    BOOL shouldBlock;           // TRUE = block, FALSE = allow
    std::string moduleName;     // Name of the module that made the decision
    std::string reason;         // Reason for the verdict
    std::vector<std::string> detections;  // List of specific detections if any
    BOOL shouldContinue;
};

// Interface for security analysis modules
class ISecurityModule {
public:
    virtual ~ISecurityModule() = default;

    // Get module name
    virtual const std::string& GetName() const = 0;

    // Initialize the module
    virtual BOOL Initialize() = 0;

    // Shutdown the module
    virtual void Shutdown() = 0;

    // Analyze a file and return a verdict
    virtual BOOL AnalyzeFile(const std::string& filePath, AnalysisResult& result) = 0;

    // Configure the module
    virtual BOOL Configure(const std::map<std::string, std::string>& config) = 0;

    // Get module priority (lower numbers run first)
    virtual DWORD GetPriority() const = 0;
};