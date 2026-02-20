#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include "service_interface.h"
#include "Logger.h"

// Verdict types
enum class HashVerdict {
    UNKNOWN = 0,
    ALLOW = 1,
    BLOCK = 2
};

// Hash entry structure
class HashEntry {
public:
    HashEntry() : verdict(HashVerdict::UNKNOWN), isLocal(false) {}
    std::string hash;           // The file hash (MD5, SHA1, or SHA256)
    HashVerdict verdict;        // The verdict for this hash
    std::string description;    // Optional description
    bool isLocal;               // Whether this entry was added locally and not from the DB file
};

// VerdictDb service class
class VerdictDbService : public IService
{
private:
    const std::string m_name = "VerdictDb";
    ServiceState m_state;
    ServiceManager* m_serviceManager;
    Logger& m_logger;
    std::map<std::string, std::string> m_config;
    std::mutex m_configMutex;

    // Hash database
    std::map<std::string, HashEntry> m_hashDb;
    std::mutex m_hashDbMutex;

    std::string m_defaultHashAlgorithm; // Default hash algorithm to use

    // Database file path
    std::string m_dbFilePath;
    bool m_isDirty;  // Flag to indicate if the db has been modified since last save
public:
    VerdictDbService();
    ~VerdictDbService();

    std::string CalculateFileHash(const std::string& filePath);
    std::string CalculateFileSHA256(const std::string& filePath);

    // IService interface implementation
    const std::string& GetName() const override { return m_name; }
    bool Initialize() override;
    bool Start() override;
    void Stop() override;
    bool Configure(const std::map<std::string, std::string>& config) override;
    ServiceState GetState() const override { return m_state; }
    void SetServiceManager(ServiceManager* manager) override { m_serviceManager = manager; }

    // Hash database operations
    HashVerdict GetHashVerdict(const std::string& hash);
    bool AddHashEntry(const HashEntry& entry);
    bool UpdateHashEntry(const HashEntry& entry);
    bool DeleteHashEntry(const std::string& hash);

    // Database file operations
    bool LoadDatabase();
    bool SaveDatabase();
    bool ReloadDatabase();

private:
    bool LoadDatabaseFromFile(const std::string& filePath);
    bool SaveDatabaseToFile(const std::string& filePath);
    bool ParseJsonDatabase(const std::string& jsonData);
    std::string GenerateJsonDatabase();
};