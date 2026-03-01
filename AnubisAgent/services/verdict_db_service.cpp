#include "verdict_db_service.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>

// RapidJSON includes
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h" // For nice formatting

VerdictDbService::VerdictDbService()
    : m_state(ServiceState::STOPPED),
    m_serviceManager(nullptr),
    m_logger(Logger::GetInstance()),
    m_isDirty(false)
{
}


VerdictDbService::~VerdictDbService() {
    // Last-resort save in case Stop() wasn't called
    if (m_isDirty) {
        try {
            SaveDatabase();
        }
        catch (...) {
            // Destructor must not throw
        }
    }
}

bool VerdictDbService::Initialize()
{
    m_logger.Info(m_name, "Initializing verdict database service");

    // Load configuration
    {
        std::lock_guard<std::mutex> lock(m_configMutex);

        // Get database file path from config
        auto it = m_config.find("DatabaseFile");
        if (it != m_config.end()) {
            m_dbFilePath = it->second;
            m_logger.Info(m_name, "Database file path: " + m_dbFilePath);
        }
        else {
            // Default database path
			m_dbFilePath = DEFAULT_DB_FILE;
            m_logger.Warning(m_name, "No database file specified in config, using default: " + m_dbFilePath);
        }

        // In VerdictDbService::Configure method:
        it = m_config.find("DefaultHashAlgorithm");
        if (it != m_config.end()) {
            m_defaultHashAlgorithm = it->second;
        }
        else {
            m_defaultHashAlgorithm = "SHA256"; // Default if not specified
        }

    }

    EnsureDirectoryExists(m_dbFilePath);

    // Try to load the database
    if (std::filesystem::exists(m_dbFilePath)) {
        if (!LoadDatabase()) {
            m_logger.Warning(m_name, "Failed to load verdict database, starting with empty database");
        }
        else {
            m_logger.Info(m_name, "Loaded verdict database with " +
                std::to_string(m_hashDb.size()) + " entries from file");
        }
    }
    else {
        m_logger.Info(m_name, "No existing database file found at " + m_dbFilePath +
            ", starting with empty database (will be created on save)");
    }

    m_state = ServiceState::STOPPED;
    return true;

}

std::string VerdictDbService::CalculateFileHash(const std::string& filePath) {
    // Use specified algorithm or fall back to default
    std::string hashAlg = m_defaultHashAlgorithm;

    // Convert to upper case for case-insensitive comparison
    std::transform(hashAlg.begin(), hashAlg.end(), hashAlg.begin(), ::toupper);


    // Default to SHA256
    return CalculateFileSHA256(filePath);
}

void VerdictDbService::EnsureDirectoryExists(const std::string& filePath)
{
    try {
        std::filesystem::path p(filePath);
        std::filesystem::path parentDir = p.parent_path();

        if (!parentDir.empty() && !std::filesystem::exists(parentDir)) {
            std::filesystem::create_directories(parentDir);
            m_logger.Info(m_name, "Created directory: " + parentDir.string());
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        m_logger.Error(m_name, "Failed to create directory for: " + filePath +
            ", Error: " + std::string(e.what()));
    }
}

std::string VerdictDbService::VerdictToString(HashVerdict verdict)
{
    switch (verdict) {
    case HashVerdict::ALLOW:    return "ALLOW";
    case HashVerdict::BLOCK:    return "BLOCK";
    case HashVerdict::UNKNOWN:  return "UNKNOWN";
    default:                    return "INVALID(" + std::to_string(static_cast<int>(verdict)) + ")";
    }
}

std::string VerdictDbService::CalculateFileSHA256(const std::string& filePath)
{
    // Implementation for SHA256 - similar to SHA1 but using SHA256 algorithm
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = 0;
    DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;
    std::string hashString = "";

    // Open the file
    HANDLE hFile = CreateFileA(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Failed to open file for hashing: " + filePath +
            ", Error: " + std::to_string(error));
        return "";
    }

    // Open an algorithm handle
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0))) {
        m_logger.Error(m_name, "BCryptOpenAlgorithmProvider failed: " + std::to_string(status));
        CloseHandle(hFile);
        return "";
    }

    // Calculate the size of the buffer to hold the hash object
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject,
        sizeof(DWORD),
        &cbData,
        0))) {
        m_logger.Error(m_name, "BCryptGetProperty failed: " + std::to_string(status));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return "";
    }

    // Allocate the hash object
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        m_logger.Error(m_name, "Failed to allocate memory for hash object");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return "";
    }

    // Calculate the length of the hash
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&cbHash,
        sizeof(DWORD),
        &cbData,
        0))) {
        m_logger.Error(m_name, "BCryptGetProperty failed: " + std::to_string(status));
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return "";
    }

    // Allocate the hash buffer
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash) {
        m_logger.Error(m_name, "Failed to allocate memory for hash");
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return "";
    }

    // Create a hash
    if (!BCRYPT_SUCCESS(status = BCryptCreateHash(
        hAlg,
        &hHash,
        pbHashObject,
        cbHashObject,
        NULL,
        0,
        0))) {
        m_logger.Error(m_name, "BCryptCreateHash failed: " + std::to_string(status));
        HeapFree(GetProcessHeap(), 0, pbHash);
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return "";
    }

    // Read the file and update the hash
    BYTE rgbFile[1024];
    DWORD cbRead = 0;
    BOOL result = FALSE;

    while ((result = ReadFile(hFile, rgbFile, sizeof(rgbFile), &cbRead, NULL)) != 0 && cbRead > 0) {
        if (!BCRYPT_SUCCESS(status = BCryptHashData(
            hHash,
            rgbFile,
            cbRead,
            0))) {
            m_logger.Error(m_name, "BCryptHashData failed: " + std::to_string(status));
            BCryptDestroyHash(hHash);
            HeapFree(GetProcessHeap(), 0, pbHash);
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return "";
        }
    }

    // Finalize the hash
    if (!BCRYPT_SUCCESS(status = BCryptFinishHash(
        hHash,
        pbHash,
        cbHash,
        0))) {
        m_logger.Error(m_name, "BCryptFinishHash failed: " + std::to_string(status));
        BCryptDestroyHash(hHash);
        HeapFree(GetProcessHeap(), 0, pbHash);
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return "";
    }

    // Convert hash to hex string
    std::stringstream ss;
    for (DWORD i = 0; i < cbHash; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)pbHash[i];
    }
    hashString = ss.str();

    // Clean up
    BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(), 0, pbHash);
    HeapFree(GetProcessHeap(), 0, pbHashObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);

    return hashString;
}

bool VerdictDbService::Start()
{

    if (m_state == ServiceState::RUNNING) {
        m_logger.Warning(m_name, "Service already running");
        return true;
    }

    m_logger.Info(m_name, "Starting verdict database service");

    // Nothing special to start for this service
    m_state = ServiceState::RUNNING;

    m_logger.Info(m_name, "Verdict database service started with " +
        std::to_string(m_hashDb.size()) + " hash entries");

    return true;
}

void VerdictDbService::Stop()
{
    if (m_state != ServiceState::RUNNING) {
        return;
    }

    m_logger.Info(m_name, "Stopping verdict database service");

    // Save the database if it has unsaved changes
    if (m_isDirty) {
        m_logger.Info(m_name, "Database has unsaved changes (" +
            std::to_string(m_hashDb.size()) + " entries), saving to file...");

        if (SaveDatabase()) {
            m_logger.Info(m_name, "Successfully saved verdict database to: " + m_dbFilePath);
        }
        else {
            m_logger.Error(m_name, "Failed to save verdict database to: " + m_dbFilePath);
        }
    }
    else {
        m_logger.Info(m_name, "No unsaved changes, skipping save");
    }

    m_state = ServiceState::STOPPED;
    m_logger.Info(m_name, "Verdict database service stopped");
}

bool VerdictDbService::Configure(const std::map<std::string, std::string>& config)
{

    std::lock_guard<std::mutex> lock(m_configMutex);

    m_logger.Info(m_name, "Configuring verdict database service");

    // Store configuration
    m_config = config;

    // Get database file path
    auto it = m_config.find("VerdictDatabaseFile");
    if (it != m_config.end()) {
        std::string newDbFilePath = it->second;

        // If the file path changed and we have unsaved changes, save them first
        if (newDbFilePath != m_dbFilePath && m_isDirty) {
            SaveDatabaseToFile(m_dbFilePath);
        }

        m_dbFilePath = newDbFilePath;
        m_logger.Info(m_name, "Verdicts Database file path: " + m_dbFilePath);

        // Try to load the database if we're configured with a new path
        return LoadDatabaseFromFile(m_dbFilePath);
    }

    return false;
}

HashVerdict VerdictDbService::GetHashVerdict(const std::string& hash) 
{
    std::lock_guard<std::mutex> lock(m_hashDbMutex);

    auto it = m_hashDb.find(hash);
    if (it != m_hashDb.end()) {
        return it->second.verdict;
    }

    return HashVerdict::UNKNOWN;
}

bool VerdictDbService::AddHashEntry(const HashEntry& entry) 
{
    std::lock_guard<std::mutex> lock(m_hashDbMutex);

    // Make sure the hash isn't already in the database
    auto it = m_hashDb.find(entry.hash);
    if (it != m_hashDb.end()) {
        m_logger.Warning(m_name, "Hash already exists in database: " + entry.hash);
        return false;
    }

    // Create a copy of the entry and mark it as local
    HashEntry newEntry = entry;
    newEntry.isLocal = true;

    // Add to database
    m_hashDb[entry.hash] = newEntry;
    m_isDirty = true;

    m_logger.Info(m_name, "Added hash to database: " + entry.hash +
        ", Verdict: " + std::to_string(static_cast<int>(entry.verdict)));

    return true;
}

bool VerdictDbService::AddOrUpdateHashEntry(const std::string& hash, HashVerdict verdict, const std::string& description)
{
    std::lock_guard<std::mutex> lock(m_hashDbMutex);

    auto it = m_hashDb.find(hash);
    if (it != m_hashDb.end()) {
        // Update existing
        it->second.verdict = verdict;
        if (!description.empty()) {
            it->second.description = description;
        }
        it->second.isLocal = true;
    }
    else {
        // Add new
        HashEntry entry;
        entry.hash = hash;
        entry.verdict = verdict;
        entry.description = description;
        entry.isLocal = true;
        m_hashDb[hash] = entry;
    }

    m_isDirty = true;

    m_logger.Info(m_name, "Added/updated hash in database: " + hash +
        ", Verdict: " + VerdictToString(verdict));

    return true;
}

bool VerdictDbService::UpdateHashEntry(const HashEntry& entry) 
{
    std::lock_guard<std::mutex> lock(m_hashDbMutex);

    // Make sure the hash is in the database
    auto it = m_hashDb.find(entry.hash);
    if (it == m_hashDb.end()) {
        m_logger.Warning(m_name, "Hash not found in database: " + entry.hash);
        return false;
    }

    // Update the entry
    it->second.verdict = entry.verdict;
    it->second.description = entry.description;
    it->second.isLocal = true;  // Mark as locally modified
    m_isDirty = true;

    m_logger.Info(m_name, "Updated hash in database: " + entry.hash +
        ", New verdict: " + std::to_string(static_cast<int>(entry.verdict)));

    return true;
}

bool VerdictDbService::DeleteHashEntry(const std::string& hash)
{
    std::lock_guard<std::mutex> lock(m_hashDbMutex);

    // Make sure the hash is in the database
    auto it = m_hashDb.find(hash);
    if (it == m_hashDb.end()) {
        m_logger.Warning(m_name, "Hash not found in database: " + hash);
        return false;
    }

    // Remove from database
    m_hashDb.erase(it);
    m_isDirty = true;

    m_logger.Info(m_name, "Deleted hash from database: " + hash);

    return true;
}

size_t VerdictDbService::GetEntryCount() const
{
    return m_hashDb.size();
}

bool VerdictDbService::LoadDatabase() 
{
    return LoadDatabaseFromFile(m_dbFilePath);
}

bool VerdictDbService::SaveDatabase() 
{
    return SaveDatabaseToFile(m_dbFilePath);
}

bool VerdictDbService::ReloadDatabase()
{
    // Clear the database and reload from file
    std::lock_guard<std::mutex> lock(m_hashDbMutex);
    m_hashDb.clear();
    m_isDirty = false;

    return LoadDatabaseFromFile(m_dbFilePath);
}

bool VerdictDbService::LoadDatabaseFromFile(const std::string& filePath) 
{

    if (!std::filesystem::exists(filePath)) {
        m_logger.Info(m_name, "Database file does not exist yet: " + filePath);
        return false;
    }

    std::ifstream file(filePath);
    if (!file.is_open()) {
        m_logger.Error(m_name, "Failed to open database file: " + filePath);
        return false;
    }

    // Read the entire file
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    std::string content = buffer.str();

    // Treat empty file as valid (0 entries) instead of parse error
    if (content.empty()) {
        m_logger.Info(m_name, "Database file is empty, starting with 0 entries");
        return true;
    }

    // Parse the JSON data
    bool success = ParseJsonDatabase(buffer.str());

    if (success) {
        m_logger.Info(m_name, "Successfully loaded " + std::to_string(m_hashDb.size()) +
            " hash entries from " + filePath);
    }
    else {
        m_logger.Error(m_name, "Failed to parse database file: " + filePath);
    }

    return success;
}

bool VerdictDbService::SaveDatabaseToFile(const std::string& filePath) 
{
    EnsureDirectoryExists(filePath);

    // Generate JSON from the database
    std::string jsonData = GenerateJsonDatabase();

    // Open the file for writing
    std::ofstream file(filePath);
    if (!file.is_open()) {
        m_logger.Error(m_name, "Failed to open database file for writing: " + filePath);
        return false;
    }

    // Write the JSON data
    file << jsonData;
    file.close();

    m_isDirty = false;
    m_logger.Info(m_name, "Successfully saved " + std::to_string(m_hashDb.size()) +
        " hash entries to " + filePath);

    return true;
}

bool VerdictDbService::ParseJsonDatabase(const std::string& jsonData) 
{
    std::lock_guard<std::mutex> lock(m_hashDbMutex);

    // Clear the existing database
    m_hashDb.clear();

    try {
        // Parse the JSON using RapidJSON
        rapidjson::Document document;
        if (document.Parse(jsonData.c_str()).HasParseError()) {
            m_logger.Error(m_name, "JSON parsing error: " +
                std::to_string(document.GetParseError()) +
                " at offset " + std::to_string(document.GetErrorOffset()));
            return false;
        }

        // Check if document has the 'hashes' array
        if (!document.HasMember("hashes") || !document["hashes"].IsArray()) {
            m_logger.Error(m_name, "Invalid database format: missing 'hashes' array");
            return false;
        }

        // Extract hash entries
        const rapidjson::Value& hashesArray = document["hashes"];
        for (rapidjson::SizeType i = 0; i < hashesArray.Size(); i++) {
            const rapidjson::Value& hashObject = hashesArray[i];

            // Validate required fields
            if (!hashObject.HasMember("hash") || !hashObject["hash"].IsString() ||
                !hashObject.HasMember("verdict") || !hashObject["verdict"].IsInt()) {
                m_logger.Warning(m_name, "Skipping invalid hash entry at index " + std::to_string(i));
                continue;
            }

            HashEntry entry;
            entry.hash = hashObject["hash"].GetString();
            entry.verdict = static_cast<HashVerdict>(hashObject["verdict"].GetInt());

            // Optional description field
            if (hashObject.HasMember("description") && hashObject["description"].IsString()) {
                entry.description = hashObject["description"].GetString();
            }

            // Not from local changes
            entry.isLocal = false;

            // Add to database
            m_hashDb[entry.hash] = entry;
        }

        return true;
    }
    catch (const std::exception& e) {
        m_logger.Error(m_name, "Exception during JSON parsing: " + std::string(e.what()));
        return false;
    }
}

std::string VerdictDbService::GenerateJsonDatabase() 
{
    std::lock_guard<std::mutex> lock(m_hashDbMutex);

    try {
        // Create document and array for hashes
        rapidjson::Document document;
        document.SetObject();
        rapidjson::Document::AllocatorType& allocator = document.GetAllocator();

        // Create hashes array
        rapidjson::Value hashesArray(rapidjson::kArrayType);

        // Add each hash entry to the array
        for (const auto& pair : m_hashDb) {
            const HashEntry& entry = pair.second;

            // Create hash object
            rapidjson::Value hashObject(rapidjson::kObjectType);

            // Add hash field
            rapidjson::Value hashValue;
            hashValue.SetString(entry.hash.c_str(), static_cast<rapidjson::SizeType>(entry.hash.length()), allocator);
            hashObject.AddMember("hash", hashValue, allocator);

            // Add verdict field
            hashObject.AddMember("verdict", static_cast<int>(entry.verdict), allocator);

            // Add description field
            rapidjson::Value descValue;
            descValue.SetString(entry.description.c_str(), static_cast<rapidjson::SizeType>(entry.description.length()), allocator);
            hashObject.AddMember("description", descValue, allocator);

            // Add to array
            hashesArray.PushBack(hashObject, allocator);
        }

        // Add hashes array to document
        document.AddMember("hashes", hashesArray, allocator);

        // Write document to string with pretty formatting
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        document.Accept(writer);

        return buffer.GetString();
    }
    catch (const std::exception& e) {
        m_logger.Error(m_name, "Exception during JSON generation: " + std::string(e.what()));
        return "{}";  // Return empty JSON object on error
    }
}