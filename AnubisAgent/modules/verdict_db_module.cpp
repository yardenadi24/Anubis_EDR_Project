#include "verdict_db_module.h"
#include "service_manager.h"

// Windows cryptography includes
#include <Windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <sstream>
#include <algorithm>
#include <iomanip>

VerdictDbModule::VerdictDbModule()
    :m_logger(Logger::GetInstance()),
    m_initialized(FALSE),
    m_priority(5),  // Default priority - lower than YaraModule
    m_stopOnAllow(true),
    m_stopOnBlock(true),
    m_hashAlgorithm("SHA256")  // Default hash algorithm
{
}

VerdictDbModule::~VerdictDbModule() 
{
    Shutdown();
}

BOOL VerdictDbModule::Initialize()
{
    std::lock_guard<std::mutex>lock(m_moduleMutex);

    if (m_initialized) {
        m_logger.Info(m_name, "VerdictDbModule already initialized.");
        return TRUE;
    }

    m_logger.Info(m_name, "Initializing VerdictDb module");

    // The module needs a reference to the VerdictDbService
    if (!m_verdictDbService) {
        m_logger.Error(m_name, "VerdictDbService reference not set");
        return FALSE;
    }

    m_initialized = TRUE;
    m_logger.Info(m_name, "VerdictDb module initialized");

    return TRUE;
}

void VerdictDbModule::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_moduleMutex);

    if (!m_initialized) {
        return;
    }

    m_logger.Info(m_name, "Shutting down VerdictDb module");
    m_initialized = FALSE;
}

BOOL VerdictDbModule::Configure(const std::map<std::string, std::string>& config)
{
    std::lock_guard<std::mutex> lock(m_moduleMutex);

    m_logger.Info(m_name, "Configuring VerdictDb module");

    // Store configuration
    m_config = config;

    // Extract priority setting
    auto it = config.find("Priority");
    if (it != config.end()) {
        char* endPtr = NULL;
        DWORD priority = strtoul(it->second.c_str(), &endPtr, 10);
        if (endPtr != it->second.c_str() && *endPtr == '\0') {
            m_priority = priority;
        }
    }

    // Extract hash algorithm setting
    it = config.find("HashAlgorithm");
    if (it != config.end()) {
        std::string hashAlg = it->second;
        // Convert to uppercase for case-insensitive comparison
        std::transform(hashAlg.begin(), hashAlg.end(), hashAlg.begin(), ::toupper);
        if (hashAlg == "SHA256") {
            m_hashAlgorithm = hashAlg;
        }
        else {
            m_logger.Warning(m_name, "Invalid hash algorithm specified: " + it->second +
                ", using default: SHA256");
            m_hashAlgorithm = "SHA256";
        }
    }

    // Extract stop on allow setting
    it = config.find("StopOnAllow");
    if (it != config.end()) {
        m_stopOnAllow = (it->second == "true" || it->second == "1" || it->second == "yes");
    }

    // Extract stop on block setting
    it = config.find("StopOnBlock");
    if (it != config.end()) {
        m_stopOnBlock = (it->second == "true" || it->second == "1" || it->second == "yes");
    }

    m_logger.Info(m_name, "Configuration: HashAlgorithm=" + m_hashAlgorithm +
        ", StopOnAllow=" + (m_stopOnAllow ? "true" : "false") +
        ", StopOnBlock=" + (m_stopOnBlock ? "true" : "false") +
        ", Priority=" + std::to_string(m_priority));

    return TRUE;
}

BOOL VerdictDbModule::AnalyzeFile(const std::string& filePath, AnalysisResult& result)
{
    std::lock_guard<std::mutex> lock(m_moduleMutex);

    if (!m_initialized) {
        m_logger.Error(m_name, "VerdictDb module not initialized");
        return FALSE;
    }

    if (!m_verdictDbService) {
        m_logger.Error(m_name, "VerdictDbService reference not set");
        return FALSE;
    }

    m_logger.Info(m_name, "Analyzing file: " + filePath);

    // Check if file exists and is accessible
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
        m_logger.Error(m_name, "Cannot access file: " + filePath +
            ", Error: " + std::to_string(error));
        return FALSE;
    }

    // Close the file handle as we'll reopen it for hashing
    CloseHandle(hFile);

    // Calculate file hash
    std::string fileHash = CalculateFileHash(filePath);
    if (fileHash.empty()) {
        m_logger.Error(m_name, "Failed to calculate hash for file: " + filePath);
        return FALSE;
    }

    m_logger.Info(m_name, "File hash (" + m_hashAlgorithm + "): " + fileHash);

    // Look up the hash in the verdict database
    HashVerdict verdict = m_verdictDbService->GetHashVerdict(fileHash);

    // Prepare result
    result.moduleName = m_name;
    result.detections.clear();

    // Process the verdict
    switch (verdict) {
    case HashVerdict::ALLOW:
        m_logger.Info(m_name, "Hash is allowed: " + fileHash);
        result.shouldBlock = FALSE;
        result.shouldContinue = !m_stopOnAllow;
        result.reason = "File hash is allowed in Verdict DB";
        result.details = "Hash (" + m_hashAlgorithm + "): " + fileHash + "\r\nVerdict: ALLOWED";
        result.metadata["detection_method"] = "hash_lookup";
        result.metadata["hash_algorithm"] = m_hashAlgorithm;
        result.metadata["matched_hash"] = fileHash;
        break;

    case HashVerdict::BLOCK:
        m_logger.Warning(m_name, "Hash is blocked: " + fileHash);
        result.shouldBlock = TRUE;
        result.shouldContinue = !m_stopOnBlock;
        result.reason = "Known malicious file hash";

        // Module provides its own detection details for the alert
        result.details = "Detection: Known malicious file hash\r\n"
            "Hash (" + m_hashAlgorithm + "): " + fileHash + "\r\n"
            "Source: Verdict Database lookup";

        result.detections.push_back("Hash match: " + fileHash);

        // Module provides its own metadata for the security event
        result.metadata["detection_method"] = "hash_lookup";
        result.metadata["hash_algorithm"] = m_hashAlgorithm;
        result.metadata["matched_hash"] = fileHash;

        break;

    case HashVerdict::UNKNOWN:
    default:
        m_logger.Info(m_name, "Hash not found in Verdict database: " + fileHash);
        result.shouldBlock = FALSE;
        result.shouldContinue = TRUE;
        result.reason = "File hash not found in database";
        result.metadata["hash_algorithm"] = m_hashAlgorithm;
        result.metadata["checked_hash"] = fileHash;
        break;
    }

    return TRUE;
}

void VerdictDbModule::SetVerdictDbService(std::shared_ptr<VerdictDbService> service)
{
    std::lock_guard<std::mutex> lock(m_moduleMutex);
    m_verdictDbService = service;

    if (m_verdictDbService) {
        m_logger.Info(m_name, "VerdictDbService reference set");
    }
    else {
        m_logger.Warning(m_name, "VerdictDbService reference cleared");
    }
}

std::string VerdictDbModule::CalculateFileHash(const std::string& filePath)
{
    return CalculateFileSHA256(filePath);
}

std::string VerdictDbModule::CalculateFileSHA256(const std::string& filePath)
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
