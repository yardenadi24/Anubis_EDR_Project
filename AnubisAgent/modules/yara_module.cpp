#include "yara_module.h"
#include <yara.h>

// Struct for passing data to YARA callback
struct YaraCallbackData {
    AnalysisResult* result;
    YaraModule* module;
};

YaraModule::YaraModule(const std::string& name)
    : m_name(name),
    m_logger(Logger::GetInstance()),
    m_initialized(FALSE),
    m_priority(10),  // Default priority
    m_blockOnDetection(TRUE),
    m_namespace("Anubis")
{
}

YaraModule::~YaraModule() {
    Shutdown();
}

BOOL YaraModule::Initialize()
{
    std::lock_guard<std::mutex>lock(m_moduleMutex);

    if (m_initialized) {
        m_logger.Info(m_name, "YaraModule already initialized.");
        return TRUE;
    }

    m_logger.Info(m_name, "Initializing YARA module");

    // Initialize YARA library
    if (!InitializeYaraLibrary()) {
        m_logger.Error(m_name, "Failed to initialize YARA library");
        return FALSE;
    }

    // Load rules
    if (!m_rulesDirectory.empty()) {
        if (!LoadRulesFromDirectory(m_rulesDirectory)) {
            m_logger.Warning(m_name, "Failed to load rules from directory: " + m_rulesDirectory);
        }
    }
    else {
        m_logger.Warning(m_name, "No rules directory specified");
    }

    // Check if any rules were loaded
    if (m_rules.empty()) {
        m_logger.Warning(m_name, "No YARA rules loaded, module will not be effective");
    }
    else {
        m_logger.Info(m_name, "Loaded " + std::to_string(m_rules.size()) + " rule files");
    }

    m_initialized = TRUE;
    return TRUE;
}

void YaraModule::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_moduleMutex);

    if (!m_initialized) {
        return;
    }

    m_logger.Info(m_name, "Shutting down YARA module");

    // Clean up YARA resources
    CleanupYaraLibrary();

    m_initialized = FALSE;
}

BOOL YaraModule::Configure(const std::map<std::string, std::string>& config)
{
    std::lock_guard<std::mutex> lock(m_moduleMutex);

    m_logger.Info(m_name, "Configuring YARA module");

    // Store configuration
    m_config = config;

    // Extract rules directory
    auto it = config.find("RulesDirectory");
    if (it != config.end()) {
        m_rulesDirectory = it->second;
    }
    else {
        // Default rules directory
        m_rulesDirectory = "C:\\ProgramData\\Anubis\\Rules";
    }

    // Extract block on detection setting
    it = config.find("BlockOnDetection");
    if (it != config.end()) {
        m_blockOnDetection = (it->second == "true" || it->second == "1" || it->second == "yes") ? TRUE : FALSE;
    }

    // Extract priority
    it = config.find("Priority");
    if (it != config.end()) {
        char* endPtr = NULL;
        DWORD priority = strtoul(it->second.c_str(), &endPtr, 10);
        if (endPtr != it->second.c_str() && *endPtr == '\0') {
            m_priority = priority;
        }
    }

    m_logger.Info(m_name, "Configuration: RulesDirectory=" + m_rulesDirectory +
        ", BlockOnDetection=" + (m_blockOnDetection ? "true" : "false") +
        ", Priority=" + std::to_string(m_priority));

    return TRUE;
}

BOOL YaraModule::AnalyzeFile(const std::string& filePath, AnalysisResult& result)
{
    std::lock_guard<std::mutex> lock(m_moduleMutex);

    if (!m_initialized) {
        m_logger.Error(m_name, "YARA module not initialized");
        return FALSE;
    }

    if (m_rules.empty()) {
        m_logger.Warning(m_name, "No YARA rules loaded, skipping analysis");
        result.shouldBlock = FALSE;
        return TRUE;
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

    // Close the file handle as YARA will open it again
    CloseHandle(hFile);

    // Prepare result
    result.shouldBlock = FALSE;
    result.moduleName = m_name;
    result.reason = "";
    result.detections.clear();


    // Prepare callback data
    YaraCallbackData callbackData;
    callbackData.result = &result;
    callbackData.module = this;

    // Scan with each rule set
    BOOL scanSuccess = TRUE;
    for (auto rules : m_rules) {
        int scanResult = yr_rules_scan_file(
            rules,
            filePath.c_str(),
            0, // No flags
            YaraCallbackFunction, // This should now match the expected type
            &callbackData,
            0  // No timeout
        );

        if (scanResult != ERROR_SUCCESS /*Scan failed*/
            && scanResult != ERROR_TOO_MANY_MATCHES /*Not duo too many matches*/)
        {
            m_logger.Error(m_name, "Error scanning file: " + filePath +
                ", Error: " + std::to_string(scanResult));
            scanSuccess = FALSE;
        }

        // If we already have enough detections to block, stop scanning
        if (result.shouldBlock && m_blockOnDetection) {
            break;
        }

        if (!result.detections.empty() && m_blockOnDetection)
        {
            result.shouldBlock = TRUE;
            result.reason = "YARA rule matches detected";

            std::string detailsLog = "Blocking file: " + filePath + ", Detections: ";
            for (const auto& detection : result.detections) {
                detailsLog += detection + ", ";
            }
            m_logger.Warning(m_name, detailsLog);
        }
        else {
            m_logger.Info(m_name, "File scan completed: " + filePath + ", Verdict: " + (result.shouldBlock ? "BLOCK" : "ALLOW"));
        }
    }

    return scanSuccess;
}

BOOL YaraModule::InitializeYaraLibrary()
{
    // Initialize YARA library
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        m_logger.Error(m_name, "Failed to initialize YARA library: " + std::to_string(result));
        return FALSE;
    }

    return TRUE;
}

void YaraModule::CleanupYaraLibrary() {
    // Destroy all loaded rules
    for (auto rules : m_rules) {
        yr_rules_destroy(rules);
    }
    m_rules.clear();

    // Finalize YARA library
    yr_finalize();
}

BOOL YaraModule::LoadRulesFromDirectory(const std::string& directoryPath)
{
    m_logger.Info(m_name, "Loading YARA rules from directory: " + directoryPath);

    // Check if directory exists
    DWORD attributes = GetFileAttributesA(directoryPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES /* If invalid*/
        || !(attributes & FILE_ATTRIBUTE_DIRECTORY) /* OR is not a directory*/) {
        m_logger.Error(m_name, "Directory does not exist: " + directoryPath);
        return FALSE;
    }

    // Create search path
    std::string searchPath = directoryPath;
    if (searchPath.back() != '\\' && searchPath.back() != '/') {
        searchPath += '\\';
    }

    searchPath += "*";

    // Find all files in directory
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Failed to enumerate directory: " + directoryPath +
            ", Error: " + std::to_string(error));
        return FALSE;
    }

    BOOL success = TRUE;
    DWORD ruleCount = 0;


    // Loop over all entires in the rules directory and load them
    do {
        // Skip directories
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        // Check file extension
        std::string fileName = findData.cFileName;
        std::string extension;

        size_t dotPos = fileName.find_last_of('.');
        if (dotPos != std::string::npos) {
            extension = fileName.substr(dotPos);
            // Convert to lowercase
            for (auto& c : extension) {
                c = tolower(c);
            }
        }
        else {
            // No extension, skip
            continue;
        }

        // Process YARA rule files
        if (extension == ".yar" || extension == ".yara") {
            std::string fullPath = directoryPath;
            if (fullPath.back() != '\\' && fullPath.back() != '/') {
                fullPath += '\\';
            }
            fullPath += fileName;

            if (LoadRulesFromFile(fullPath)) {
                ruleCount++;
            }
            else {
                success = FALSE;
            }
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    if (ruleCount > 0) {
        m_logger.Info(m_name, "Successfully loaded " + std::to_string(ruleCount) +
            " YARA rule files from " + directoryPath);
    }
    else {
        m_logger.Warning(m_name, "No YARA rule files found in " + directoryPath);
    }

    return success;
}

BOOL YaraModule::LoadRulesFromFile(const std::string& filePath)
{
    m_logger.Info(m_name, "Loading YARA rules from file: " + filePath);

    // Check if file exists
    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES
        || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        m_logger.Error(m_name, "File does not exist: " + filePath);
        return FALSE;
    }

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
        m_logger.Error(m_name, "Failed to open file: " + filePath +
            ", Error: " + std::to_string(error));
        return FALSE;
    }

    // Get file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Failed to get file size: " + filePath +
            ", Error: " + std::to_string(error));
        CloseHandle(hFile);
        return FALSE;
    }

    // Allocate buffer for file content
    char* buffer = (char*)HeapAlloc(GetProcessHeap(), 0, fileSize + 1);
    if (!buffer) {
        m_logger.Error(m_name, "Failed to allocate memory for file content");
        CloseHandle(hFile);
        return FALSE;
    }

    // Read file content
    DWORD bytesRead;
    BOOL readResult = ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    if (!readResult || bytesRead != fileSize) {
        DWORD error = GetLastError();
        m_logger.Error(m_name, "Failed to read file: " + filePath +
            ", Error: " + std::to_string(error));
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    // Null-terminate the buffer
    buffer[fileSize] = '\0';

    // Create YARA compiler
    YR_COMPILER* compiler = NULL;
    int result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        m_logger.Error(m_name, "Failed to create YARA compiler: " +
            std::to_string(result));
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }

    // Add source to compiler
    result = yr_compiler_add_string(compiler, buffer, m_namespace.c_str());
    HeapFree(GetProcessHeap(), 0, buffer);

    if (result > 0) {
        m_logger.Error(m_name, "Errors found in YARA rules file: " + filePath);
        yr_compiler_destroy(compiler);
        return FALSE;
    }

    // Get compiled rules
    YR_RULES* rules = NULL;
    result = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    if (result != ERROR_SUCCESS) {
        m_logger.Error(m_name, "Failed to compile YARA rules: " +
            std::to_string(result));
        return FALSE;
    }

    // Add rules to list
    m_rules.push_back(rules);

    // Count rules for logging
    DWORD ruleCount = 0;
    YR_RULE* rule;
    yr_rules_foreach(rules, rule) {
        ruleCount++;
    }

    m_logger.Info(m_name, "Successfully loaded " + std::to_string(ruleCount) +
        " rules from " + filePath);

    return TRUE;
}

int
YaraModule::YaraCallbackFunction(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    Logger& logger = Logger::GetInstance();

    // Only process match messages
    if (message != CALLBACK_MSG_RULE_MATCHING) {
        return CALLBACK_CONTINUE;
    }

    YaraCallbackData* callbackData = (YaraCallbackData*)user_data;
    if (!callbackData || !callbackData->result) {
        return CALLBACK_ERROR;
    }

    YR_RULE* rule = (YR_RULE*)message_data;

    // Create detection string
    std::string detection = rule->identifier;

    // Add namespace if available
    if (rule->ns->name) {
        detection += " [" + std::string(rule->ns->name) + "]";
    }

    // Add metadata if available
    YR_META* meta;
    yr_rule_metas_foreach(rule, meta)
    {
        if (strcmp(meta->identifier, "description") == 0
            && meta->type == META_TYPE_STRING)
        {
            detection += ": " + std::string(meta->string);
            break;
        }
    }

    // Add matched strings information using the context parameter
    YR_STRING* string;
    yr_rule_strings_foreach(rule, string)
    {
        YR_MATCH* match;
        yr_string_matches_foreach(context, string, match) {
            // Now we can access match data through the context
            detection += " (match at offset: " + std::to_string(match->offset) + ")";
            break; // Just include the first match for brevity
        }
    }

    // Add to detections list
    callbackData->result->detections.push_back(detection);

    // Log detection
    logger.Warning(callbackData->module->GetName(), "YARA rule match: " + detection);


    return CALLBACK_CONTINUE;
}