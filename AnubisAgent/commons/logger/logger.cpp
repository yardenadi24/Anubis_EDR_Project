#include <chrono>
#include <sstream>

#include "Logger.h"
#include "filesystem_utils.h"

// Private constructor for singleton pattern
Logger::Logger() : 
    m_log_level(LogLevel::LOG_INFO),
    m_log_file_handle(INVALID_HANDLE_VALUE)
{}

Logger::~Logger() {
    if (m_log_file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_log_file_handle);
        m_log_file_handle = INVALID_HANDLE_VALUE;
    }
}

// Get singleton instance
Logger& Logger::GetInstance() {
    static Logger s_logger;
    return s_logger;
}

bool Logger::CreateLogDirectory(const std::string& path)
{
    bool ret = CreateDirectoryPath(path, m_name);

    if (!ret)
    {
        std::cerr << "Failed to create logger directory" << std::endl;
    }

    return ret;
}

bool Logger::Initialize(const std::string& log_path, LogLevel level)
{
    {
        std::lock_guard<std::mutex> lock(m_log_mutex);

        m_log_level = level;
        m_log_path = log_path;

        // Create log directory if it doesn't exist
        if (!CreateLogDirectory(m_log_path)) {
            return false;
        }

        // Create log filename with timestamp
        time_t time_t_now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm tm_now;
        localtime_s(&tm_now, &time_t_now);

        char timeBuffer[32];
        strftime(timeBuffer, sizeof(timeBuffer), DATE_TIME_FORMAT, &tm_now);

        std::string fileName = log_path + "\\anubis_" + timeBuffer + ".log";

        m_log_file_handle = CreateFileA(
            fileName.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (m_log_file_handle == INVALID_HANDLE_VALUE)
        {
            DWORD error = GetLastError();
            std::cerr << "Failed to open log file: " << fileName << ", Error: " << error << std::endl;
            return false;
        }
    }

    // Log initialization message
    Log(LogLevel::LOG_INFO, "Logger", "Logger initialized");
    return true;
}

void Logger::SetLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(m_log_mutex);
    m_log_level = level;
    Log(LogLevel::LOG_INFO, "Logger", "Log level changed to " + LogLevelToString(level));
}

void Logger::Log(LogLevel level, const std::string& service, const std::string& message)
{
    // Only log if the level is sufficient
    if (level > m_log_level) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_log_mutex);

    // Get current time
    auto time_t_now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm_now;
    localtime_s(&tm_now, &time_t_now);

    char timeBuffer[32];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &tm_now);

    std::ostringstream logEntry;
    logEntry << timeBuffer << " ["
        << LogLevelToString(level) << "] ["
        << service << "] "
        << message
        << "\r\n";  // Windows-style line ending

    std::string logStr = logEntry.str();

    // Write to file if open
    if (m_log_file_handle != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        WriteFile(
            m_log_file_handle,
            logStr.c_str(),
            static_cast<DWORD>(logStr.length()),
            &bytesWritten,
            NULL
        );
        // Flush to disk
        FlushFileBuffers(m_log_file_handle);
    }
    else {
        //std::cerr << "[Logger handle is invalid] " << std::endl;
    }
}

void Logger::Debug(const std::string& service, const std::string& message) {
    Log(LogLevel::LOG_DEBUG, service, message);
}

void Logger::Info(const std::string& service, const std::string& message) {
    Log(LogLevel::LOG_INFO, service, message);
}

void Logger::Warning(const std::string& service, const std::string& message) {
    Log(LogLevel::LOG_WARNING, service, message);
}

void Logger::Error(const std::string& service, const std::string& message) {
    Log(LogLevel::LOG_ERROR, service, message);
}

void Logger::Critical(const std::string& service, const std::string& message) {
    Log(LogLevel::LOG_CRITICAL, service, message);
}
void Logger::Notice(const std::string& service, const std::string& message) {
    Log(LogLevel::LOG_NOTICE, service, message);
}

// Helper method to convert LogLevel to string
std::string Logger::LogLevelToString(LogLevel level) {
    switch (level) {
    case LogLevel::LOG_DEBUG:    return "DEBUG";
    case LogLevel::LOG_INFO:     return "INFO";
    case LogLevel::LOG_WARNING:  return "WARNING";
    case LogLevel::LOG_ERROR:    return "ERROR";
    case LogLevel::LOG_CRITICAL: return "CRITICAL";
    default:                     return "UNKNOWN";
    }
}
