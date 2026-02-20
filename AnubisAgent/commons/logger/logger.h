#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <fstream>
#include <Windows.h>

#define DATE_TIME_FORMAT "%Y-%m-%d_%H-%M-%S"

// Singleton Logger class for thread-safe logging
class Logger {

public:
    enum class LogLevel {
        LOG_CRITICAL,
        LOG_ERROR,
        LOG_INFO,
        LOG_DEBUG,
        LOG_WARNING,
        LOG_NOTICE
    };

    // Delete copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    ~Logger();

private:
    Logger();

    static std::mutex m_instance_mutex;

    std::string m_log_path;
    LogLevel m_log_level;
    std::mutex m_log_mutex;
	HANDLE m_log_file_handle;

    const std::string m_name = "AnubisLogger";

    // Helper method
    std::string LogLevelToString(LogLevel level);
    bool CreateLogDirectory(const std::string& path);
public:

    // Singleton access methods
    static Logger& GetInstance();

    bool Initialize(const std::string& log_path, LogLevel level = LogLevel::LOG_INFO);
    void Log(LogLevel level, const std::string& service, const std::string& message);
    void SetLogLevel(LogLevel level);

    // Helper logging methods
    void Debug(const std::string& service, const std::string& message);
    void Info(const std::string& service, const std::string& message);
    void Warning(const std::string& service, const std::string& message);
    void Error(const std::string& service, const std::string& message);
    void Critical(const std::string& service, const std::string& message);
    void Notice(const std::string& service, const std::string& message);
};