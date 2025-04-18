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

class Logger {
public:
    enum class LogLevel {
        LOG_DEBUG,
        LOG_INFO,
        LOG_WARNING,
        LOG_ERROR,
        LOG_CRITICAL
    };


    // Delete copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    ~Logger();

private:
    Logger();

    static std::mutex s_instanceMutex;

    std::string m_LogPath;
    LogLevel m_LogLevel;
    std::mutex m_LogMutex;
    HANDLE m_hLogFile;
    const std::string m_name = "Logger";

    // Helper method
    std::string LogLevelToString(LogLevel level);
    bool CreateLogDirectory(const std::string& path);

public:

    // Singleton access methods
    static Logger& GetInstance();

    bool Initialize(const std::string& logPath, LogLevel level = LogLevel::LOG_INFO);
    void Log(LogLevel level, const std::string& service, const std::string& message);
    void SetLogLevel(LogLevel level);

    // Helper logging methods
    void Debug(const std::string& service, const std::string& message);
    void Info(const std::string& service, const std::string& message);
    void Warning(const std::string& service, const std::string& message);
    void Error(const std::string& service, const std::string& message);
    void Critical(const std::string& service, const std::string& message);
};
