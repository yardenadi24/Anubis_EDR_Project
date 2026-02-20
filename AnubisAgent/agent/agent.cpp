#include "agent.h"

AnubisAgent::AnubisAgent()
    : m_isRunning(false),
    m_Logger(Logger::GetInstance())
{
    // Create core components
    m_configManager = std::make_unique<ConfigurationManager>();
    m_serviceManager = std::make_unique<ServiceManager>(m_configManager.get());
}

AnubisAgent::~AnubisAgent() {
    Stop();
}

bool AnubisAgent::Initialize(const std::string& configPath)
{
    // First, load the configuration
    m_Logger.Info("Agent", "Loading configuration from: " + configPath);
    if (!m_configManager->LoadConfiguration(configPath))
    {
        m_Logger.Error("Agent", "Failed to load configuration from " + configPath);
        return false;
    }

    // Now configure the logger properly using the settings from config
    std::string logPath = m_configManager->GetGlobalConfig("LogPath");
    if (logPath.empty())
        logPath = "C:\\ProgramData\\Anubis\\Logs";

    std::string logLevelStr = m_configManager->GetGlobalConfig("LogLevel");
    if (logLevelStr.empty())
        logLevelStr = "INFO";

    // Convert log level string to enum
    Logger::LogLevel logLevel = Logger::LogLevel::LOG_INFO; // Default
    if (logLevelStr == "DEBUG") {
        logLevel = Logger::LogLevel::LOG_DEBUG;
    }
    else if (logLevelStr == "WARNING") {
        logLevel = Logger::LogLevel::LOG_WARNING;
    }
    else if (logLevelStr == "ERROR") {
        logLevel = Logger::LogLevel::LOG_ERROR;
    }
    else if (logLevelStr == "CRITICAL") {
        logLevel = Logger::LogLevel::LOG_CRITICAL;
    }
    else if (logLevelStr == "NOTICE") {
        logLevel = Logger::LogLevel::LOG_NOTICE;
    }

    // Initialize the logger with the configured settings
    // We need to place this in a separate block to avoid deadlock with m_LogMutex
    {
        if (!m_Logger.Initialize(logPath, logLevel)) {
            std::cerr << "Failed to initialize logging system at path: " << logPath << std::endl;
            return false;
        }
    }

    m_Logger.Info("Agent", "Initializing Anubis EDR Agent");
    m_Logger.Info("Agent", "Configuration loaded from: " + configPath);
    m_Logger.Info("Agent", "Using log path: " + logPath);
    m_Logger.Info("Agent", "Log level set to: " + logLevelStr);

    return true;
}

bool AnubisAgent::Start()
{
    std::lock_guard<std::mutex> lock(m_agentMutex);

    if (m_isRunning) {
        m_Logger.Warning("Agent", "Agent is already running");
        return false;
    }

    m_Logger.Info("Agent", "Starting Anubis EDR Agent");

    // Start all registered services
    if (!m_serviceManager->StartAllServices()) {
        m_Logger.Error("Agent", "Failed to start all services");
        return false;
    }

    m_isRunning = true;
    m_mainThread = std::thread(&AnubisAgent::MainThreadProc, this);

    m_Logger.Info("Agent", "Anubis EDR Agent started successfully");
    return true;
}

void AnubisAgent::Stop()
{
    std::lock_guard<std::mutex> lock(m_agentMutex);

    if (!m_isRunning) {
        m_Logger.Warning("Agent", "Agent is not running");
        return;
    }

    m_Logger.Info("Agent", "Stopping Anubis EDR Agent");

    m_isRunning = false;

    //Stop all registered services
    m_serviceManager->StopAllServices();

    // Wait for main thread to finish
    if (m_mainThread.joinable())
    {
        m_mainThread.join();
    }

    m_Logger.Info("Agent", "Anubis EDR Agent stopped successfully");
}

bool AnubisAgent::ReloadConfiguration()
{
    m_Logger.Info("Agent", "Reloading configuration");

    if (!m_configManager->LoadConfiguration(""))
    {
        m_Logger.Error("Agent", "Failed to reload configuration");
        return false;
    }

    // Notify all services about the configuration change
    auto serviceNames = m_serviceManager->GetAllServiceNames();
    for (const auto& serviceName : serviceNames)
    {
        auto config = m_configManager->GetServiceConfig(serviceName);
        m_serviceManager->ConfigureService(serviceName, config);
    }

    m_Logger.Info("Agent", "Configuration reloaded successfully");
    return true;
}


void AnubisAgent::MainThreadProc()
{
    m_Logger.Info("Agent", "Main thread started");

    while (m_isRunning)
    {
        // Main agent loop
        // Perform periodic tasks (health checks, etc.)
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    m_Logger.Info("Agent", "Main thread exiting");
}
