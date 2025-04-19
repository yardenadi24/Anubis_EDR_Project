#include <iostream>
#include <string>
#include <csignal>

#include "agent/agent.h"

#include "services/IService.h"
#include "services/process_monitor/ProcessMonitorService.h"
#include "services/anti_malware/AntiMalwareService.h"
#include "services/security_event/SecurityEventService.h"
#include "services/event_persistence/EventPersistenceService.h"



#include "managers/service_manager/ServiceManager.h"

#include "modules/security_modules/yara_analysis/YaraModule.h"
#include "modules/security_modules/yara_analysis/YaraModule.h"
#include "modules/security_modules/verdict_db_analysis/VerdictDbModule.h"

#include <thread> // For std::this_thread

AnubisAgent* g_agent = nullptr;

void SignalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nReceived termination signal. Shutting down..." << std::endl;
        if (g_agent) {
            g_agent->Stop();
        }
    }
}

void PrintUsage() {
    std::cout << "Anubis EDR Agent - Modular Security Framework\n";
    std::cout << "Usage: AnubisAgent.exe [config_file]\n";
    std::cout << "  config_file: Path to configuration file (optional)\n";
    std::cout << "Commands:\n";
    std::cout << "  help        - Show this help\n";
    std::cout << "  exit        - Exit the application\n";
    std::cout << "  reload      - Reload configuration file\n";
    std::cout << "  status      - Show agent status\n";
    std::cout << "  services    - List all services\n";
    std::cout << "  start [svc] - Start a specific service\n";
    std::cout << "  stop [svc]  - Stop a specific service\n";
    std::cout << "  modules     - List all security modules\n";
    std::cout << "  stats       - Show anti-malware statistics\n";
}

int main(int argc, char* argv[])
{
    std::string configFile = "C:\\ProgramData\\Anubis\\Config\\anubis_config.ini";

    // Override config file if provided
    if (argc > 1) {
        configFile = argv[1];
    }

    // Set up signal handling for graceful shutdown
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    // Initialize logger
    Logger& logger = Logger::GetInstance();

    // Create the agent
    g_agent = new AnubisAgent();

    // Initialize agent
    if (!g_agent->Initialize(configFile)) {
        std::cerr << "Failed to initialize agent. Exiting." << std::endl;
        delete g_agent;
        return 1;
    }

    // Create and register services
    auto serviceManager = g_agent->GetServiceManager();

    // Create and register EventPersistenceService
    auto eventPersistenceService = std::make_shared<EventPersistenceService>();
    serviceManager->RegisterService(eventPersistenceService);

    // Create and register SecurityEventService
    auto securityEventService = std::make_shared<SecurityEventService>();
    serviceManager->RegisterService(securityEventService);

    // Create and register ProcessMonitorService
    auto processMonitorService = std::make_shared<ProcessMonitorService>();
    serviceManager->RegisterService(processMonitorService);

    // Create and register VerdictDbService
    auto verdictDbService = std::make_shared<VerdictDbService>();
    serviceManager->RegisterService(verdictDbService);


    auto yaraModule = std::make_shared<YaraModule>();

    auto verdictDbModule = std::make_shared<VerdictDbModule>();
    verdictDbModule->SetVerdictDbService(verdictDbService);

    // Create and register AntiMalwareService
    auto antiMalwareService = std::make_shared<AntiMalwareService>(serviceManager);
    serviceManager->RegisterService(antiMalwareService);

    // Register security modules
    antiMalwareService->RegisterModule(yaraModule);
    antiMalwareService->RegisterModule(verdictDbModule);

    // Additional modules will be registered here
    // antiMalwareService->RegisterModule(std::make_shared<BehaviorModule>());
    // antiMalwareService->RegisterModule(std::make_shared<HashLookupModule>());

    // Start the agent
    if (!g_agent->Start()) {
        std::cerr << "Failed to start agent. Exiting." << std::endl;
        delete g_agent;
        return 1;
    }

    // Simple command interface
    std::string command;
    bool running = true;

    PrintUsage();

    while (running)
    {
        std::cout << "\nAnubis> ";
        std::getline(std::cin, command);

        if (command == "exit") {
            running = false;
        }
        else if (command == "help") {
            PrintUsage();
        }
        else if (command == "reload") {
            g_agent->ReloadConfiguration();
        }
        else if (command == "status") {
            std::cout << "Agent is running.\n";
            std::cout << "Using config file: " << configFile << std::endl;
        }
        else if (command == "services")
        {
            auto services = serviceManager->GetAllServiceNames();
            std::cout << "Registered services:\n";
            for (const auto& name : services) {
                auto service = serviceManager->GetService(name);
                std::string state;
                switch (service->GetState()) {
                case IService::ServiceState::STOPPED: state = "STOPPED"; break;
                case IService::ServiceState::STARTING: state = "STARTING"; break;
                case IService::ServiceState::RUNNING: state = "RUNNING"; break;
                case IService::ServiceState::STOPPING: state = "STOPPING"; break;
                case IService::ServiceState::FAILED: state = "FAILED"; break;
                default: state = "UNKNOWN";
                }
                std::cout << " - " << name << " [" << state << "]\n";
            }
        }
        else if (command.find("start ") == 0) {
            std::string serviceName = command.substr(6);
            if (!serviceName.empty()) {
                serviceManager->StartService(serviceName);
			}
			else {
				std::cout << "Please specify a service name to start." << std::endl;
			}
        }
        else if (command == "modules") {
            // Display registered security modules
            auto service = dynamic_cast<AntiMalwareService*>(
                serviceManager->GetService("AntiMalware").get());

            if (service) {
                auto moduleNames = service->GetModuleNames();
                std::cout << "Registered security modules:\n";
                for (const auto& name : moduleNames) {
                    std::cout << " - " << name << "\n";
                }
                if (moduleNames.empty()) {
                    std::cout << " - No modules registered\n";
                }
            }
            else {
                std::cout << "AntiMalware service not available\n";
            }
        }
        else if (command == "stats") {
            // Display anti-malware statistics
            auto service = dynamic_cast<AntiMalwareService*>(
                serviceManager->GetService("AntiMalware").get());

            if (service) {
                std::cout << "Anti-Malware Statistics:\n";
                std::cout << " - Total scans: " << service->GetTotalScans() << "\n";
                std::cout << " - Total blocked: " << service->GetTotalBlockedFiles() << "\n";

                if (service->GetTotalScans() > 0) {
                    double blockRate = static_cast<double>(service->GetTotalBlockedFiles()) /
                        service->GetTotalScans() * 100.0;
                    std::cout << " - Block rate: " << blockRate << "%\n";
                }
            }
            else {
                std::cout << "AntiMalware service not available\n";
            }
        }
        else if (!command.empty()) {
            std::cout << "Unknown command. Type 'help' for available commands." << std::endl;
        }
    }

    // Stop the agent before exiting
    g_agent->Stop();
    delete g_agent;

    return 0;
}