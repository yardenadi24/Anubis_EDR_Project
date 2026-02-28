#pragma once
#include "shared_commons.h"
#include <chrono>
#include <map>

// Callback function type for anti-malware scanning
typedef void (*ScanResultCallback)(bool verdict, void* context);

// Security event severity levels
enum class SecurityEventSeverity {
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Security event structure
class SecurityEvent {
public:
    SecurityEvent()
        : severity(SecurityEventSeverity::INFO),
        timestamp(std::chrono::system_clock::now()),
        shouldAlert(false)
    {
    }
    std::string id;                                      // Unique event identifier
    std::string source;                                  // Event source (e.g., "FileSystem", "Process", "Network")
    std::string type;                                    // Event type (e.g., "FileCreated", "ProcessStarted")
    std::string description;                             // Human-readable description
    std::string details;                                 // Detailed information about the event
    std::string filePath;                                // File path if applicable
    std::string fileName;                                // File name if applicable
    std::string publisher;                               // Publisher/source application
    bool shouldAlert;                                    // Whether to show an alert for this event
    SecurityEventSeverity severity;                      // Event severity level
    std::chrono::system_clock::time_point timestamp;     // Event timestamp
    std::map<std::string, std::string> metadata;         // Additional metadata
};
