#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <map>

enum class SecurityEventSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct SecurityEvent {
    std::string id;                      // Unique ID for the event (e.g., AFX-123456)
    std::string source;                  // Service that generated the event
    std::string type;                    // Type of event (e.g., "MALWARE_DETECTED")
    std::string description;             // Human-readable description
    std::string details;                 // Additional details
    std::string filePath;                // File path that triggered the event
    std::string fileName;                // File name that triggered the event
    std::string publisher;               // Publisher information if available
    SecurityEventSeverity severity;      // Severity level
    std::chrono::system_clock::time_point timestamp; // When the event occurred
    std::map<std::string, std::string> metadata; // Additional metadata
    bool shouldAlert;                    // Whether to alert the user
};