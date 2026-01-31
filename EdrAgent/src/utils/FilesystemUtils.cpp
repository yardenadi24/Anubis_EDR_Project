#include "FilesystemUtils.h"
#include "Logger.h"

// Helper function to create directory path recursively using Windows API
bool CreateDirectoryPath(const std::string& path, const std::string& namesapce) {

    Logger& logger = Logger::GetInstance();

    // Normalize the path (replace forward slashes with backslashes)
    std::string normalizedPath = path;
    for (char& c : normalizedPath) {
        if (c == '/') c = '\\';
    }

    // Check if the directory already exists
    DWORD attrs = GetFileAttributesA(normalizedPath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return true; // Directory already exists
    }


    size_t pos = 0;
    std::string currentPath;

    // Iteratively create each directory component
    while ((pos = normalizedPath.find('\\', pos)) != std::string::npos) {

        // Extract the current directory path
        currentPath = normalizedPath.substr(0, pos);

        // Skip empty segments
        if (currentPath.empty()) {
            pos++;
            continue;
        }

        // Create the directory
        if (!CreateDirectoryA(currentPath.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            DWORD error = GetLastError();
            logger.Error(namesapce, "Failed to create directory: " + currentPath + ", Error: " + std::to_string(error));
            return false;
        }

        pos++;
    }

    // Create the final directory
    if (!CreateDirectoryA(normalizedPath.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        DWORD error = GetLastError();
        logger.Error(namesapce, "Failed to create directory: " + normalizedPath + ", Error: " + std::to_string(error));
        return false;
    }

    return true;
}