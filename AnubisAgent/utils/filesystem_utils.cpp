#include "filesystem_utils.h"
#include "logger.h"

// Helper function to create directory path recursively using Windows API
bool CreateDirectoryPath(const std::string& path, const std::string& namesapce)
{
    // Normalize the path (replace forward slashes with backslashes)
    std::string normalized_path = path;
    for (char& c : normalized_path) {
        if (c == '/') c = '\\';
    }

    // Check if the directory already exists
    DWORD attrs = GetFileAttributesA(normalized_path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return true; // Directory already exists
    }

    size_t pos = 0;
    std::string current_path;

    // Iteratively create each directory component
    while ((pos = normalized_path.find('\\', pos)) != std::string::npos)
    {

        // Extract the current directory path
        current_path = normalized_path.substr(0, pos);

        // Skip empty segments
        if (current_path.empty()) {
            pos++;
            continue;
        }

        // Create the directory
        if (!CreateDirectoryA(current_path.c_str(), NULL) 
            && GetLastError() != ERROR_ALREADY_EXISTS)
        {
            DWORD error = GetLastError();
            return false;
        }

        pos++;
    }

    // Create the final directory
    if (!CreateDirectoryA(normalized_path.c_str(), NULL) 
        && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        DWORD error = GetLastError();
        return false;
    }

    return true;
}