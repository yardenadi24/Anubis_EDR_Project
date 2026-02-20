#include "strings_utils.h"
#include "logger.h"

std::string WideToAnsi(const std::wstring& wstr, const std::string& name_space) {

    if (wstr.empty()) return std::string();

    Logger& logger = Logger::GetInstance();

    // Calculate required buffer size
    int size_needed = WideCharToMultiByte(CP_ACP, 0, wstr.data(), (int)wstr.size(),
        NULL, 0, NULL, NULL);

    if (size_needed <= 0) {
        DWORD error = GetLastError();
        logger.Error(name_space, "WideToAnsi failed to calculate buffer size, Error: " +
            std::to_string(error));
        return std::string();
    }

    // Allocate buffer using Windows API
    LPSTR buffer = (LPSTR)HeapAlloc(GetProcessHeap(), 0, size_needed + 1);
    if (!buffer) {
        DWORD error = GetLastError();
        logger.Error(name_space, "WideToAnsi failed to allocate memory, Error: " +
            std::to_string(error));
        return std::string();
    }

    // Perform the actual conversion
    int result = WideCharToMultiByte(CP_ACP, 0, wstr.data(), (int)wstr.size(),
        buffer, size_needed, NULL, NULL);

    if (result <= 0) {
        DWORD error = GetLastError();
        logger.Error(name_space, "WideToAnsi conversion failed, Error: " +
            std::to_string(error));
        HeapFree(GetProcessHeap(), 0, buffer);
        return std::string();
    }

    // Null-terminate the string
    buffer[size_needed] = '\0';

    // Create std::string and free buffer
    std::string ansiStr(buffer);
    HeapFree(GetProcessHeap(), 0, buffer);

    return ansiStr;
}