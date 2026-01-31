#pragma once
#include <Windows.h>
#include <string>

// Helper function to create directory path recursively using Windows API
bool CreateDirectoryPath(const std::string& path, const std::string& namesapce);