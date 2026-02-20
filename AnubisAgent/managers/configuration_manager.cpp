#include "configuration_manager.h"
#include "logger.h"
#include <sstream>
#include <iostream>
#include <fstream>
#include <filesystem>

ConfigurationManager::ConfigurationManager() :
	m_logger(Logger::GetInstance())
{}

ConfigurationManager::~ConfigurationManager()
{
	// Save configuration on destruction
	SaveConfiguration();
}

bool ConfigurationManager::LoadConfiguration(const std::string& configPath)
{
	std::lock_guard<std::mutex> lock(m_configMutex);

	// If configPath is empty, use the previously loaded path
	if (!configPath.empty()) {
		m_configPath = configPath;
	}

	// Check if the configuration path is set
	if (m_configPath.empty()) {
		m_logger.Error("ConfigManager", "No configuration path specified");
		return false;
	}

	// Clear existing configuration
	m_configurations.clear();

	// Read the INI file
	bool success = ReadIniFile(m_configPath);

	if (success)
	{
		m_logger.Info("ConfigManager", "Configuration loaded successfully from: " + m_configPath);
	}
	else {
		m_logger.Error("ConfigManager", "Failed to load configuration from: " + m_configPath);
	}

	return success;
}

bool ConfigurationManager::ReadIniFile(const std::string& filePath)
{
	// First, open and read the file to check basic access
	std::ifstream file(filePath);
	if (!file.is_open()) {
		DWORD error = GetLastError();
		m_logger.Error("ConfigManager", "Cannot open file: " + filePath + ", Error: " + std::to_string(error));
		return false;
	}
	file.close();

	// Buffer for section names
	size_t sectionNameSize = 8192; // 8KB buffer for section names
	char* sectionNames = reinterpret_cast<char*>(new char[sectionNameSize]);

	// Get all section names
	DWORD sectionResult = GetPrivateProfileSectionNamesA(
		sectionNames,
		sectionNameSize,
		filePath.c_str()
	);

	// Validate results
	if (sectionResult == 0 ||
		sectionResult >= sectionNameSize - 2)
	{
		DWORD error = GetLastError();
		m_logger.Error("ConfigManager", "Failed to read section names from: " + filePath + ", Error: " + std::to_string(error));
		return false;
	}

	// Process each section
	char* section = sectionNames;
	size_t sectionSize = 16384;
	// Buffer for section keys and values
	char* sectionData = reinterpret_cast<char*>(new char[sectionSize]);

	while (*section) 
	{
		std::string sectionName = section;
		RtlZeroMemory(sectionData, sectionSize);

		// Get all keys and values for this section
		DWORD keyResult = GetPrivateProfileSectionA(
			section,
			sectionData,
			sectionSize,
			filePath.c_str()
		);

		if (keyResult == 0 ||
			keyResult >= sectionSize - 2)
		{
			DWORD error = GetLastError();
			m_logger.Warning("ConfigManager", "Failed to read section data for: " + sectionName + ", Error: " + std::to_string(error));
			section += strlen(section) + 1;
			continue;
		}

		// Now parse the section using our helper method
		// Convert the char array to a string - note that sectionData contains multiple
		// null-terminated strings, so we need to handle this specially
		ParseIniSection(sectionName, sectionData, keyResult);

		section += strlen(section) + 1;
	}
	delete[] sectionData;
	delete[] sectionNames;

	return true;
}

bool ConfigurationManager::ParseIniSection(const std::string& sectionName, const char* sectionData, DWORD dataLength)
{
	// Initialize the section in our configurations map if it doesn't exist
	if (m_configurations.find(sectionName) == m_configurations.end()) {
		m_configurations[sectionName] = std::map<std::string, std::string>();
	}

	// The buffer from GetPrivateProfileSectionA contains null-terminated strings
	// followed by an additional null character at the end
	const char* data = sectionData;
	const char* dataEnd = sectionData + dataLength;
	while (data < dataEnd && *data)
	{
		std::string line = data;
		size_t delimPos = line.find('=');
		if (delimPos == std::string::npos)
		{
			// No equals sign found, ignore this line
			m_logger.Warning("ConfigManager", "Invalid configuration line in section " + sectionName + ": " + line);
		}
		else {
			std::string key = line.substr(0, delimPos);
			std::string value = line.substr(delimPos + 1);

			// Trim whitespace if needed
			key.erase(0, key.find_first_not_of(" \t"));
			key.erase(key.find_last_not_of(" \t") + 1);

			// Store in the configuration map
			m_configurations[sectionName][key] = value;
		}

		// Move to the next null-terminated string
		data += strlen(data) + 1;
	}

	return true;
}

std::vector<std::string> ConfigurationManager::GetSectionNames()
{
	std::lock_guard<std::mutex> lock(m_configMutex);

	std::vector<std::string> sectionNames;
	sectionNames.reserve(m_configurations.size());

	for (const auto& section : m_configurations) {
		sectionNames.push_back(section.first);
	}

	return sectionNames;
}

bool ConfigurationManager::SetGlobalConfig(const std::string& key, const std::string& value)
{
	std::lock_guard<std::mutex> lock(m_configMutex);

	// Create Global section if it doesn't exist
	if (m_configurations.find("Global") == m_configurations.end()) {
		m_configurations["Global"] = std::map<std::string, std::string>();
	}

	m_configurations["Global"][key] = value;
	m_logger.Info("ConfigManager", "Updated global configuration key: " + key);
	return true;
}

std::string ConfigurationManager::GetGlobalConfig(const std::string& key) 
{
	std::lock_guard<std::mutex> lock(m_configMutex);

	auto globalIt = m_configurations.find("Global");
	if (globalIt != m_configurations.end()) {
		auto keyIt = globalIt->second.find(key);
		if (keyIt != globalIt->second.end()) {
			return keyIt->second;
		}
	}

	return std::string();
}

std::map<std::string, std::string> ConfigurationManager::GetServiceConfig(const std::string& serviceName) 
{
	std::lock_guard<std::mutex> lock(m_configMutex);

	auto it = m_configurations.find(serviceName);
	if (it != m_configurations.end()) {
		return it->second;
	}

	// Return empty map if not found
	return std::map<std::string, std::string>();
}

bool ConfigurationManager::SetServiceConfig(
	const std::string& serviceName,
	const std::map<std::string, std::string>& config)
{
	std::lock_guard<std::mutex> lock(m_configMutex);
	m_configurations[serviceName] = config;
	m_logger.Info("ConfigManager", "Updated configuration for service: " + serviceName);
	return true;
}

bool ConfigurationManager::SaveConfiguration(const std::string& configPath)
{
	std::lock_guard<std::mutex> lock(m_configMutex);

	// If configPath is empty, use the previously loaded path
	std::string savePath = configPath.empty() ? m_configPath : configPath;

	if (savePath.empty())
	{
		m_logger.Error("ConfigManager", "No configuration path specified for saving");
		return false;
	}

	// Make sure directory exists
	std::filesystem::path filePath(savePath);
	std::filesystem::path directory = filePath.parent_path();

	if (!directory.empty() &&
		!std::filesystem::exists(directory))
	{
		try {
			std::filesystem::create_directories(directory);
		}
		catch (const std::exception& e) {
			m_logger.Error("ConfigManager", "Failed to create directory: " + directory.string() + ", Error: " + e.what());
			return false;
		}
	}

	// First ensure the file exists
	std::ofstream createFile(savePath, std::ios::out | std::ios::app);
	if (!createFile.is_open()) 
	{
		DWORD error = GetLastError();
		m_logger.Error("ConfigManager", "Failed to create/open file: " + savePath + ", Error: " + std::to_string(error));
		return false;
	}
	createFile.close();

	// Write each section and its keys
	for (const auto& section : m_configurations) {
		for (const auto& keyValue : section.second) {
			if (!WritePrivateProfileStringA(
				section.first.c_str(),
				keyValue.first.c_str(),
				keyValue.second.c_str(),
				savePath.c_str()))
			{
				DWORD error = GetLastError();
				m_logger.Error("ConfigManager", "Failed to write key '" + keyValue.first + "' in section '" + section.first + "', Error: " + std::to_string(error));
				return false;
			}
		}
	}

	m_logger.Info("ConfigManager", "Configuration saved successfully to: " + savePath);
	return true;
}