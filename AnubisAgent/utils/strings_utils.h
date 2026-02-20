#pragma once
#include <Windows.h>
#include <string>

std::string WideToAnsi(const std::wstring& wstr, const std::string& name_space);
