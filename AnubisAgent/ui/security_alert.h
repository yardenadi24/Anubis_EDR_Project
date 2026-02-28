#pragma once
#include <windows.h>
#include <string>
#include <mutex>
#include <atomic>
#include "commons.h"

// Data structure passed to each alert window instance
struct AlertWindowData {
    std::wstring eventId;
    std::wstring source;
    std::wstring type;
    std::wstring description;
    std::wstring details;
    std::wstring filePath;
    std::wstring fileName;
    std::wstring severityText;
    std::wstring timestamp;
    SecurityEventSeverity severityLevel;
};

class SecurityAlertWindow {
public:
    // Initialize the alert window system (call once at startup with the app HINSTANCE)
    static bool Initialize(HINSTANCE hInstance);

    // Show an alert for a security event (non-blocking, spawns its own thread)
    static void ShowAlert(const SecurityEvent& event);

    // Shutdown and cleanup
    static void Shutdown();

    // Configuration
    static void SetAutoCloseTimeoutMs(UINT timeoutMs) { s_autoCloseTimeoutMs = timeoutMs; }
    static void SetMaxConcurrentAlerts(int max) { s_maxConcurrentAlerts = max; }

private:
    // Window procedure
    static LRESULT CALLBACK AlertWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // Internal helpers
    static void RegisterWindowClass(HINSTANCE hInstance);
    static COLORREF GetSeverityColor(SecurityEventSeverity severity);
    static std::wstring GetSeverityString(SecurityEventSeverity severity);
    static std::wstring FormatTimestamp(const std::chrono::system_clock::time_point& tp);
    static std::wstring Utf8ToWide(const std::string& str);
    static AlertWindowData* CreateAlertData(const SecurityEvent& event);

    // Custom drawing
    static void PaintSeverityBanner(HDC hdc, RECT& clientRect, SecurityEventSeverity severity);

    // Static state
    static HINSTANCE s_hInstance;
    static bool s_classRegistered;
    static std::atomic<int> s_activeAlertCount;
    static int s_maxConcurrentAlerts;
    static UINT s_autoCloseTimeoutMs;
    static HFONT s_titleFont;
    static HFONT s_labelFont;
    static HFONT s_bodyFont;

    static constexpr const wchar_t* WINDOW_CLASS_NAME = L"AnubisSecurityAlertWnd";
    static constexpr int WINDOW_WIDTH = 520;
    static constexpr int WINDOW_HEIGHT = 420;
    static constexpr int TIMER_AUTO_CLOSE = 1;

    // Control IDs
    static constexpr int IDC_BTN_DISMISS = 1001;
    static constexpr int IDC_BTN_DETAILS = 1002;
};


