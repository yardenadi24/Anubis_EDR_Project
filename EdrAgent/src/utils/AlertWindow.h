// AlertWindow.h
#pragma once
#include <Windows.h>
#include <string>
#include <thread>
#include <functional>
#include "SecurityEvent.h"

class AlertWindow {
private:
    static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    HWND m_hwnd;
    HINSTANCE m_hInstance;
    HICON m_hIcon;
    ULONG_PTR m_gdiplusToken;
    bool m_showDetails;

    // Event data
    std::wstring m_mainMessage;
    std::wstring m_appName;
    std::wstring m_publisher;
    std::wstring m_description;
    std::wstring m_details;

    // Window parameters
    static constexpr int WINDOW_WIDTH = 600;
    static constexpr int CONTENT_HEIGHT_COLLAPSED = 200;
    static constexpr int CONTENT_HEIGHT_EXPANDED = 360;
    static constexpr int PADDING = 20;
    static constexpr int TITLE_FONT_SIZE = 22;
    static constexpr int TEXT_FONT_SIZE = 14;
    static constexpr int FOOTER_HEIGHT = 30;
    static constexpr int BUTTON_HEIGHT = 30;
    static constexpr int WINDOW_FRAME_HEIGHT = 38;

    static constexpr LPCWSTR WINDOW_CLASS = L"AnubisAlertWindow";
    static constexpr LPCWSTR APP_TITLE = L"Anubis EDR Prevention Alert";
    static constexpr LPCWSTR FOOTER_TEXT = L"Please contact your security team for more information.";

    // Control IDs
    enum ControlIDs {
        ID_BTN_OK = 1,
        ID_BTN_TOGGLE_DETAILS
    };

    void ToggleDetails();
    void OnPaint(HDC hdc);
    void RegisterWindowClass();

public:
    AlertWindow(HINSTANCE hInstance);
    ~AlertWindow();

    bool Initialize();
    void Shutdown();
    void Show(const SecurityEvent& event);
    static std::wstring ToWideString(const std::string& str);

    // Use this to run an alert window from any thread
    static void ShowAlertDialog(const SecurityEvent& event);
};