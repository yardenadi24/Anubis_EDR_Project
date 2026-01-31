// AlertWindow.cpp
#include "AlertWindow.h"
#include <windowsx.h>
#include <tchar.h>
#include <gdiplus.h>
//#include "resource.h"
#include <thread>
#include <filesystem>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

// Static method for message routing
LRESULT CALLBACK AlertWindow::StaticWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    AlertWindow* pThis = nullptr;

    if (msg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
        pThis = reinterpret_cast<AlertWindow*>(pCreate->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->m_hwnd = hwnd;
    }
    else {
        pThis = reinterpret_cast<AlertWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }

    if (pThis) {
        return pThis->WndProc(hwnd, msg, wParam, lParam);
    }
    else {
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

AlertWindow::AlertWindow(HINSTANCE hInstance)
    : m_hwnd(nullptr),
    m_hInstance(hInstance),
    m_hIcon(nullptr),
    m_gdiplusToken(0),
    m_showDetails(false)
{
}

AlertWindow::~AlertWindow() {
    Shutdown();
}

bool AlertWindow::Initialize() {
    // Initialize GDI+
    GdiplusStartupInput gdiplusStartupInput;
    if (GdiplusStartup(&m_gdiplusToken, &gdiplusStartupInput, nullptr) != Ok) {
        return false;
    }

    // Load icon
    //m_hIcon = LoadIcon(m_hInstance, MAKEINTRESOURCE(IDI_ANUBIS_ICON));
    //if (!m_hIcon) {
    //    // Try to load a default icon if the resource doesn't exist
    //    m_hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    //}

    // Register window class
    RegisterWindowClass();

    return true;
}

void AlertWindow::RegisterWindowClass() {
    WNDCLASSW wc = {};
    wc.lpfnWndProc = StaticWndProc;
    wc.hInstance = m_hInstance;
    wc.lpszClassName = WINDOW_CLASS;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hIcon = m_hIcon;

    RegisterClassW(&wc);
}

void AlertWindow::Shutdown() {
    // Clean up GDI+
    if (m_gdiplusToken != 0) {
        GdiplusShutdown(m_gdiplusToken);
        m_gdiplusToken = 0;
    }

    // Destroy icon
    if (m_hIcon) {
        DestroyIcon(m_hIcon);
        m_hIcon = nullptr;
    }

    // Unregister window class
    UnregisterClassW(WINDOW_CLASS, m_hInstance);
}

std::wstring AlertWindow::ToWideString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

void AlertWindow::Show(const SecurityEvent& event) {
    // Set up the event data
    m_mainMessage = L"Anubis EDR has detected a malicious file!";
    m_appName = ToWideString(event.fileName);
    m_publisher = ToWideString(event.publisher.empty() ? "Unknown" : event.publisher);
    m_description = ToWideString(event.description);

    // Format details
    auto time_t_now = std::chrono::system_clock::to_time_t(event.timestamp);
    std::tm tm_now;
    localtime_s(&tm_now, &time_t_now);

    char timeBuffer[64];
    strftime(timeBuffer, sizeof(timeBuffer), "%A, %b %d, %Y %H:%M:%S", &tm_now);

    std::string detailsStr = "Detection time: " + std::string(timeBuffer) + "\n";
    detailsStr += "Detection source: EDR Sensor\n";
    detailsStr += "Component: " + event.source + "\n";
    detailsStr += "Anubis code: " + event.id + "\n";
    detailsStr += "Detection description: " + event.details + "\n";
    detailsStr += "File path: " + event.filePath;

    m_details = ToWideString(detailsStr);

    // Calculate window height
    int contentHeight = CONTENT_HEIGHT_COLLAPSED;
    int totalHeight = contentHeight + FOOTER_HEIGHT + BUTTON_HEIGHT + PADDING * 3 + WINDOW_FRAME_HEIGHT;

    // Create and show window
    m_hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        WINDOW_CLASS,
        APP_TITLE,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        WINDOW_WIDTH, totalHeight,
        nullptr, nullptr, m_hInstance, this
    );

    if (!m_hwnd) return;

    // Create buttons
    CreateWindowW(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        WINDOW_WIDTH - 90, totalHeight - BUTTON_HEIGHT - PADDING - WINDOW_FRAME_HEIGHT, 70, BUTTON_HEIGHT,
        m_hwnd, (HMENU)ID_BTN_OK, m_hInstance, nullptr);

    CreateWindowW(L"BUTTON", L"Show details", WS_CHILD | WS_VISIBLE,
        WINDOW_WIDTH - 200, totalHeight - BUTTON_HEIGHT - PADDING - WINDOW_FRAME_HEIGHT, 100, BUTTON_HEIGHT,
        m_hwnd, (HMENU)ID_BTN_TOGGLE_DETAILS, m_hInstance, nullptr);

    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);
}

void AlertWindow::ToggleDetails() {
    int contentHeight = m_showDetails ? CONTENT_HEIGHT_COLLAPSED : CONTENT_HEIGHT_EXPANDED;
    int totalHeight = contentHeight + FOOTER_HEIGHT + BUTTON_HEIGHT + PADDING * 3 + WINDOW_FRAME_HEIGHT;
    m_showDetails = !m_showDetails;

    // Resize window
    SetWindowPos(m_hwnd, nullptr, 0, 0, WINDOW_WIDTH, totalHeight, SWP_NOMOVE | SWP_NOZORDER);

    // Update button text
    SetWindowTextW(GetDlgItem(m_hwnd, ID_BTN_TOGGLE_DETAILS),
        m_showDetails ? L"Hide details" : L"Show details");

    // Redraw window
    InvalidateRect(m_hwnd, nullptr, TRUE);
}

LRESULT CALLBACK AlertWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_OK:
            DestroyWindow(hwnd);
            return 0;
        case ID_BTN_TOGGLE_DETAILS:
            ToggleDetails();
            return 0;
        }
        break;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        OnPaint(hdc);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY:
        m_hwnd = nullptr;
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void AlertWindow::OnPaint(HDC hdc) {
    Graphics graphics(hdc);
    graphics.SetTextRenderingHint(TextRenderingHintAntiAlias);

    RECT rect;
    GetClientRect(m_hwnd, &rect);

    // Draw header
    SolidBrush headerBrush(Color(255, 200, 0, 0));  // RED HEADER
    graphics.FillRectangle(&headerBrush, 0, 0, rect.right, 50);

    // Draw icon in header
    if (m_hIcon) {
        DrawIconEx(hdc, PADDING, 6, m_hIcon, 32, 32, 0, NULL, DI_NORMAL);
    }

    // Create fonts and brushes
    Font titleFont(L"Segoe UI", (REAL)TITLE_FONT_SIZE, FontStyleBold, UnitPixel);
    Font bodyFont(L"Segoe UI", (REAL)TEXT_FONT_SIZE, FontStyleRegular, UnitPixel);
    SolidBrush whiteBrush(Color(255, 255, 255));
    SolidBrush blackBrush(Color(255, 0, 0, 0));

    // Draw title
    graphics.DrawString(m_mainMessage.c_str(), -1, &titleFont,
        PointF((REAL)(PADDING + 40), 12), &whiteBrush);

    // Draw content
    int y = 60;
    graphics.DrawString(L"File name:", -1, &bodyFont, PointF((REAL)PADDING, (REAL)y), &blackBrush);
    graphics.DrawString(m_appName.c_str(), -1, &bodyFont, PointF(200.0f, (REAL)y), &blackBrush);
    y += 20;
    graphics.DrawString(L"Publisher:", -1, &bodyFont, PointF((REAL)PADDING, (REAL)y), &blackBrush);
    graphics.DrawString(m_publisher.c_str(), -1, &bodyFont, PointF(200.0f, (REAL)y), &blackBrush);
    y += 20;
    graphics.DrawString(L"Detection description:", -1, &bodyFont, PointF((REAL)PADDING, (REAL)y), &blackBrush);
    graphics.DrawString(m_description.c_str(), -1, &bodyFont, PointF(200.0f, (REAL)y), &blackBrush);

    // Draw details if expanded
    if (m_showDetails) {
        y += 40;
        int availableHeight = rect.bottom - FOOTER_HEIGHT - BUTTON_HEIGHT - y - PADDING * 2;
        if (availableHeight > 0) {
            RectF detailsRect((REAL)PADDING, (REAL)y, (REAL)(WINDOW_WIDTH - 2 * PADDING), (REAL)availableHeight);
            StringFormat format;
            format.SetAlignment(StringAlignmentNear);
            format.SetLineAlignment(StringAlignmentNear);
            format.SetFormatFlags(StringFormatFlagsLineLimit);
            graphics.DrawString(m_details.c_str(), -1, &bodyFont, detailsRect, &format, &blackBrush);
        }
    }

    // Draw footer
    SolidBrush footerBrush(Color(255, 240, 240, 240));
    graphics.FillRectangle(&footerBrush, 0, rect.bottom - FOOTER_HEIGHT - BUTTON_HEIGHT - PADDING, rect.right, FOOTER_HEIGHT);

    RectF footerTextRect((REAL)PADDING, (REAL)(rect.bottom - FOOTER_HEIGHT - BUTTON_HEIGHT - PADDING + 5),
        (REAL)(rect.right - 2 * PADDING), (REAL)FOOTER_HEIGHT);
    StringFormat footerFormat;
    footerFormat.SetAlignment(StringAlignmentNear);
    footerFormat.SetLineAlignment(StringAlignmentNear);
    footerFormat.SetFormatFlags(StringFormatFlagsLineLimit);
    graphics.DrawString(FOOTER_TEXT, -1, &bodyFont, footerTextRect, &footerFormat, &blackBrush);
}

// Static method to show alert from any thread
void AlertWindow::ShowAlertDialog(const SecurityEvent& event) {
    // Launch a new thread to handle the alert window
    std::thread([event]() {
        HINSTANCE hInstance = GetModuleHandle(NULL);
        AlertWindow alertWindow(hInstance);

        if (alertWindow.Initialize()) {
            alertWindow.Show(event);

            // Message loop for this window
            MSG msg;
            while (GetMessage(&msg, nullptr, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
        }).detach();
}