#include "security_alert.h"
#include <thread>
#include <sstream>
#include <iomanip>
#include <chrono>

HINSTANCE SecurityAlertWindow::s_hInstance = NULL;
bool SecurityAlertWindow::s_classRegistered = false;
std::atomic<int> SecurityAlertWindow::s_activeAlertCount(0);
int SecurityAlertWindow::s_maxConcurrentAlerts = 5;
UINT SecurityAlertWindow::s_autoCloseTimeoutMs = 30000;  // 30 seconds
HFONT SecurityAlertWindow::s_titleFont = NULL;
HFONT SecurityAlertWindow::s_labelFont = NULL;
HFONT SecurityAlertWindow::s_bodyFont = NULL;

bool SecurityAlertWindow::Initialize(HINSTANCE hInstance)
{
    s_hInstance = hInstance;
    RegisterWindowClass(hInstance);

    // Create fonts for the alert UI
    s_titleFont = CreateFontW(
        20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI"
    );

    s_labelFont = CreateFontW(
        15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI"
    );

    s_bodyFont = CreateFontW(
        14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI"
    );

    return s_classRegistered;
}

void SecurityAlertWindow::Shutdown()
{
    if (s_titleFont) { DeleteObject(s_titleFont); s_titleFont = NULL; }
    if (s_labelFont) { DeleteObject(s_labelFont); s_labelFont = NULL; }
    if (s_bodyFont) { DeleteObject(s_bodyFont);  s_bodyFont = NULL; }
}

void SecurityAlertWindow::RegisterWindowClass(HINSTANCE hInstance)
{
    if (s_classRegistered) return;

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = AlertWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = WINDOW_CLASS_NAME;
    wc.hbrBackground = CreateSolidBrush(RGB(32, 32, 36));   // Dark background
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_WARNING);
    wc.hIconSm = LoadIcon(NULL, IDI_WARNING);

    if (RegisterClassExW(&wc)) {
        s_classRegistered = true;
    }
}

void SecurityAlertWindow::ShowAlert(const SecurityEvent& event)
{
    // Rate-limit concurrent alerts
    if (s_activeAlertCount.load() >= s_maxConcurrentAlerts) {
        return;  // Drop the alert if too many are showing
    }

    // Prepare data on the calling thread
    AlertWindowData* data = CreateAlertData(event);
    if (!data) return;

    // Spawn a dedicated UI thread for this alert window
    std::thread([data]() {
        s_activeAlertCount++;

        // Calculate position - stagger windows so they don't overlap
        int staggerOffset = (s_activeAlertCount.load() - 1) * 30;
        int screenW = GetSystemMetrics(SM_CXSCREEN);
        int screenH = GetSystemMetrics(SM_CYSCREEN);
        int x = screenW - WINDOW_WIDTH - 20 - staggerOffset;   // Bottom-right area
        int y = screenH - WINDOW_HEIGHT - 60 - staggerOffset;

        // Clamp to screen
        if (x < 0) x = 10;
        if (y < 0) y = 10;

        // Build window title
        std::wstring title = L"\x26A0 Anubis EDR \u2014 " + data->severityText + L" Security Alert";

        HWND hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_APPWINDOW,
            WINDOW_CLASS_NAME,
            title.c_str(),
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_BORDER,
            x, y, WINDOW_WIDTH, WINDOW_HEIGHT,
            NULL, NULL, s_hInstance, data   // Pass data via CREATESTRUCT
        );

        if (!hwnd) {
            delete data;
            s_activeAlertCount--;
            return;
        }

        // Show with animation
        ShowWindow(hwnd, SW_SHOWDEFAULT);
        UpdateWindow(hwnd);

        // Play system notification sound
        MessageBeep(MB_ICONWARNING);

        // Set auto-close timer
        SetTimer(hwnd, TIMER_AUTO_CLOSE, s_autoCloseTimeoutMs, NULL);

        // Run message loop for this window
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        s_activeAlertCount--;
        }).detach();
}

LRESULT CALLBACK SecurityAlertWindow::AlertWndProc(HWND hwnd, UINT msg,
    WPARAM wParam, LPARAM lParam)
{
    switch (msg) {

    case WM_CREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        auto* data = reinterpret_cast<AlertWindowData*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data));

        // ---- Layout constants ----
        const int MARGIN = 20;
        const int BANNER_HEIGHT = 8;
        int yPos = BANNER_HEIGHT + 15;
        int contentWidth = WINDOW_WIDTH - (2 * MARGIN) - 16;  // account for non-client area

        // ---- Severity title ----
        std::wstring sevTitle = L"\x26A0  " + data->severityText + L" SECURITY ALERT";
        HWND hSevLabel = CreateWindowW(L"STATIC", sevTitle.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            MARGIN, yPos, contentWidth, 26,
            hwnd, NULL, s_hInstance, NULL);
        if (s_titleFont) SendMessage(hSevLabel, WM_SETFONT, (WPARAM)s_titleFont, TRUE);
        yPos += 34;

        // ---- Separator line (using a thin static) ----
        CreateWindowW(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
            MARGIN, yPos, contentWidth, 2,
            hwnd, NULL, s_hInstance, NULL);
        yPos += 12;

        // ---- Event ID & Timestamp row ----
        std::wstring idLine = L"Event: " + data->eventId + L"    " + data->timestamp;
        HWND hIdLabel = CreateWindowW(L"STATIC", idLine.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            MARGIN, yPos, contentWidth, 18,
            hwnd, NULL, s_hInstance, NULL);
        if (s_bodyFont) SendMessage(hIdLabel, WM_SETFONT, (WPARAM)s_bodyFont, TRUE);
        yPos += 26;

        // ---- Source & Type ----
        std::wstring srcLabel = L"Source:";
        HWND hSrcLbl = CreateWindowW(L"STATIC", srcLabel.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            MARGIN, yPos, 55, 18,
            hwnd, NULL, s_hInstance, NULL);
        if (s_labelFont) SendMessage(hSrcLbl, WM_SETFONT, (WPARAM)s_labelFont, TRUE);

        std::wstring srcValue = data->source + L"  \u2192  " + data->type;
        HWND hSrcVal = CreateWindowW(L"STATIC", srcValue.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            MARGIN + 60, yPos, contentWidth - 60, 18,
            hwnd, NULL, s_hInstance, NULL);
        if (s_bodyFont) SendMessage(hSrcVal, WM_SETFONT, (WPARAM)s_bodyFont, TRUE);
        yPos += 24;

        // ---- File path (if present) ----
        if (!data->filePath.empty()) {
            std::wstring fileLabel = L"File:";
            HWND hFileLbl = CreateWindowW(L"STATIC", fileLabel.c_str(),
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                MARGIN, yPos, 55, 18,
                hwnd, NULL, s_hInstance, NULL);
            if (s_labelFont) SendMessage(hFileLbl, WM_SETFONT, (WPARAM)s_labelFont, TRUE);

            HWND hFileVal = CreateWindowW(L"STATIC", data->filePath.c_str(),
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_PATHELLIPSIS,
                MARGIN + 60, yPos, contentWidth - 60, 18,
                hwnd, NULL, s_hInstance, NULL);
            if (s_bodyFont) SendMessage(hFileVal, WM_SETFONT, (WPARAM)s_bodyFont, TRUE);
            yPos += 24;
        }
        yPos += 6;

        // ---- Description ----
        std::wstring descLabel = L"Description:";
        HWND hDescLbl = CreateWindowW(L"STATIC", descLabel.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            MARGIN, yPos, contentWidth, 18,
            hwnd, NULL, s_hInstance, NULL);
        if (s_labelFont) SendMessage(hDescLbl, WM_SETFONT, (WPARAM)s_labelFont, TRUE);
        yPos += 20;

        HWND hDescVal = CreateWindowW(L"STATIC", data->description.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            MARGIN, yPos, contentWidth, 40,
            hwnd, NULL, s_hInstance, NULL);
        if (s_bodyFont) SendMessage(hDescVal, WM_SETFONT, (WPARAM)s_bodyFont, TRUE);
        yPos += 46;

        // ---- Details box (scrollable, read-only edit) ----
        std::wstring detLabel = L"Details:";
        HWND hDetLbl = CreateWindowW(L"STATIC", detLabel.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            MARGIN, yPos, contentWidth, 18,
            hwnd, NULL, s_hInstance, NULL);
        if (s_labelFont) SendMessage(hDetLbl, WM_SETFONT, (WPARAM)s_labelFont, TRUE);
        yPos += 20;

        HWND hDetails = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT", data->details.c_str(),
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
            MARGIN, yPos, contentWidth, 80,
            hwnd, NULL, s_hInstance, NULL);
        if (s_bodyFont) SendMessage(hDetails, WM_SETFONT, (WPARAM)s_bodyFont, TRUE);
        yPos += 90;

        // ---- Buttons ----
        int btnWidth = 120;
        int btnHeight = 32;
        int btnY = WINDOW_HEIGHT - btnHeight - 55;  // Bottom area
        int btnSpacing = 15;
        int totalBtnWidth = (2 * btnWidth) + btnSpacing;
        int btnStartX = (WINDOW_WIDTH - totalBtnWidth) / 2 - 8;

        HWND hDismissBtn = CreateWindowW(L"BUTTON", L"Dismiss",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            btnStartX, btnY, btnWidth, btnHeight,
            hwnd, (HMENU)(INT_PTR)IDC_BTN_DISMISS, s_hInstance, NULL);
        if (s_bodyFont) SendMessage(hDismissBtn, WM_SETFONT, (WPARAM)s_bodyFont, TRUE);

        HWND hCopyBtn = CreateWindowW(L"BUTTON", L"Copy Details",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            btnStartX + btnWidth + btnSpacing, btnY, btnWidth, btnHeight,
            hwnd, (HMENU)(INT_PTR)IDC_BTN_DETAILS, s_hInstance, NULL);
        if (s_bodyFont) SendMessage(hCopyBtn, WM_SETFONT, (WPARAM)s_bodyFont, TRUE);

        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // Get the stored alert data for severity color
        auto* data = reinterpret_cast<AlertWindowData*>(
            GetWindowLongPtr(hwnd, GWLP_USERDATA));

        if (data) {
            PaintSeverityBanner(hdc, ps.rcPaint, data->severityLevel);
        }

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        // Dark theme: light text on dark background for all static controls
        HDC hdcStatic = (HDC)wParam;
        SetTextColor(hdcStatic, RGB(220, 220, 225));
        SetBkColor(hdcStatic, RGB(32, 32, 36));
        static HBRUSH hBrushBg = CreateSolidBrush(RGB(32, 32, 36));
        return (LRESULT)hBrushBg;
    }

    case WM_CTLCOLOREDIT: {
        // Details edit box: slightly lighter background
        HDC hdcEdit = (HDC)wParam;
        SetTextColor(hdcEdit, RGB(200, 200, 205));
        SetBkColor(hdcEdit, RGB(45, 45, 50));
        static HBRUSH hBrushEdit = CreateSolidBrush(RGB(45, 45, 50));
        return (LRESULT)hBrushEdit;
    }

    case WM_COMMAND: {
        int wmId = LOWORD(wParam);

        if (wmId == IDC_BTN_DISMISS) {
            DestroyWindow(hwnd);
        }
        else if (wmId == IDC_BTN_DETAILS) {
            // Copy event details to clipboard
            auto* data = reinterpret_cast<AlertWindowData*>(
                GetWindowLongPtr(hwnd, GWLP_USERDATA));

            if (data && OpenClipboard(hwnd)) {
                EmptyClipboard();

                std::wstring clipText =
                    L"Anubis EDR Security Alert\r\n"
                    L"========================\r\n"
                    L"Event ID: " + data->eventId + L"\r\n"
                    L"Severity: " + data->severityText + L"\r\n"
                    L"Source: " + data->source + L"\r\n"
                    L"Type: " + data->type + L"\r\n"
                    L"File: " + data->filePath + L"\r\n"
                    L"Time: " + data->timestamp + L"\r\n"
                    L"Description: " + data->description + L"\r\n"
                    L"Details: " + data->details + L"\r\n";

                size_t cbSize = (clipText.size() + 1) * sizeof(wchar_t);
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, cbSize);
                if (hMem) {
                    wchar_t* pMem = static_cast<wchar_t*>(GlobalLock(hMem));
                    if (pMem) {
                        memcpy(pMem, clipText.c_str(), cbSize);
                        GlobalUnlock(hMem);
                        SetClipboardData(CF_UNICODETEXT, hMem);
                    }
                }
                CloseClipboard();

                // Flash the button text briefly to confirm copy
                SetWindowTextW(GetDlgItem(hwnd, IDC_BTN_DETAILS), L"Copied!");
                SetTimer(hwnd, 2, 1500, NULL);  // Reset text after 1.5s
            }
        }
        return 0;
    }

    case WM_TIMER: {
        if (wParam == TIMER_AUTO_CLOSE) {
            DestroyWindow(hwnd);
        }
        else if (wParam == 2) {
            // Reset "Copy Details" button text
            HWND hBtn = GetDlgItem(hwnd, IDC_BTN_DETAILS);
            if (hBtn) SetWindowTextW(hBtn, L"Copy Details");
            KillTimer(hwnd, 2);
        }
        return 0;
    }

    case WM_DESTROY: {
        // Cleanup the alert data
        auto* data = reinterpret_cast<AlertWindowData*>(
            GetWindowLongPtr(hwnd, GWLP_USERDATA));
        delete data;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, 0);

        KillTimer(hwnd, TIMER_AUTO_CLOSE);
        PostQuitMessage(0);
        return 0;
    }

    } // end switch

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void SecurityAlertWindow::PaintSeverityBanner(HDC hdc, RECT& clientRect,
    SecurityEventSeverity severity)
{
    COLORREF color = GetSeverityColor(severity);
    HBRUSH hBrush = CreateSolidBrush(color);

    RECT bannerRect = { 0, 0, clientRect.right, 8 };
    FillRect(hdc, &bannerRect, hBrush);
    DeleteObject(hBrush);
}

COLORREF SecurityAlertWindow::GetSeverityColor(SecurityEventSeverity severity)
{
    switch (severity) {
    case SecurityEventSeverity::CRITICAL: return RGB(220, 30, 30);    // Bright red
    case SecurityEventSeverity::HIGH:     return RGB(230, 90, 20);    // Orange
    case SecurityEventSeverity::MEDIUM:   return RGB(230, 175, 0);    // Amber
    case SecurityEventSeverity::LOW:      return RGB(50, 160, 50);    // Green
    case SecurityEventSeverity::INFO:     return RGB(60, 130, 200);   // Blue
    default:                              return RGB(128, 128, 128);  // Gray
    }
}

std::wstring SecurityAlertWindow::GetSeverityString(SecurityEventSeverity severity)
{
    switch (severity) {
    case SecurityEventSeverity::CRITICAL: return L"CRITICAL";
    case SecurityEventSeverity::HIGH:     return L"HIGH";
    case SecurityEventSeverity::MEDIUM:   return L"MEDIUM";
    case SecurityEventSeverity::LOW:      return L"LOW";
    case SecurityEventSeverity::INFO:     return L"INFO";
    default:                              return L"UNKNOWN";
    }
}

std::wstring SecurityAlertWindow::FormatTimestamp(const std::chrono::system_clock::time_point& tp)
{
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_val;
    localtime_s(&tm_val, &time_t_val);

    std::wostringstream wss;
    wss << std::put_time(&tm_val, L"%Y-%m-%d %H:%M:%S");
    return wss.str();
}

std::wstring SecurityAlertWindow::Utf8ToWide(const std::string& str)
{
    if (str.empty()) return L"";

    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    if (sizeNeeded <= 0) return L"";

    std::wstring result(sizeNeeded, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], sizeNeeded);
    return result;
}

AlertWindowData* SecurityAlertWindow::CreateAlertData(const SecurityEvent& event)
{
    auto* data = new (std::nothrow) AlertWindowData();
    if (!data) return nullptr;

    data->eventId = Utf8ToWide(event.id);
    data->source = Utf8ToWide(event.source);
    data->type = Utf8ToWide(event.type);
    data->description = Utf8ToWide(event.description);
    data->details = Utf8ToWide(event.details);
    data->filePath = Utf8ToWide(event.filePath);
    data->fileName = Utf8ToWide(event.fileName);
    data->severityText = GetSeverityString(event.severity);
    data->timestamp = FormatTimestamp(event.timestamp);
    data->severityLevel = event.severity;

    return data;
}