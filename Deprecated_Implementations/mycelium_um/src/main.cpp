#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>
#include "json.hpp"

#define IOCTL_GET_LOG_ENTRY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

using json = nlohmann::json;
const wchar_t* DLL_PATH = L"C:\\Spore.dll";

struct MalwareExecutionParams {
    std::wstring malwarePath;
    int executionTime;
};

struct LOG_ENTRY {
    LARGE_INTEGER Timestamp;
    ULONG EventType;
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG ParentProcessId;
    WCHAR ImagePath[260];
    WCHAR CommandLine[512];
    WCHAR RegistryPath[260];
    UCHAR Encrypted;
};

// ------------ Global Logging ------------
std::wofstream g_logFile;
void InitLogging() {
    g_logFile.open(L"C:\\MyceliumLogs\\service.log", std::ios::app);
}
void Log(const std::wstring& message) {
    if (g_logFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        g_logFile << L"[" << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"] " << message << std::endl;
        g_logFile.flush();
    }
}
void CloseLogging() {
    if (g_logFile.is_open()) g_logFile.close();
}

// ------------ Utilities ------------

std::wstring ConvertTimestampToString(const LARGE_INTEGER& timestamp) {
    FILETIME ft;
    ft.dwLowDateTime = timestamp.LowPart;
    ft.dwHighDateTime = timestamp.HighPart;

    SYSTEMTIME stUTC, stLocal;
    if (FileTimeToSystemTime(&ft, &stUTC)) {
        if (SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal)) {
            std::wstringstream ss;
            ss << std::setfill(L'0')
                << std::setw(2) << stLocal.wHour << L":"
                << std::setw(2) << stLocal.wMinute << L":"
                << std::setw(2) << stLocal.wSecond << L"."
                << std::setw(3) << stLocal.wMilliseconds << L" "
                << stLocal.wDay << L"/"
                << stLocal.wMonth << L"/"
                << stLocal.wYear;
            return ss.str();
        }
    }
    return L"<invalid time>";
}

std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

bool CopyToKnownPath(const std::wstring& sourcePath, const std::wstring& targetPath) {
    if (!CopyFileW(sourcePath.c_str(), targetPath.c_str(), FALSE)) {
        Log(L"[!] Copy failed: " + std::to_wstring(GetLastError()));
        return false;
    }
    Log(L"[+] Copied malware to known path.");
    return true;
}

// ------------ DLL Injection ------------
bool InjectDLL(HANDLE processHandle, const wchar_t* dllPath) {
    SIZE_T pathLen = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(processHandle, nullptr, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;

    if (!WriteProcessMemory(processHandle, remoteMem, dllPath, pathLen, nullptr)) {
        VirtualFreeEx(processHandle, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        processHandle, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"),
        remoteMem, 0, nullptr
    );

    if (!hThread) {
        VirtualFreeEx(processHandle, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(processHandle, remoteMem, 0, MEM_RELEASE);
    return true;
}

bool InjectDLL(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;
    bool result = InjectDLL(hProcess, dllPath);
    CloseHandle(hProcess);
    return result;
}

// ------------ Malware Thread ------------
DWORD WINAPI MalwareExecutionThread(LPVOID lpParameter) {
    auto* params = static_cast<MalwareExecutionParams*>(lpParameter);
    if (!params) return 1;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(params->malwarePath.c_str(), nullptr, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        Log(L"[!] Failed to launch malware: " + std::to_wstring(GetLastError()));
        delete params;
        return 1;
    }

    Log(L"[+] Malware running (PID: " + std::to_wstring(pi.dwProcessId) + L")");

    if (!InjectDLL(pi.hProcess, DLL_PATH)) {
        Log(L"[!] Injection failed. Terminating process.");
        TerminateProcess(pi.hProcess, 1);
    }

    Sleep(params->executionTime * 1000);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    delete params;

    return 0;
}

// ------------ Driver Monitor Thread ------------
void MonitorKernelLogs() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\Mycelium", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        Log(L"[!] Failed to open device. Error: " + std::to_wstring(GetLastError()));
        return;
    }

    std::unordered_set<DWORD> injectedPIDs;
    LOG_ENTRY logEntry;
    DWORD bytesReturned;

    Log(L"[*] Monitoring kernel logs...");

    while (true) {
        BOOL success = DeviceIoControl(hDevice, IOCTL_GET_LOG_ENTRY, nullptr, 0,
            &logEntry, sizeof(logEntry), &bytesReturned, nullptr);
        if (!success || bytesReturned == 0) {
            Sleep(100);
            continue;
        }

        std::wstring msg = L"[" + ConvertTimestampToString(logEntry.Timestamp) + L"] | PID: " +
            std::to_wstring(logEntry.ProcessId) + L" | " + std::to_wstring(logEntry.EventType) +
            L" | Image: " + logEntry.ImagePath;
        Log(msg);

        if (injectedPIDs.insert(logEntry.ProcessId).second) {
            if (InjectDLL(logEntry.ProcessId, DLL_PATH)) {
                Log(L"[*] DLL injected into PID " + std::to_wstring(logEntry.ProcessId));
            }
            else {
                Log(L"[!] Injection failed for PID " + std::to_wstring(logEntry.ProcessId));
            }
        }
    }

    CloseHandle(hDevice);
}

// ------------ Config Loader ------------
void LoadConfigAndExecute(const std::wstring& configFilePath) {
    std::ifstream configFile(configFilePath);
    if (!configFile) {
        Log(L"[!] Failed to open config: " + configFilePath);
        return;
    }

    json configJson;
    try {
        configFile >> configJson;
    }
    catch (const std::exception& e) {
        Log(L"[!] Invalid JSON config.");
        return;
    }

    for (const auto& entry : configJson) {
        if (!entry.contains("executionTime") || !entry.contains("sampleName")) continue;

        int timeSec = entry["executionTime"];
        std::wstring malwarePath = utf8_to_wstring(entry["sampleName"]);

        std::wstring fixedPath = L"C:\\sample.exe";
        if (!CopyToKnownPath(malwarePath, fixedPath)) continue;

        auto* params = new MalwareExecutionParams{ fixedPath, timeSec };
        HANDLE hThread = CreateThread(nullptr, 0, MalwareExecutionThread, params, 0, nullptr);
        if (hThread) CloseHandle(hThread);
        else delete params;
    }
}

SERVICE_STATUS_HANDLE gStatusHandle = nullptr;
SERVICE_STATUS gServiceStatus = {0};

void SetStatus(DWORD state) {
    gServiceStatus.dwCurrentState = state;
    gServiceStatus.dwControlsAccepted = 0;
    gServiceStatus.dwWin32ExitCode = 0;
    gServiceStatus.dwServiceSpecificExitCode = 0;
    gServiceStatus.dwCheckPoint = 0;
    gServiceStatus.dwWaitHint = 0;
    gServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    SetServiceStatus(gStatusHandle, &gServiceStatus);
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    gStatusHandle = RegisterServiceCtrlHandlerW(L"MyceliumMonitor", nullptr);
    if (!gStatusHandle) return;

    SetStatus(SERVICE_START_PENDING);

    std::wstring configPath = L"D:\\config.json";

    // Start kernel monitoring in background
    std::thread monitorThread(MonitorKernelLogs);

    // Start malware execution from config
    LoadConfigAndExecute(configPath);

    SetStatus(SERVICE_RUNNING);

    // Keep the service alive
    while (true) {
        Sleep(1000);
    }
}

void RunAsConsole() {
    std::wcout << L"[i] Running in console mode...\n";

    std::wstring configPath = L"D:\\config.json";

    // Start kernel monitoring in background
    std::thread monitorThread(MonitorKernelLogs);

    // Start malware execution from config
    LoadConfigAndExecute(configPath);

    std::cout << "[*] All tasks started. Press Ctrl+C to stop." << std::endl;
    monitorThread.join();
    
    std::wcout << L"[i] Press Ctrl+C to exit\n";
    while (true) {
        Sleep(1000);
    }
}

int wmain(int argc, wchar_t* argv[]) {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { (LPWSTR)L"MyceliumMonitor", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(ServiceTable)) {
        // Not launched as a service, fallback to console mode
        RunAsConsole();
    }

    return 0;
}