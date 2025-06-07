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

// ------------ Structs ------------
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

// ------------ Utility ------------
std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

bool CopyToKnownPath(const std::wstring& sourcePath, const std::wstring& targetPath) {
    if (!CopyFileW(sourcePath.c_str(), targetPath.c_str(), FALSE)) {
        std::wcerr << L"[!] Copy failed: " << GetLastError() << std::endl;
        return false;
    }
    std::wcout << L"[+] Copied malware to known path." << std::endl;
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
        std::wcerr << L"[!] Failed to launch malware: " << GetLastError() << std::endl;
        delete params;
        return 1;
    }

    std::wcout << L"[+] Malware running (PID: " << pi.dwProcessId << L")" << std::endl;

    if (!InjectDLL(pi.hProcess, DLL_PATH)) {
        std::wcerr << L"[!] Injection failed. Terminating process." << std::endl;
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
        std::wcerr << L"[!] Failed to open device. Error: " << GetLastError() << std::endl;
        return;
    }

    std::unordered_set<DWORD> injectedPIDs;
    LOG_ENTRY logEntry;
    DWORD bytesReturned;

    std::wcout << L"[*] Monitoring kernel logs..." << std::endl;

    while (true) {
        BOOL success = DeviceIoControl(hDevice, IOCTL_GET_LOG_ENTRY, nullptr, 0,
            &logEntry, sizeof(logEntry), &bytesReturned, nullptr);
        if (!success || bytesReturned == 0) {
            Sleep(100);
            continue;
        }

        std::wcout << L"[" << ConvertTimestampToString(logEntry.Timestamp) << L"] | PID: "
            << logEntry.ProcessId << L" | " << logEntry.EventType
            << L" | Image: " << logEntry.ImagePath << std::endl;

        if (injectedPIDs.insert(logEntry.ProcessId).second) {
            if (InjectDLL(logEntry.ProcessId, DLL_PATH)) {
                std::wcout << L"[*] DLL injected into PID " << logEntry.ProcessId << std::endl;
            }
            else {
                std::wcerr << L"[!] Injection failed for PID " << logEntry.ProcessId << std::endl;
            }
        }
    }

    CloseHandle(hDevice);
}

void ListenToMyceliumPipe() {
    HANDLE hPipe = CreateNamedPipeW(
        L"\\\\.\\pipe\\MyceliumPipe",          
        PIPE_ACCESS_INBOUND,                  
        PIPE_TYPE_BYTE | PIPE_WAIT,           
        1,                                    
        4096, 4096,                           
        0,                                    
        nullptr                               
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] Failed to create named pipe: " << GetLastError() << std::endl;
        return;
    }

    std::wcout << L"[+] Waiting for Spore.dll to connect to pipe..." << std::endl;
    if (!ConnectNamedPipe(hPipe, nullptr)) {
        std::wcerr << L"[!] Failed to connect named pipe: " << GetLastError() << std::endl;
        CloseHandle(hPipe);
        return;
    }

    std::wcout << L"[+] Spore.dll connected to MyceliumPipe.\n" << std::endl;

    char buffer[512];
    DWORD bytesRead;

    while (true) {
        BOOL success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
        if (!success || bytesRead == 0)
            break;

        buffer[bytesRead] = '\0';
        std::cout << buffer;
    }

    std::wcout << L"[!] Pipe disconnected.\n";
    CloseHandle(hPipe);
}


// ------------ Config Loader ------------
void LoadConfigAndExecute(const std::string& configFilePath) {
    std::ifstream configFile(configFilePath);
    if (!configFile) {
        std::cerr << "[!] Failed to open config: " << configFilePath << std::endl;
        return;
    }

    json configJson;
    try {
        configFile >> configJson;
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Invalid JSON config: " << e.what() << std::endl;
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

// ------------ Main ------------
int main() {
    std::string configPath = "config.json";

    // Start kernel monitoring in background
    std::thread monitorThread(MonitorKernelLogs);

    // Start hook DLL logging in background
    std::thread hookLogThread(ListenToMyceliumPipe);


    // Start malware execution from config
    LoadConfigAndExecute(configPath);

    std::cout << "[*] All tasks started. Press Ctrl+C to stop." << std::endl;
    monitorThread.join();
    hookLogThread.join();

    return 0;
}
