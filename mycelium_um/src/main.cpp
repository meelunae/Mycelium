#include <windows.h>
#include <iostream>
#include <unordered_set>

#define IOCTL_GET_LOG_ENTRY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct LOG_ENTRY {
    LARGE_INTEGER Timestamp;
    ULONG EventType;
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG ParentProcessId;
    ULONG SuspicionScore;
    WCHAR ImagePath[260];
    WCHAR CommandLine[512];
    WCHAR RegistryPath[260];
    UCHAR Encrypted;
    BOOLEAN IsRansomwareIndicator;
};

BOOL InjectDLL(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"Failed to open process: " << pid << std::endl;
        return FALSE;
    }

    SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProcess);
        return FALSE;
    }

    WriteProcessMemory(hProcess, remoteMem, dllPath, pathSize, nullptr);

    HMODULE hKernel32 = GetModuleHandleW(L"Kernel32");
    FARPROC loadLib = GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, nullptr);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return TRUE;
}

int main() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\Mycelium",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device. Error: " << GetLastError() << std::endl;
        return 1;
    }

    LOG_ENTRY logEntry;
    DWORD bytesReturned;

    std::cout << "Listening for kernel logs...\n";

    while (true) {
        BOOL success = DeviceIoControl(hDevice,
            IOCTL_GET_LOG_ENTRY,
            nullptr, 0,  // no input buffer
            &logEntry, sizeof(logEntry),  // output buffer
            &bytesReturned,
            nullptr);

        if (!success || bytesReturned == 0) {
            // No log available or error - wait a bit and try again
            Sleep(100); // 100 ms delay to avoid busy loop
            continue;
        }

        // Print log info (simplified)
        std::wcout << L"Event Type: " << logEntry.EventType
            << L" | PID: " << logEntry.ProcessId
            << L" | Suspicion: " << logEntry.SuspicionScore
            << L" | ImagePath: " << logEntry.ImagePath << std::endl;

        static std::unordered_set<DWORD> injected;

        if (injected.find(logEntry.ProcessId) == injected.end()) {
            if (InjectDLL(logEntry.ProcessId, L"C:\\Spore.dll")) {
                std::wcout << L"[*] DLL injected into PID " << logEntry.ProcessId << std::endl;
                injected.insert(logEntry.ProcessId);
            }
        }
    }

    CloseHandle(hDevice);
    return 0;
}
