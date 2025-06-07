#include <windows.h>
#include <detours.h>
#include <iostream>
#include <string>

// Function pointers for original functions
static BOOL(WINAPI* TrueReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = ReadProcessMemory;
static BOOL(WINAPI* TrueWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
static HANDLE(WINAPI* TrueCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;

// Logging via named pipe
void LogMessage(const std::string& msg) {
    HANDLE hPipe = CreateFileA(
        "\\\\.\\pipe\\MyceliumPipe",
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hPipe, msg.c_str(), (DWORD)msg.size(), &written, nullptr);
        CloseHandle(hPipe);
    }
    else {
        // Fallback: send to debugger
        OutputDebugStringA(msg.c_str());
    }
}

// Hook implementations
BOOL WINAPI HookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
    LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    DWORD pid = GetProcessId(hProcess);
    char buffer[256];
    sprintf_s(buffer, "[HookDLL] ReadProcessMemory intercepted! PID: %lu, Size: %zu\n", pid, nSize);
    LogMessage(buffer);

    return TrueReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress,
    LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    DWORD pid = GetProcessId(hProcess);
    char buffer[256];
    sprintf_s(buffer, "[HookDLL] WriteProcessMemory intercepted! PID: %lu, Size: %zu\n", pid, nSize);
    LogMessage(buffer);

    return TrueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    DWORD pid = GetProcessId(hProcess);
    char buffer[256];
    sprintf_s(buffer, "[HookDLL] CreateRemoteThread intercepted! PID: %lu, StartAddr: 0x%p\n", pid, lpStartAddress);
    LogMessage(buffer);

    return TrueCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

// Hook setup
BOOL InstallHooks() {
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;

    DetourAttach(&(PVOID&)TrueReadProcessMemory, HookedReadProcessMemory);
    DetourAttach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
    DetourAttach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);

    return (DetourTransactionCommit() == NO_ERROR);
}

BOOL RemoveHooks() {
    if (DetourTransactionBegin() != NO_ERROR) return FALSE;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) return FALSE;

    DetourDetach(&(PVOID&)TrueReadProcessMemory, HookedReadProcessMemory);
    DetourDetach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
    DetourDetach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);

    return (DetourTransactionCommit() == NO_ERROR);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        LogMessage("[HookDLL] DLL_PROCESS_ATTACH - Installing hooks...\n");
        if (!InstallHooks()) {
            LogMessage("[HookDLL] Hook installation failed!\n");
            return FALSE;
        }
        break;

    case DLL_PROCESS_DETACH:
        if (reserved == nullptr) {
            LogMessage("[HookDLL] DLL_PROCESS_DETACH - Removing hooks...\n");
            RemoveHooks();
        }
        break;
    }
    return TRUE;
}
