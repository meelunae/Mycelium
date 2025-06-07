#include <windows.h>
#include <detours.h>
#include <iostream>

// Function pointers for original functions
static BOOL(WINAPI* TrueReadProcessMemory)(
    HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*
    ) = ReadProcessMemory;

static BOOL(WINAPI* TrueWriteProcessMemory)(
    HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*
    ) = WriteProcessMemory;

static HANDLE(WINAPI* TrueCreateRemoteThread)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD
    ) = CreateRemoteThread;

// Hook functions
BOOL WINAPI HookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
    LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    // Get process ID for logging
    DWORD processId = GetProcessId(hProcess);
    char logMsg[256];
    sprintf_s(logMsg, "[HookDLL] ReadProcessMemory intercepted! PID: %lu, Size: %zu bytes",
        processId, nSize);
    OutputDebugStringA(logMsg);

    return TrueReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress,
    LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    DWORD processId = GetProcessId(hProcess);
    char logMsg[256];
    sprintf_s(logMsg, "[HookDLL] WriteProcessMemory intercepted! PID: %lu, Size: %zu bytes",
        processId, nSize);
    OutputDebugStringA(logMsg);

    return TrueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    DWORD processId = GetProcessId(hProcess);
    char logMsg[256];
    sprintf_s(logMsg, "[HookDLL] CreateRemoteThread intercepted! PID: %lu, StartAddr: 0x%p",
        processId, lpStartAddress);
    OutputDebugStringA(logMsg);

    return TrueCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

// Helper function to install hooks
BOOL InstallHooks()
{
    LONG error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        OutputDebugStringA("[HookDLL] Failed to begin detour transaction");
        return FALSE;
    }

    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) {
        OutputDebugStringA("[HookDLL] Failed to update thread");
        DetourTransactionAbort();
        return FALSE;
    }

    // Only call DetourRestoreAfterWith if you're using it with a specific loader
    // DetourRestoreAfterWith();

    error = DetourAttach(&(PVOID&)TrueReadProcessMemory, HookedReadProcessMemory);
    if (error != NO_ERROR) {
        OutputDebugStringA("[HookDLL] Failed to attach ReadProcessMemory hook");
        DetourTransactionAbort();
        return FALSE;
    }

    error = DetourAttach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
    if (error != NO_ERROR) {
        OutputDebugStringA("[HookDLL] Failed to attach WriteProcessMemory hook");
        DetourTransactionAbort();
        return FALSE;
    }

    error = DetourAttach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);
    if (error != NO_ERROR) {
        OutputDebugStringA("[HookDLL] Failed to attach CreateRemoteThread hook");
        DetourTransactionAbort();
        return FALSE;
    }

    error = DetourTransactionCommit();
    if (error == NO_ERROR) {
        OutputDebugStringA("[HookDLL] All hooks installed successfully!");
        return TRUE;
    }
    else {
        OutputDebugStringA("[HookDLL] Failed to commit detour transaction");
        return FALSE;
    }
}

// Helper function to remove hooks
BOOL RemoveHooks()
{
    LONG error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        OutputDebugStringA("[HookDLL] Failed to begin detach transaction");
        return FALSE;
    }

    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) {
        OutputDebugStringA("[HookDLL] Failed to update thread for detach");
        DetourTransactionAbort();
        return FALSE;
    }

    DetourDetach(&(PVOID&)TrueReadProcessMemory, HookedReadProcessMemory);
    DetourDetach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
    DetourDetach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);

    error = DetourTransactionCommit();
    if (error == NO_ERROR) {
        OutputDebugStringA("[HookDLL] All hooks removed successfully!");
        return TRUE;
    }
    else {
        OutputDebugStringA("[HookDLL] Failed to commit detach transaction");
        return FALSE;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Disable thread notifications to reduce overhead
        DisableThreadLibraryCalls(hModule);

        OutputDebugStringA("[HookDLL] DLL attached, installing hooks...");
        if (!InstallHooks()) {
            OutputDebugStringA("[HookDLL] Failed to install hooks!");
            return FALSE;
        }
        break;

    case DLL_PROCESS_DETACH:
        // Only remove hooks if we're not being unloaded due to process termination
        if (lpReserved == nullptr) {
            OutputDebugStringA("[HookDLL] DLL detaching, removing hooks...");
            RemoveHooks();
        }
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        // These cases are disabled by DisableThreadLibraryCalls
        break;
    }
    return TRUE;
}