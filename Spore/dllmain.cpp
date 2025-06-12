#include <windows.h>
#include <detours.h>
#include <ntstatus.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <winternl.h>
#include <string>
#include <iostream>

static HANDLE g_hLogFile = INVALID_HANDLE_VALUE;
static DWORD g_processId = 0;
static thread_local bool g_inLogMessage = false;

void LogMessage(const std::string& msg) {
    if (g_inLogMessage) return;
    g_inLogMessage = true;

    if (g_hLogFile == INVALID_HANDLE_VALUE) {
        char path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path))) {
            std::string logDir = std::string(path) + "\\Mycelium\\logs";
            CreateDirectoryA((std::string(path) + "\\Mycelium").c_str(), nullptr);
            CreateDirectoryA(logDir.c_str(), nullptr);

            std::string logPath = logDir + "\\" + std::to_string(GetCurrentProcessId()) + "_hooks.txt";
            g_hLogFile = CreateFileA(logPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (g_hLogFile == INVALID_HANDLE_VALUE) {
                g_inLogMessage = false;
                return;
            }
        }
    }

    DWORD written = 0;
    WriteFile(g_hLogFile, msg.c_str(), (DWORD)msg.size(), &written, nullptr);

    g_inLogMessage = false;
}

// Function pointer declarations
static BOOL(WINAPI* TrueReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = nullptr;
static BOOL(WINAPI* TrueWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = nullptr;
static HANDLE(WINAPI* TrueCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = nullptr;
static NTSTATUS(NTAPI* TrueNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID) = nullptr;
static BOOL(WINAPI* TrueCreateProcessInternalW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE) = nullptr;
static NTSTATUS(NTAPI* TrueNtWriteFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG) = nullptr;
static BOOL(WINAPI* TrueDeleteFileW)(LPCWSTR) = nullptr;
static LSTATUS(WINAPI* TrueRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD) = nullptr;
static BOOL(WINAPI* TrueMoveFileExW)(LPCWSTR, LPCWSTR, DWORD) = nullptr;
static BOOL(WINAPI* TrueCryptEncrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD) = nullptr;
static LPVOID(WINAPI* TrueVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = nullptr;
static HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;

void InitializeOriginalFunctionPointers() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");

    if (!hKernel32 || !hNtdll || !hAdvapi32) {
        LogMessage("[MyceliumSpore] Failed to get module handles\n");
        return;
    }

    TrueReadProcessMemory = (decltype(TrueReadProcessMemory))GetProcAddress(hKernel32, "ReadProcessMemory");
    TrueWriteProcessMemory = (decltype(TrueWriteProcessMemory))GetProcAddress(hKernel32, "WriteProcessMemory");
    TrueCreateRemoteThread = (decltype(TrueCreateRemoteThread))GetProcAddress(hKernel32, "CreateRemoteThread");
    TrueDeleteFileW = (decltype(TrueDeleteFileW))GetProcAddress(hKernel32, "DeleteFileW");
    TrueMoveFileExW = (decltype(TrueMoveFileExW))GetProcAddress(hKernel32, "MoveFileExW");
    TrueVirtualAllocEx = (decltype(TrueVirtualAllocEx))GetProcAddress(hKernel32, "VirtualAllocEx");
    TrueCreateFileW = (decltype(TrueCreateFileW))GetProcAddress(hKernel32, "CreateFileW");

    TrueRegSetValueExW = (decltype(TrueRegSetValueExW))GetProcAddress(hAdvapi32, "RegSetValueExW");
    TrueCryptEncrypt = (decltype(TrueCryptEncrypt))GetProcAddress(hAdvapi32, "CryptEncrypt");

    TrueNtCreateThreadEx = (decltype(TrueNtCreateThreadEx))GetProcAddress(hNtdll, "NtCreateThreadEx");
    TrueNtWriteFile = (decltype(TrueNtWriteFile))GetProcAddress(hNtdll, "NtWriteFile");

    TrueCreateProcessInternalW = (decltype(TrueCreateProcessInternalW))GetProcAddress(hKernel32, "CreateProcessInternalW");

    // Log any missing functions
    if (!TrueReadProcessMemory) LogMessage("[MyceliumSpore] Warning: ReadProcessMemory not found\n");
    if (!TrueWriteProcessMemory) LogMessage("[MyceliumSpore] Warning: WriteProcessMemory not found\n");
    if (!TrueCreateRemoteThread) LogMessage("[MyceliumSpore] Warning: CreateRemoteThread not found\n");
    if (!TrueNtCreateThreadEx) LogMessage("[MyceliumSpore] Warning: NtCreateThreadEx not found\n");
    if (!TrueCreateProcessInternalW) LogMessage("[MyceliumSpore] Warning: CreateProcessInternalW not found\n");
    if (!TrueNtWriteFile) LogMessage("[MyceliumSpore] Warning: NtWriteFile not found\n");
    if (!TrueDeleteFileW) LogMessage("[MyceliumSpore] Warning: DeleteFileW not found\n");
    if (!TrueRegSetValueExW) LogMessage("[MyceliumSpore] Warning: RegSetValueExW not found\n");
    if (!TrueMoveFileExW) LogMessage("[MyceliumSpore] Warning: MoveFileExW not found\n");
    if (!TrueCryptEncrypt) LogMessage("[MyceliumSpore] Warning: CryptEncrypt not found\n");
    if (!TrueVirtualAllocEx) LogMessage("[MyceliumSpore] Warning: VirtualAllocEx not found\n");
    if (!TrueCreateFileW) LogMessage("[MyceliumSpore] Warning: CreateFileW not found\n");
}

bool IsOurLogFile(LPCWSTR fileName) {
    if (!fileName) return false;

    // Check if it's our log file to avoid hooking our own logging
    std::wstring fileStr(fileName);
    return fileStr.find(L"_hooks.txt") != std::wstring::npos;
}

// Hook implementations
BOOL WINAPI HookedReadProcessMemory(HANDLE hProcess, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T* read) {
    LogMessage("[MyceliumSpore] ReadProcessMemory intercepted\n");
    return TrueReadProcessMemory ? TrueReadProcessMemory(hProcess, addr, buf, size, read) : FALSE;
}

BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID addr, LPCVOID buf, SIZE_T size, SIZE_T* written) {
    LogMessage("[MyceliumSpore] WriteProcessMemory intercepted\n");
    return TrueWriteProcessMemory ? TrueWriteProcessMemory(hProcess, addr, buf, size, written) : FALSE;
}

HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES attr, SIZE_T stackSize, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD id) {
    LogMessage("[MyceliumSpore] CreateRemoteThread intercepted\n");
    return TrueCreateRemoteThread ? TrueCreateRemoteThread(hProcess, attr, stackSize, start, param, flags, id) : NULL;
}

NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK access, POBJECT_ATTRIBUTES attr, HANDLE process, PVOID start, PVOID param, ULONG flags, SIZE_T size1, SIZE_T size2, SIZE_T size3, PVOID unknown) {
    LogMessage("[MyceliumSpore] NtCreateThreadEx intercepted\n");
    return TrueNtCreateThreadEx ? TrueNtCreateThreadEx(hThread, access, attr, process, start, param, flags, size1, size2, size3, unknown) : STATUS_UNSUCCESSFUL;
}

BOOL WINAPI HookedCreateProcessInternalW(HANDLE hToken, LPCWSTR appName, LPWSTR cmdLine, LPSECURITY_ATTRIBUTES p1, LPSECURITY_ATTRIBUTES p2, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW start, LPPROCESS_INFORMATION info, PHANDLE hNewToken) {
    LogMessage("[MyceliumSpore] CreateProcessInternalW intercepted\n");
    return TrueCreateProcessInternalW ? TrueCreateProcessInternalW(hToken, appName, cmdLine, p1, p2, inherit, flags, env, dir, start, info, hNewToken) : FALSE;
}

NTSTATUS NTAPI HookedNtWriteFile(HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcCtx, PIO_STATUS_BLOCK status, PVOID buf, ULONG len, PLARGE_INTEGER off, PULONG key) {
    LogMessage("[MyceliumSpore] NtWriteFile intercepted\n");
    return TrueNtWriteFile ? TrueNtWriteFile(file, event, apc, apcCtx, status, buf, len, off, key) : STATUS_UNSUCCESSFUL;
}

BOOL WINAPI HookedDeleteFileW(LPCWSTR file) {
    // Don't log deletion of our own log file
    if (!IsOurLogFile(file)) {
        LogMessage("[MyceliumSpore] DeleteFileW intercepted\n");
    }
    return TrueDeleteFileW ? TrueDeleteFileW(file) : FALSE;
}

LSTATUS WINAPI HookedRegSetValueExW(HKEY hKey, LPCWSTR name, DWORD r, DWORD type, const BYTE* data, DWORD size) {
    LogMessage("[MyceliumSpore] RegSetValueExW intercepted\n");
    return TrueRegSetValueExW ? TrueRegSetValueExW(hKey, name, r, type, data, size) : ERROR_CALL_NOT_IMPLEMENTED;
}

BOOL WINAPI HookedMoveFileExW(LPCWSTR existing, LPCWSTR newname, DWORD flags) {
    // Don't log moves involving our log file
    if (!IsOurLogFile(existing) && !IsOurLogFile(newname)) {
        LogMessage("[MyceliumSpore] MoveFileExW intercepted\n");
    }
    return TrueMoveFileExW ? TrueMoveFileExW(existing, newname, flags) : FALSE;
}

BOOL WINAPI HookedCryptEncrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL final, DWORD flags, BYTE* data, DWORD* len, DWORD bufLen) {
    LogMessage("[MyceliumSpore] CryptEncrypt intercepted\n");
    return TrueCryptEncrypt ? TrueCryptEncrypt(key, hash, final, flags, data, len, bufLen) : FALSE;
}

LPVOID WINAPI HookedVirtualAllocEx(HANDLE hProcess, LPVOID addr, SIZE_T size, DWORD allocType, DWORD protect) {
    LogMessage("[MyceliumSpore] VirtualAllocEx intercepted\n");
    return TrueVirtualAllocEx ? TrueVirtualAllocEx(hProcess, addr, size, allocType, protect) : NULL;
}

HANDLE WINAPI HookedCreateFileW(LPCWSTR fileName, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sec, DWORD creation, DWORD flags, HANDLE templateFile) {
    // Don't log creation of our own log file to prevent recursion
    if (!IsOurLogFile(fileName)) {
        LogMessage("[MyceliumSpore] CreateFileW intercepted\n");
    }
    return TrueCreateFileW ? TrueCreateFileW(fileName, access, share, sec, creation, flags, templateFile) : INVALID_HANDLE_VALUE;
}

BOOL InstallHooks() {
    LogMessage("[MyceliumSpore] Installing hooks...\n");

    if (!TrueNtCreateThreadEx) {
        LogMessage("[MyceliumSpore] Critical: NtCreateThreadEx not found - some hooks will fail\n");
    }
    if (!TrueNtWriteFile) {
        LogMessage("[MyceliumSpore] Critical: NtWriteFile not found - some hooks will fail\n");
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

#define ATTACH_HOOK(realFn, hookFn) do { \
        if (realFn) { \
            LONG result = DetourAttach(&(PVOID&)realFn, hookFn); \
            if (result == NO_ERROR) { \
                LogMessage("[MyceliumSpore] Successfully hooked " #realFn "\n"); \
            } else { \
                LogMessage("[MyceliumSpore] Failed to hook " #realFn " (error: " + std::to_string(result) + ")\n"); \
            } \
        } else { \
            LogMessage("[MyceliumSpore] Skipping " #realFn " - function not found\n"); \
        } \
    } while (0)

    // Install hooks for available functions
    ATTACH_HOOK(TrueReadProcessMemory, HookedReadProcessMemory);
    ATTACH_HOOK(TrueWriteProcessMemory, HookedWriteProcessMemory);
    ATTACH_HOOK(TrueCreateRemoteThread, HookedCreateRemoteThread);
    ATTACH_HOOK(TrueNtCreateThreadEx, HookedNtCreateThreadEx);
    ATTACH_HOOK(TrueCreateProcessInternalW, HookedCreateProcessInternalW);
    ATTACH_HOOK(TrueNtWriteFile, HookedNtWriteFile);
    ATTACH_HOOK(TrueDeleteFileW, HookedDeleteFileW);
    ATTACH_HOOK(TrueRegSetValueExW, HookedRegSetValueExW);
    ATTACH_HOOK(TrueMoveFileExW, HookedMoveFileExW);
    ATTACH_HOOK(TrueCryptEncrypt, HookedCryptEncrypt);
    ATTACH_HOOK(TrueVirtualAllocEx, HookedVirtualAllocEx);
    ATTACH_HOOK(TrueCreateFileW, HookedCreateFileW);

#undef ATTACH_HOOK

    LONG commitResult = DetourTransactionCommit();
    LogMessage("[MyceliumSpore] DetourTransactionCommit result: " + std::to_string(commitResult) + "\n");

    return (commitResult == NO_ERROR);
}

BOOL RemoveHooks() {
    LogMessage("[MyceliumSpore] Removing hooks...\n");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

#define DETACH_HOOK(realFn, hookFn) do { \
        if (realFn) { \
            LONG result = DetourDetach(&(PVOID&)realFn, hookFn); \
            if (result == NO_ERROR) { \
                LogMessage("[MyceliumSpore] Successfully unhooked " #realFn "\n"); \
            } else { \
                LogMessage("[MyceliumSpore] Failed to unhook " #realFn " (error: " + std::to_string(result) + ")\n"); \
            } \
        } \
    } while (0)

    DETACH_HOOK(TrueReadProcessMemory, HookedReadProcessMemory);
    DETACH_HOOK(TrueWriteProcessMemory, HookedWriteProcessMemory);
    DETACH_HOOK(TrueCreateRemoteThread, HookedCreateRemoteThread);
    DETACH_HOOK(TrueNtCreateThreadEx, HookedNtCreateThreadEx);
    DETACH_HOOK(TrueCreateProcessInternalW, HookedCreateProcessInternalW);
    DETACH_HOOK(TrueNtWriteFile, HookedNtWriteFile);
    DETACH_HOOK(TrueDeleteFileW, HookedDeleteFileW);
    DETACH_HOOK(TrueRegSetValueExW, HookedRegSetValueExW);
    DETACH_HOOK(TrueMoveFileExW, HookedMoveFileExW);
    DETACH_HOOK(TrueCryptEncrypt, HookedCryptEncrypt);
    DETACH_HOOK(TrueVirtualAllocEx, HookedVirtualAllocEx);
    DETACH_HOOK(TrueCreateFileW, HookedCreateFileW);

#undef DETACH_HOOK

    LONG commitResult = DetourTransactionCommit();
    LogMessage("[MyceliumSpore] DetourTransactionCommit (removal) result: " + std::to_string(commitResult) + "\n");

    return (commitResult == NO_ERROR);
}

extern "C" __declspec(dllexport) BOOL StartHooking() {
    LogMessage("[MyceliumSpore] StartHooking called\n");
    InitializeOriginalFunctionPointers();
    return InstallHooks();
}

extern "C" __declspec(dllexport) BOOL StopHooking() {
    LogMessage("[MyceliumSpore] StopHooking called\n");
    return RemoveHooks();
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        LogMessage("[MyceliumSpore] DLL_PROCESS_ATTACH\n");
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)StartHooking, nullptr, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        LogMessage("[MyceliumSpore] DLL_PROCESS_DETACH\n");
        RemoveHooks();
        if (g_hLogFile != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hLogFile);
            g_hLogFile = INVALID_HANDLE_VALUE;
        }
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}