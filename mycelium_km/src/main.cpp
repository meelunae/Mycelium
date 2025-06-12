#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

void debug_print(PCSTR text) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%s", text);
}

VOID ProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
);

VOID ImageLoadNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
);

NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
);

LARGE_INTEGER RegCookie = { 0 };



typedef struct _LOG_ENTRY {
    LARGE_INTEGER Timestamp;
    ULONG EventType;
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG ParentProcessId;
    WCHAR ImagePath[260];
    WCHAR CommandLine[512];
    WCHAR RegistryPath[260];
    UCHAR Encrypted;
} LOG_ENTRY, * PLOG_ENTRY;

#define MAX_LOG_ENTRIES 1000
LOG_ENTRY LogBuffer[MAX_LOG_ENTRIES];
ULONG LogIndex = 0;
KSPIN_LOCK LogSpinLock;
KSPIN_LOCK RegistrySpinLock;

#define IOCTL_GET_LOG_ENTRY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_CONTEXT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_MONITORING_STATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)\

ULONG TargetRootProcId = 0;
BOOLEAN TrackingEnabled = false;

typedef struct _PROCESS_CONTEXT {
    ULONG ProcessId;
    ULONG ParentProcessId;
    BOOLEAN IsTracked;
    ULONG SuspicionScore;
    LARGE_INTEGER CreationTime;
    ULONG InjectionAttempts;
    ULONG RegistryModifications;
    ULONG NetworkConnections;
    ULONG FileOperations;
    ULONG CryptoApiCalls;
    BOOLEAN IsSystemProcess;
    BOOLEAN HasSuspiciousParent;
    BOOLEAN InUse;
    BOOLEAN IsRansomwareLikely;
} PROCESS_CONTEXT, * PPROCESS_CONTEXT;

#define MAX_TRACKED_PROCESSES 500
PROCESS_CONTEXT ProcessContexts[MAX_TRACKED_PROCESSES];
ULONG ProcessContextIndex = 0;
KSPIN_LOCK ProcessContextLock;

const WCHAR* TrustedProcesses[] = {
    L"system", L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
    L"services.exe", L"lsass.exe", L"svchost.exe", L"explorer.exe",
    L"dwm.exe", L"taskhost.exe", L"spoolsv.exe", L"audiodg.exe"
};
#define TRUSTED_PROCESS_COUNT (sizeof(TrustedProcesses) / sizeof(WCHAR*))

const WCHAR* IgnoredRegistryPaths[] = {
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Hvsi",
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services",
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager",
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\Registry\\Machine\\Software\\Classes",
    L"\\Registry\\User\\.DEFAULT",
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class"
};
#define IGNORED_REG_COUNT (sizeof(IgnoredRegistryPaths) / sizeof(WCHAR*))
#define MAX_REGISTRY_EVENTS_PER_SECOND 10
ULONG RegistryEventCount = 0;
LARGE_INTEGER LastRegistryReset = { 0 };

#define EVENT_PROCESS_CREATE    1
#define EVENT_PROCESS_TERMINATE 2
#define EVENT_THREAD_CREATE     3
#define EVENT_THREAD_TERMINATE  4
#define EVENT_IMAGE_LOAD        5
#define EVENT_REGISTRY_CREATE   6
#define EVENT_REGISTRY_SET      7
#define EVENT_REGISTRY_DELETE   8
#define EVENT_PROCESS_INJECTION 9


// Function prototypes
VOID AddLogEntry(ULONG EventType, ULONG ProcessId, ULONG ThreadId,
    PCUNICODE_STRING ImagePath, PCUNICODE_STRING CommandLine,
    PCUNICODE_STRING RegistryPath);
BOOLEAN IsProcessTrusted(PCUNICODE_STRING ImagePath);
PPROCESS_CONTEXT GetOrCreateProcessContext(ULONG ProcessId, ULONG ParentProcessId);
BOOLEAN IsRegistryPathIgnored(PCUNICODE_STRING RegistryPath);
BOOLEAN ShouldLogRegistryEvent();
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
VOID MyceliumUnload(_In_ PDRIVER_OBJECT DriverObject);


NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);
    PVOID buffer = irp->AssociatedIrp.SystemBuffer;

    if (stack_irp == nullptr || buffer == nullptr) {
        irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    static PEPROCESS target_process = nullptr;
    const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;

    switch (control_code) {
    case IOCTL_GET_LOG_ENTRY:
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&LogSpinLock, &oldIrql);

        if (LogIndex == 0) {
            KeReleaseSpinLock(&LogSpinLock, oldIrql);
            irp->IoStatus.Information = 0;
            status = STATUS_SUCCESS;
            break;
        }

        PLOG_ENTRY userBuffer = (PLOG_ENTRY)irp->AssociatedIrp.SystemBuffer;
        if (!userBuffer || stack_irp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(LOG_ENTRY)) {
            KeReleaseSpinLock(&LogSpinLock, oldIrql);
            status = STATUS_BUFFER_TOO_SMALL;
            irp->IoStatus.Information = 0;
            break;
        }

        BOOLEAN foundTrackedEntry = FALSE;
        ULONG searchIndex = LogIndex;

        while (searchIndex > 0 && !foundTrackedEntry) {
            searchIndex--;
            PLOG_ENTRY currentEntry = &LogBuffer[searchIndex % MAX_LOG_ENTRIES];

            if (currentEntry->ProcessId != 0) {
                PPROCESS_CONTEXT ctx = GetOrCreateProcessContext(currentEntry->ProcessId, 0);
                if (ctx && ctx->IsTracked) {
                    *userBuffer = *currentEntry;
                    foundTrackedEntry = TRUE;

                    for (ULONG i = searchIndex; i < LogIndex - 1; i++) {
                        LogBuffer[i % MAX_LOG_ENTRIES] = LogBuffer[(i + 1) % MAX_LOG_ENTRIES];
                    }
                    LogIndex--;
                }
            }
            else {
                if (TrackingEnabled) {
                    *userBuffer = *currentEntry;
                    foundTrackedEntry = TRUE;

                    for (ULONG i = searchIndex; i < LogIndex - 1; i++) {
                        LogBuffer[i % MAX_LOG_ENTRIES] = LogBuffer[(i + 1) % MAX_LOG_ENTRIES];
                    }
                    LogIndex--;
                }
            }
        }

        if (foundTrackedEntry) {
            irp->IoStatus.Information = sizeof(LOG_ENTRY);
            status = STATUS_SUCCESS;
        }
        else {
            irp->IoStatus.Information = 0;
            status = STATUS_SUCCESS; // No tracked entries available
        }

        KeReleaseSpinLock(&LogSpinLock, oldIrql);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        irp->IoStatus.Information = 0;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

PWCHAR SafeWcsstrI(PCWSTR haystack, PCWSTR needle)
{
    if (!haystack || !needle) return NULL;

    __try {
        SIZE_T haystackLen = wcslen(haystack);
        SIZE_T needleLen = wcslen(needle);

        if (needleLen > haystackLen) return NULL;

        for (SIZE_T i = 0; i <= haystackLen - needleLen; i++) {
            if (_wcsnicmp(&haystack[i], needle, needleLen) == 0) {
                return (PWCHAR)&haystack[i];
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    return NULL;
}

BOOLEAN ShouldLogRegistryEvent()
{
    KIRQL oldIrql;
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    KeAcquireSpinLock(&RegistrySpinLock, &oldIrql);

    if ((currentTime.QuadPart - LastRegistryReset.QuadPart) > 10000000LL) {
        RegistryEventCount = 0;
        LastRegistryReset = currentTime;
    }

    if (RegistryEventCount >= MAX_REGISTRY_EVENTS_PER_SECOND) {
        KeReleaseSpinLock(&RegistrySpinLock, oldIrql);
        return FALSE;
    }

    RegistryEventCount++;
    KeReleaseSpinLock(&RegistrySpinLock, oldIrql);
    return TRUE;
}

BOOLEAN IsRegistryPathIgnored(PCUNICODE_STRING RegistryPath)
{
    if (!RegistryPath || !RegistryPath->Buffer || RegistryPath->Length == 0) {
        return TRUE;
    }

    __try {
        for (ULONG i = 0; i < IGNORED_REG_COUNT; i++) {
            if (SafeWcsstrI(RegistryPath->Buffer, IgnoredRegistryPaths[i])) {
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE; // If we can't check, ignore it to be safe
    }

    return FALSE;
}

BOOLEAN ShouldLogEvent(ULONG ProcessId) {
    PPROCESS_CONTEXT ctx = GetOrCreateProcessContext(ProcessId, 0);
    if (ctx && ctx->IsTracked) {
        return TRUE;
    }
    return FALSE;
}

VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return;
    }

    __try {
        ULONG pid = HandleToUlong(ProcessId);
        ULONG tid = HandleToUlong(ThreadId);

        if (ShouldLogEvent(pid)) {
            if (Create) {
                AddLogEntry(EVENT_THREAD_CREATE, pid, tid, NULL, NULL, NULL);
            }
            else {
                PPROCESS_CONTEXT ctx = GetOrCreateProcessContext(pid, 0);
                if (ctx && ctx->IsTracked) {
                    AddLogEntry(EVENT_THREAD_TERMINATE, pid, tid, NULL, NULL, NULL);

                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Mycelium: Exception in ThreadNotifyCallback\n"));
    }
}

VOID ImageLoadNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL || !ImageInfo) {
        return;
    }

    __try {
        ULONG pid = HandleToUlong(ProcessId);
        PPROCESS_CONTEXT ctx = GetOrCreateProcessContext(pid, 0);

        if (!ctx) return;


        if (ShouldLogEvent(pid)) {
            AddLogEntry(EVENT_IMAGE_LOAD, pid, 0, FullImageName, NULL, NULL);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Mycelium: Exception in ImageLoadNotifyCallback\n"));
    }
}

VOID SafeUnicodeStringCopy(PWCHAR Destination, SIZE_T DestinationSize, PCUNICODE_STRING Source)
{
    if (!Destination || !Source || !Source->Buffer || DestinationSize == 0) {
        return;
    }

    SIZE_T maxChars = (DestinationSize / sizeof(WCHAR)) - 1;
    SIZE_T sourceChars = Source->Length / sizeof(WCHAR);
    SIZE_T copyChars = min(maxChars, sourceChars);

    __try {
        RtlCopyMemory(Destination, Source->Buffer, copyChars * sizeof(WCHAR));
        Destination[copyChars] = L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Destination[0] = L'\0';
    }
}

NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return STATUS_SUCCESS;
    }

    if (!ShouldLogRegistryEvent()) {
        return STATUS_SUCCESS;
    }

    __try {
        REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

        HANDLE currentProcessId = PsGetCurrentProcessId();
        ULONG pid = HandleToUlong(currentProcessId);

        if (!ShouldLogEvent(pid)) {
            return STATUS_SUCCESS;
        }

        switch (notifyClass) {
        case RegNtPreCreateKeyEx: {
            PREG_CREATE_KEY_INFORMATION createInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
            if (createInfo && createInfo->CompleteName) {
                if (IsRegistryPathIgnored(createInfo->CompleteName)) {
                    return STATUS_SUCCESS;
                }

                AddLogEntry(EVENT_REGISTRY_CREATE, pid, 0, NULL, NULL,
                    createInfo->CompleteName);
            }
            break;
        }

        case RegNtPreSetValueKey: {
            PREG_SET_VALUE_KEY_INFORMATION setValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (setValueInfo && setValueInfo->ValueName) {
                AddLogEntry(EVENT_REGISTRY_SET, pid, 0, NULL, NULL,
                    setValueInfo->ValueName);
            }
            break;
        }

        case RegNtPreDeleteKey:
                AddLogEntry(EVENT_REGISTRY_DELETE, pid, 0, NULL, NULL, NULL);
            break;

        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Silently handle exceptions to prevent system instability
    }

    return STATUS_SUCCESS;
}

VOID AddLogEntry(ULONG EventType, ULONG ProcessId, ULONG ThreadId,
    PCUNICODE_STRING ImagePath, PCUNICODE_STRING CommandLine,
    PCUNICODE_STRING RegistryPath)
{
    PPROCESS_CONTEXT ctx = NULL;
    ctx = GetOrCreateProcessContext(ProcessId, 0);
    if (ctx && ctx->IsTracked) {

        KIRQL oldIrql;
        PLOG_ENTRY entry;

        if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
            return;
        }

        KeAcquireSpinLock(&LogSpinLock, &oldIrql);

        __try {
            entry = &LogBuffer[LogIndex % MAX_LOG_ENTRIES];
            LogIndex++;

            RtlZeroMemory(entry, sizeof(LOG_ENTRY));

            KeQuerySystemTime(&entry->Timestamp);
            entry->EventType = EventType;
            entry->ProcessId = ProcessId;
            entry->ThreadId = ThreadId;

            if (ProcessId != 0) {
                if (ctx) {
                    entry->ParentProcessId = ctx->ParentProcessId;
                }
            }

            SafeUnicodeStringCopy(entry->ImagePath, sizeof(entry->ImagePath), ImagePath);
            SafeUnicodeStringCopy(entry->CommandLine, sizeof(entry->CommandLine), CommandLine);
            SafeUnicodeStringCopy(entry->RegistryPath, sizeof(entry->RegistryPath), RegistryPath);

            char debugBuffer[512];
            const char* eventTypeStr = "UNKNOWN";
            const char* prefix = "[EVENT-";

            switch (EventType) {
            case EVENT_PROCESS_CREATE: eventTypeStr = "PROCESS_CREATE"; break;
            case EVENT_PROCESS_TERMINATE: eventTypeStr = "PROCESS_TERMINATE"; break;
            case EVENT_THREAD_CREATE: eventTypeStr = "THREAD_CREATE"; break;
            case EVENT_THREAD_TERMINATE: eventTypeStr = "THREAD_TERMINATE"; break;
            case EVENT_IMAGE_LOAD: eventTypeStr = "IMAGE_LOAD"; break;
            case EVENT_REGISTRY_CREATE: eventTypeStr = "REGISTRY_CREATE"; break;
            case EVENT_REGISTRY_SET: eventTypeStr = "REGISTRY_SET"; break;
            case EVENT_REGISTRY_DELETE: eventTypeStr = "REGISTRY_DELETE"; break;
            }

            RtlStringCbPrintfA(debugBuffer, sizeof(debugBuffer),
                "%s%s] PID: %lu\n",
                prefix, eventTypeStr, ProcessId);
            debug_print(debugBuffer);

            if (ImagePath && ImagePath->Buffer && ImagePath->Length > 0) {
                RtlStringCbPrintfA(debugBuffer, sizeof(debugBuffer),
                    "[INFO] Image: %wZ\n", ImagePath);
                debug_print(debugBuffer);
            }

            if (CommandLine && CommandLine->Buffer && CommandLine->Length > 0) {
                RtlStringCbPrintfA(debugBuffer, sizeof(debugBuffer),
                    "[INFO] CommandLine: %wZ\n", CommandLine);
                debug_print(debugBuffer);
            }

            if (RegistryPath && RegistryPath->Buffer && RegistryPath->Length > 0) {
                RtlStringCbPrintfA(debugBuffer, sizeof(debugBuffer),
                    "[INFO] Registry: %wZ\n", RegistryPath);
                debug_print(debugBuffer);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Silently handle exceptions
        }

        KeReleaseSpinLock(&LogSpinLock, oldIrql);
    }
}

PPROCESS_CONTEXT GetOrCreateProcessContext(ULONG ProcessId, ULONG ParentProcessId)
{
    KIRQL oldIrql;
    PPROCESS_CONTEXT ctx = NULL;

    if (ProcessId == 0) return NULL;

    KeAcquireSpinLock(&ProcessContextLock, &oldIrql);

    __try {
        for (ULONG i = 0; i < MAX_TRACKED_PROCESSES; i++) {
            if (ProcessContexts[i].InUse && ProcessContexts[i].ProcessId == ProcessId) {
                ctx = &ProcessContexts[i];
                break;
            }
        }

        if (!ctx) {
            ctx = &ProcessContexts[ProcessContextIndex % MAX_TRACKED_PROCESSES];
            ProcessContextIndex++;

            RtlZeroMemory(ctx, sizeof(PROCESS_CONTEXT));
            ctx->ProcessId = ProcessId;
            ctx->ParentProcessId = ParentProcessId;
            ctx->InUse = TRUE;
            KeQuerySystemTime(&ctx->CreationTime);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ctx = NULL;
    }

    KeReleaseSpinLock(&ProcessContextLock, oldIrql);
    return ctx;
}

BOOLEAN IsProcessTrusted(PCUNICODE_STRING ImagePath)
{
    if (!ImagePath || !ImagePath->Buffer || ImagePath->Length == 0) {
        return FALSE;
    }

    __try {
        PWCHAR filename = wcsrchr(ImagePath->Buffer, L'\\');
        if (filename) {
            filename++;
        }
        else {
            filename = ImagePath->Buffer;
        }

        for (ULONG i = 0; i < TRUSTED_PROCESS_COUNT; i++) {
            if (_wcsicmp(filename, TrustedProcesses[i]) == 0) {
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}

VOID ProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return;
    }

    __try {
        if (CreateInfo) {
            ULONG pid = HandleToUlong(ProcessId);
            ULONG parentPid = CreateInfo->ParentProcessId ? HandleToUlong(CreateInfo->ParentProcessId) : 0;


            if (!TrackingEnabled) {
                PCUNICODE_STRING imageName = CreateInfo->ImageFileName;
                UNICODE_STRING targetName;
                RtlInitUnicodeString(&targetName, L"sample.exe");
                // Get pointer to filename part by scanning backward for '\\'
                USHORT len = imageName->Length / sizeof(WCHAR);
                WCHAR* buffer = imageName->Buffer;

                // Find last backslash position
                USHORT i = len;
                while (i > 0) {
                    if (buffer[i - 1] == L'\\') {
                        break;
                    }
                    i--;
                }

                UNICODE_STRING baseName;
                baseName.Buffer = &buffer[i];
                baseName.Length = (USHORT)((len - i) * sizeof(WCHAR));
                baseName.MaximumLength = baseName.Length;

                if (RtlEqualUnicodeString(&baseName, &targetName, TRUE)) {
                    char cpybuf[256];
                    sprintf(cpybuf, "Target process '%wZ' detected. PID: %lu\n", imageName, pid);
                    debug_print(cpybuf);
                    TargetRootProcId = pid;
                    TrackingEnabled = true;
                    sprintf(cpybuf, "[+] Started tracking root sample process(sample.exe) : % lu\n", pid);
                    debug_print(cpybuf);
                }
            }

            if (TrackingEnabled) {
                PPROCESS_CONTEXT parentContext = GetOrCreateProcessContext(parentPid, 0);
                PPROCESS_CONTEXT newContext = GetOrCreateProcessContext(pid, parentPid);

                if (parentContext && parentContext->IsTracked) {
                    newContext->IsTracked = true;
                    char cpybuf[256];
                    sprintf(cpybuf, "[+] Started tracking child process %lu spawned from parent PID %lu\n", pid, parentPid);
                    debug_print(cpybuf);
                }
                else if (pid == TargetRootProcId) {
                    newContext->IsTracked = true;
                }
            }

            if (ShouldLogEvent(pid)) {
                char logBuffer[512];
                const char* prefix = "[PROCESS_CREATE]";

                RtlStringCbPrintfA(logBuffer, sizeof(logBuffer),
                    "%s PID: %lu, Parent PID: %lu",
                    prefix, pid, parentPid);
                debug_print(logBuffer);

                if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
                    RtlStringCbPrintfA(logBuffer, sizeof(logBuffer),
                        "[INFO] Image: %wZ\n", CreateInfo->ImageFileName);
                    debug_print(logBuffer);
                }

                if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer) {
                    RtlStringCbPrintfA(logBuffer, sizeof(logBuffer),
                        "[INFO] CommandLine: %wZ\n", CreateInfo->CommandLine);
                    debug_print(logBuffer);
                }
            }

            AddLogEntry(EVENT_PROCESS_CREATE, pid, 0, CreateInfo->ImageFileName,
                CreateInfo->CommandLine, NULL);
        }
        else {
            // Process termination
            ULONG pid = HandleToUlong(ProcessId);
            BOOLEAN shouldLog = ShouldLogEvent(pid);

            if (shouldLog) {
                char logBuffer[256];
                const char* prefix = "[PROCESS_TERMINATE]";

                RtlStringCbPrintfA(logBuffer, sizeof(logBuffer),
                    "%s PID: %lu\n",
                    prefix, pid);
                debug_print(logBuffer);
            }

            AddLogEntry(EVENT_PROCESS_TERMINATE, pid, 0, NULL, NULL, NULL);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        debug_print("[-] Exception in ProcessNotifyCallback\n");
    }
}

// Enhanced unload function with cleanup
VOID MyceliumUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Mycelium");

    debug_print("[+] Unloading driver...");

    // Unregister all callbacks
    if (RegCookie.QuadPart != 0) {
        CmUnRegisterCallback(RegCookie);
    }
    PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyCallback);
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
    debug_print("[+] All notification callbacks unregistered\n");

    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
    debug_print("[+] Driver unloaded and cleaned up.\n");
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    debug_print("[+] Hello from Kernel space!\n");

    // Initialize logging structures
    KeInitializeSpinLock(&LogSpinLock);
    KeInitializeSpinLock(&ProcessContextLock);
    RtlZeroMemory(LogBuffer, sizeof(LogBuffer));
    RtlZeroMemory(ProcessContexts, sizeof(ProcessContexts));
    LogIndex = 0;
    ProcessContextIndex = 0;

    DriverObject->DriverUnload = MyceliumUnload;

    UNICODE_STRING device_name = {};
    PDEVICE_OBJECT device_object = NULL;
    RtlInitUnicodeString(&device_name, L"\\Device\\Mycelium");

    status = IoCreateDevice(DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

    if (status != STATUS_SUCCESS) {
        debug_print("[-] Could not create driver device.\n");
        return status;
    }
    debug_print("[+] Created device driver successfully!\n");

    UNICODE_STRING symbolic_link = {};
    RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\Mycelium");
    status = IoCreateSymbolicLink(&symbolic_link, &device_name);
    if (status != STATUS_SUCCESS) {
        debug_print("[-] Could not establish symlink.\n");
        IoDeleteDevice(device_object);
        return status;
    }
    debug_print("[+] Created device symlink successfully!\n");

    SetFlag(device_object->Flags, DO_BUFFERED_IO);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = close;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = device_control;

    ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);
    debug_print("[+] Driver initialized successfully!\n");

    // Register for process creation notifications
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] Failed to register process notification callback\n");
        DbgPrint("Status: 0x%X\n", status);
        IoDeleteSymbolicLink(&symbolic_link);
        IoDeleteDevice(device_object);
        return status;
    }

    // Register for thread creation notifications
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Mycelium: PsSetCreateThreadNotifyRoutine failed with status 0x%x\n", status));
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        return status;
    }

    // Register for image load notifications
    status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Mycelium: PsSetLoadImageNotifyRoutine failed with status 0x%x\n", status));
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        return status;
    }

    // Register for registry notifications
    status = CmRegisterCallback(RegistryCallback, NULL, &RegCookie);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Mycelium: CmRegisterCallback failed with status 0x%x\n", status));
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyCallback);
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        return status;
    }

    debug_print("[+] All notification callbacks registered successfully!\n");
    debug_print("[+] Driver loaded successfully\n");

    return status;
}