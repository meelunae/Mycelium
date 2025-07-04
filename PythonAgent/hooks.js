// Helper to read strings safely
function readAnsi(ptr) {
  try {
    return ptr.isNull() ? null : ptr.readCString();
  } catch (e) {
    return "[Invalid ANSI]";
  }
}

function readUtf16(ptr) {
  try {
    return ptr.isNull() ? null : ptr.readUtf16String();
  } catch (e) {
    return "[Invalid UTF16]";
  }
}

// Log filtering configuration
const LOG_CONFIG = {
  // APIs that are called too frequently - we'll throttle or filter these
  noisy_apis: new Set([
    // Process/Thread info
    'GetCurrentProcessId',
    'GetCurrentThreadId', 
    'GetCurrentProcess',
    'GetCurrentThread',
    
    // Time APIs
    'GetTickCount',
    'GetTickCount64',
    'QueryPerformanceCounter',
    'GetSystemTimeAsFileTime',
    'GetLocalTime',
    'GetSystemTime',
    
    // Memory management
    'GetProcessHeap',
    'HeapAlloc',
    'HeapFree',
    'RtlAllocateHeap',
    'RtlFreeHeap',
    'VirtualQuery',
    'VirtualQueryEx',
    
    // NT APIs that are super noisy
    'NtQueryInformationProcess',
    'NtQuerySystemInformation',
    'NtQueryInformationThread',
    'NtQueryObject',
    'NtQueryVirtualMemory',
    'NtClose',
    
    // Registry APIs - EXTREMELY noisy
    'RegOpenKeyExW',
    'RegOpenKeyExA', 
    'RegQueryValueExW',
    'RegQueryValueExA',
    'RegCloseKey',
    'RegEnumKeyExW',
    'RegEnumValueW',
    'RegQueryInfoKeyW',
    'NtOpenKey',
    'NtQueryValueKey',
    'NtEnumerateKey',
    'NtEnumerateValueKey',
    'NtQueryKey',
    
    // File system queries that happen constantly
    'GetFileAttributesW',
    'GetFileAttributesA',
    'FindFirstFileW',
    'FindNextFileW',
    'FindClose'
  ]),
  
  // APIs to completely ignore (too noisy even with throttling)
  ignored_apis: new Set([
    'RegOpenKeyExW',
    'RegQueryValueExW', 
    'RegCloseKey',
    'NtQueryInformationProcess',
    'GetCurrentProcessId',
    'GetCurrentThreadId',
    'GetTickCount',
    'HeapAlloc',
    'HeapFree'
  ]),
  
  // Counter for throttling noisy APIs
  call_counts: new Map(),
  
  // Log every Nth call for noisy APIs (higher number = less spam)
  throttle_interval: 500
};

function log(msg, apiName = null) {
  // Check if this API should be completely ignored
  if (apiName && LOG_CONFIG.ignored_apis.has(apiName)) {
    return; // Don't log at all
  }
  
  // Check if this is a noisy API that should be throttled
  if (apiName && LOG_CONFIG.noisy_apis.has(apiName)) {
    const count = (LOG_CONFIG.call_counts.get(apiName) || 0) + 1;
    LOG_CONFIG.call_counts.set(apiName, count);
    
    // Only log every Nth call
    if (count % LOG_CONFIG.throttle_interval !== 0) {
      return;
    }
    msg += ` [Call #${count}]`;
  }
  
  send({ type: "log", data: msg });
}

// More robust export checking that handles forwarders
function getExportSafely(moduleName, funcName) {
  try {
    const addr = Module.getExportByName(moduleName, funcName);
    if (addr && !addr.isNull()) {
      return addr;
    }
  } catch (e) {
    try {
      const addr = Module.findExportByName(moduleName, funcName);
      if (addr && !addr.isNull()) {
        return addr;
      }
    } catch (e2) {
      try {
        const module = Process.getModuleByName(moduleName);
        const exports = module.enumerateExports();
        const exportEntry = exports.find(exp => exp.name === funcName);
        if (exportEntry) {
          return exportEntry.address;
        }
      } catch (e3) {
        // Silently fail for export checking
      }
    }
  }
  return null;
}

// Function to check if an export is a forwarder
function checkForwarder(moduleName, funcName) {
  try {
    const module = Process.getModuleByName(moduleName);
    const exports = module.enumerateExports();
    const exportEntry = exports.find(exp => exp.name === funcName);
    
    if (exportEntry && exportEntry.type === 'function') {
      const moduleBase = module.base;
      const moduleEnd = moduleBase.add(module.size);
      
      if (exportEntry.address.compare(moduleBase) >= 0 && exportEntry.address.compare(moduleEnd) < 0) {
        return { isForwarder: false, address: exportEntry.address };
      } else {
        return { isForwarder: true, address: null };
      }
    }
  } catch (e) {
    // Silently fail
  }
  return { isForwarder: false, address: null };
}

// Enhanced export checking with forwarder detection
function getExportSafelyWithForwarderCheck(moduleName, funcName) {
  const forwarderCheck = checkForwarder(moduleName, funcName);
  
  if (forwarderCheck.isForwarder) {
    if (moduleName.toLowerCase() === 'kernel32.dll') {
      return getExportSafely('kernelbase.dll', funcName);
    }
  } else if (forwarderCheck.address) {
    return forwarderCheck.address;
  }
  
  return getExportSafely(moduleName, funcName);
}

// Helper function to format file attributes
function formatFileAttributes(attrs) {
  const attributes = [];
  if (attrs & 0x1) attributes.push("READONLY");
  if (attrs & 0x2) attributes.push("HIDDEN");
  if (attrs & 0x4) attributes.push("SYSTEM");
  if (attrs & 0x10) attributes.push("DIRECTORY");
  if (attrs & 0x20) attributes.push("ARCHIVE");
  return attributes.join("|") || "NORMAL";
}

// Helper function to format access rights
function formatAccessRights(access) {
  const rights = [];
  if (access & 0x80000000) rights.push("GENERIC_READ");
  if (access & 0x40000000) rights.push("GENERIC_WRITE");
  if (access & 0x20000000) rights.push("GENERIC_EXECUTE");
  if (access & 0x10000000) rights.push("GENERIC_ALL");
  return rights.join("|") || `0x${access.toString(16)}`;
}

// Helper function to format share mode
function formatShareMode(share) {
  const modes = [];
  if (share & 0x1) modes.push("READ");
  if (share & 0x2) modes.push("WRITE");
  if (share & 0x4) modes.push("DELETE");
  return modes.join("|") || "NONE";
}

// Helper function to format creation disposition
function formatCreationDisposition(disposition) {
  const dispositions = {
    1: "CREATE_NEW",
    2: "CREATE_ALWAYS", 
    3: "OPEN_EXISTING",
    4: "OPEN_ALWAYS",
    5: "TRUNCATE_EXISTING"
  };
  return dispositions[disposition] || `UNKNOWN(${disposition})`;
}

// Comprehensive hooks for file, process, network, and registry APIs
const TARGET_HOOKS = {
  "kernel32.dll": {
    // File APIs
    "CreateFileW": {
      onEnter(args) {
        try {
          this.fileName = readUtf16(args[0]);
          this.access = args[1].toInt32();
          this.shareMode = args[2].toInt32();
          this.disposition = args[4].toInt32();
          
          log(`CreateFileW: "${this.fileName}" access=${formatAccessRights(this.access)} share=${formatShareMode(this.shareMode)} disposition=${formatCreationDisposition(this.disposition)}`);
        } catch (e) {
          log(`Error in CreateFileW: ${e.message}`);
        }
      },
      onLeave(retval) {
        if (retval.toInt32() !== -1) {
          send({
            type: "file_access",
            data: {
              operation: "CreateFileW",
              path: this.fileName,
              access: formatAccessRights(this.access),
              handle: retval.toString()
            }
          });
        }
      }
    },
    
    "CreateFileA": {
      onEnter(args) {
        try {
          this.fileName = readAnsi(args[0]);
          this.access = args[1].toInt32();
          log(`CreateFileA: "${this.fileName}" access=${formatAccessRights(this.access)}`);
        } catch (e) {
          log(`Error in CreateFileA: ${e.message}`);
        }
      }
    },

    "ReadFile": {
      onEnter(args) {
        this.bytesToRead = args[2].toInt32();
        log(`ReadFile: handle=${args[0]} bytes=${this.bytesToRead}`);
      },
      onLeave(retval) {
        if (retval.toInt32() !== 0 && this.args[3] && !this.args[3].isNull()) {
          const bytesRead = this.args[3].readU32();
          log(`ReadFile: success, read ${bytesRead} bytes`);
        }
      }
    },

    "WriteFile": {
      onEnter(args) {
        this.bytesToWrite = args[2].toInt32();
        log(`WriteFile: handle=${args[0]} bytes=${this.bytesToWrite}`);
      },
      onLeave(retval) {
        if (retval.toInt32() !== 0 && this.args[3] && !this.args[3].isNull()) {
          const bytesWritten = this.args[3].readU32();
          log(`WriteFile: success, wrote ${bytesWritten} bytes`);
        }
      }
    },

    "DeleteFileW": {
      onEnter(args) {
        const fileName = readUtf16(args[0]);
        log(`DeleteFileW: "${fileName}"`);
        send({
          type: "file_operation",
          data: {
            operation: "DELETE",
            path: fileName
          }
        });
      }
    },

    "MoveFileW": {
      onEnter(args) {
        const oldName = readUtf16(args[0]);
        const newName = readUtf16(args[1]);
        log(`MoveFileW: "${oldName}" -> "${newName}"`);
        send({
          type: "file_operation", 
          data: {
            operation: "MOVE",
            oldPath: oldName,
            newPath: newName
          }
        });
      }
    },

    "CopyFileW": {
      onEnter(args) {
        const source = readUtf16(args[0]);
        const dest = readUtf16(args[1]);
        log(`CopyFileW: "${source}" -> "${dest}"`);
      }
    },

    // Process APIs
    "CreateProcessW": {
      onEnter(args) {
        try {
          this.app = readUtf16(args[0]);
          this.cmd = readUtf16(args[1]);
          log(`CreateProcessW: app="${this.app}" cmd="${this.cmd}"`);
        } catch (e) {
          log(`Error in CreateProcessW: ${e.message}`);
        }
      },
      onLeave(retval) {
        if (retval.toInt32() !== 0) {
          const piPtr = this.args[9];
          if (piPtr && !piPtr.isNull()) {
            const processId = piPtr.add(Process.pointerSize * 2).readU32();
            send({
              type: "child_spawn",
              data: {
                application: this.app,
                command: this.cmd,
                pid: processId
              }
            });
          }
        }
      }
    },

    "OpenProcess": {
      onEnter(args) {
        const access = args[0].toInt32();
        const pid = args[2].toInt32();
        log(`OpenProcess: PID=${pid} access=0x${access.toString(16)}`);
      }
    },

    "TerminateProcess": {
      onEnter(args) {
        const exitCode = args[1].toInt32();
        log(`TerminateProcess: handle=${args[0]} exitCode=${exitCode}`);
      }
    },

    // Memory APIs
    "VirtualAllocEx": {
      onEnter(args) {
        const size = args[2].toInt32();
        const protect = args[4].toInt32();
        log(`VirtualAllocEx: process=${args[0]} size=${size} protect=0x${protect.toString(16)}`);
      }
    },

    "WriteProcessMemory": {
      onEnter(args) {
        const size = args[3].toInt32();
        log(`WriteProcessMemory: process=${args[0]} addr=${args[1]} size=${size}`);
      }
    },

    "ReadProcessMemory": {
      onEnter(args) {
        const size = args[3].toInt32();
        log(`ReadProcessMemory: process=${args[0]} addr=${args[1]} size=${size}`);
      }
    },

    // Thread APIs
    "CreateRemoteThread": {
      onEnter(args) {
        log(`CreateRemoteThread: process=${args[0]} startAddr=${args[2]}`);
      }
    },

    "CreateThread": {
      onEnter(args) {
        log(`CreateThread: startAddr=${args[2]} param=${args[3]}`);
      }
    },

    // Module APIs
    "LoadLibraryW": {
      onEnter(args) {
        const libName = readUtf16(args[0]);
        log(`LoadLibraryW: "${libName}"`);
        send({
          type: "library_load",
          data: { library: libName }
        });
      }
    },

    "LoadLibraryA": {
      onEnter(args) {
        const libName = readAnsi(args[0]);
        log(`LoadLibraryA: "${libName}"`);
      }
    },

    "GetProcAddress": {
      onEnter(args) {
        const procName = readAnsi(args[1]);
        log(`GetProcAddress: "${procName}"`);
      }
    },

    // Registry APIs - but with filtering due to extreme noise
    "RegOpenKeyExW": {
      onEnter(args) {
        const keyName = readUtf16(args[1]);
        log(`RegOpenKeyExW: "${keyName}"`, "RegOpenKeyExW");
      }
    },

    "RegCreateKeyExW": {
      onEnter(args) {
        const keyName = readUtf16(args[1]);
        log(`RegCreateKeyExW: "${keyName}"`, "RegCreateKeyExW");
      }
    },

    "RegSetValueExW": {
      onEnter(args) {
        const valueName = readUtf16(args[1]);
        const dataType = args[3].toInt32();
        log(`RegSetValueExW: "${valueName}" type=${dataType}`);
        // Don't throttle writes - they're more interesting
        send({
          type: "registry_write",
          data: {
            value: valueName,
            type: dataType
          }
        });
      }
    },

    "RegQueryValueExW": {
      onEnter(args) {
        const valueName = readUtf16(args[1]);
        log(`RegQueryValueExW: "${valueName}"`, "RegQueryValueExW");
      }
    },

    "RegDeleteKeyW": {
      onEnter(args) {
        const keyName = readUtf16(args[1]);
        log(`RegDeleteKeyW: "${keyName}"`);
        // Don't throttle deletes - always interesting
        send({
          type: "registry_delete",
          data: { key: keyName }
        });
      }
    },

    "RegDeleteValueW": {
      onEnter(args) {
        const valueName = readUtf16(args[1]);
        log(`RegDeleteValueW: "${valueName}"`);
        send({
          type: "registry_delete",
          data: { value: valueName }
        });
      }
    },

    // Network APIs
    "InternetOpenW": {
      onEnter(args) {
        const userAgent = readUtf16(args[0]);
        log(`InternetOpenW: userAgent="${userAgent}"`);
      }
    },

    "InternetConnectW": {
      onEnter(args) {
        const serverName = readUtf16(args[1]);
        const port = args[2].toInt32();
        log(`InternetConnectW: server="${serverName}" port=${port}`);
      }
    },

    "HttpOpenRequestW": {
      onEnter(args) {
        const verb = readUtf16(args[1]);
        const objectName = readUtf16(args[2]);
        log(`HttpOpenRequestW: ${verb} "${objectName}"`);
      }
    },

    "HttpSendRequestW": {
      onEnter(args) {
        const headers = readUtf16(args[1]);
        log(`HttpSendRequestW: headers="${headers}"`);
      }
    },

    // Crypto APIs
    "CryptAcquireContextW": {
      onEnter(args) {
        const container = readUtf16(args[1]);
        const provider = readUtf16(args[2]);
        log(`CryptAcquireContextW: container="${container}" provider="${provider}"`);
      }
    }
  },

  "kernelbase.dll": {
    // Most kernel32 functions are actually implemented here
    "CreateFileW": {
      onEnter(args) {
        try {
          this.fileName = readUtf16(args[0]);
          this.access = args[1].toInt32();
          log(`CreateFileW (KERNELBASE): "${this.fileName}" access=${formatAccessRights(this.access)}`);
        } catch (e) {
          log(`Error in CreateFileW (KERNELBASE): ${e.message}`);
        }
      }
    },
    
    "CreateProcessW": {
      onEnter(args) {
        try {
          this.app = readUtf16(args[0]);
          this.cmd = readUtf16(args[1]);
          log(`CreateProcessW (KERNELBASE): app="${this.app}" cmd="${this.cmd}"`);
        } catch (e) {
          log(`Error in CreateProcessW (KERNELBASE): ${e.message}`);
        }
      }
    }
  },

  "ntdll.dll": {
    "NtCreateFile": {
      onEnter(args) {
        try {
          // OBJECT_ATTRIBUTES is at args[2]
          const objAttrPtr = args[2];
          if (objAttrPtr && !objAttrPtr.isNull()) {
            const unicodeStringPtr = objAttrPtr.add(Process.pointerSize * 2); // ObjectName offset
            const pathPtr = unicodeStringPtr.readPointer();
            if (pathPtr && !pathPtr.isNull()) {
              const path = pathPtr.add(8).readPointer(); // Buffer in UNICODE_STRING
              if (path && !path.isNull()) {
                const fileName = readUtf16(path);
                log(`NtCreateFile: "${fileName}"`);
              }
            }
          }
        } catch (e) {
          log(`NtCreateFile called (error reading path: ${e.message})`);
        }
      }
    },

    "NtCreateThreadEx": {
      onEnter(args) {
        log(`NtCreateThreadEx: startAddr=${args[4]}`);
      }
    },

    "NtWriteVirtualMemory": {
      onEnter(args) {
        const size = args[4].toInt32();
        log(`NtWriteVirtualMemory: process=${args[0]} addr=${args[1]} size=${size}`);
      }
    },

    "NtMapViewOfSection": {
      onEnter(args) {
        log(`NtMapViewOfSection: section=${args[0]} process=${args[1]}`);
      }
    },

    // Filter out noisy APIs with throttling
    "NtQueryInformationProcess": {
      onEnter(args) {
        const infoClass = args[1].toInt32();
        log(`NtQueryInformationProcess: handle=${args[0]} class=${infoClass}`, "NtQueryInformationProcess");
      }
    },

    "NtOpenKey": {
      onEnter(args) {
        try {
          const objAttrPtr = args[2];
          if (objAttrPtr && !objAttrPtr.isNull()) {
            const unicodeStringPtr = objAttrPtr.add(Process.pointerSize * 2);
            const pathPtr = unicodeStringPtr.readPointer();
            if (pathPtr && !pathPtr.isNull()) {
              const path = pathPtr.add(8).readPointer();
              if (path && !path.isNull()) {
                const keyName = readUtf16(path);
                log(`NtOpenKey: "${keyName}"`, "NtOpenKey");
              }
            }
          }
        } catch (e) {
          log(`NtOpenKey called`, "NtOpenKey");
        }
      }
    },

    "NtQueryValueKey": {
      onEnter(args) {
        log(`NtQueryValueKey called`, "NtQueryValueKey");
      }
    }
  },

  "ws2_32.dll": {
    "WSAStartup": {
      onEnter(args) {
        const version = args[0].toInt32();
        log(`WSAStartup: version=0x${version.toString(16)}`);
      }
    },

    "socket": {
      onEnter(args) {
        const family = args[0].toInt32();
        const type = args[1].toInt32();
        const protocol = args[2].toInt32();
        log(`socket: family=${family} type=${type} protocol=${protocol}`);
      }
    },

    "connect": {
      onEnter(args) {
        try {
          const sockaddrPtr = args[1];
          if (sockaddrPtr && !sockaddrPtr.isNull()) {
            const family = sockaddrPtr.readU16();
            if (family === 2) { // AF_INET
              const port = ((sockaddrPtr.add(2).readU8() << 8) | sockaddrPtr.add(3).readU8());
              const ip = `${sockaddrPtr.add(4).readU8()}.${sockaddrPtr.add(5).readU8()}.${sockaddrPtr.add(6).readU8()}.${sockaddrPtr.add(7).readU8()}`;
              log(`connect: ${ip}:${port}`);
              send({
                type: "network_connection",
                data: { ip: ip, port: port }
              });
            }
          }
        } catch (e) {
          log(`connect: error parsing address: ${e.message}`);
        }
      }
    },

    "bind": {
      onEnter(args) {
        try {
          const sockaddrPtr = args[1];
          if (sockaddrPtr && !sockaddrPtr.isNull()) {
            const family = sockaddrPtr.readU16();
            if (family === 2) {
              const port = ((sockaddrPtr.add(2).readU8() << 8) | sockaddrPtr.add(3).readU8());
              log(`bind: port ${port}`);
            }
          }
        } catch (e) {
          log(`bind: error parsing address: ${e.message}`);
        }
      }
    },

    "send": {
      onEnter(args) {
        const len = args[2].toInt32();
        log(`send: ${len} bytes`);
      }
    },

    "recv": {
      onEnter(args) {
        this.buflen = args[2].toInt32();
      },
      onLeave(retval) {
        const received = retval.toInt32();
        if (received > 0) {
          log(`recv: received ${received}/${this.buflen} bytes`);
        }
      }
    }
  },

  "user32.dll": {
    "MessageBoxW": {
      onEnter(args) {
        const text = readUtf16(args[1]);
        const caption = readUtf16(args[2]);
        log(`MessageBoxW: "${text}" title="${caption}"`);
      }
    },

    "FindWindowW": {
      onEnter(args) {
        const className = readUtf16(args[0]);
        const windowName = readUtf16(args[1]);
        log(`FindWindowW: class="${className}" window="${windowName}"`);
      }
    },

    "SetWindowsHookExW": {
      onEnter(args) {
        const hookType = args[0].toInt32();
        log(`SetWindowsHookExW: type=${hookType} (potential keylogger)`);
      }
    }
  },

  "advapi32.dll": {
    "RegOpenKeyExW": {
      onEnter(args) {
        const keyName = readUtf16(args[1]);
        log(`RegOpenKeyExW (ADVAPI32): "${keyName}"`, "RegOpenKeyExW");
      }
    },

    "RegQueryValueExW": {
      onEnter(args) {
        const valueName = readUtf16(args[1]);
        log(`RegQueryValueExW (ADVAPI32): "${valueName}"`, "RegQueryValueExW");
      }
    },

    "RegSetValueExW": {
      onEnter(args) {
        const valueName = readUtf16(args[1]);
        const dataType = args[3].toInt32();
        log(`RegSetValueExW (ADVAPI32): "${valueName}" type=${dataType}`);
        send({
          type: "registry_write",
          data: {
            value: valueName,
            type: dataType
          }
        });
      }
    },

    "CryptAcquireContextW": {
      onEnter(args) {
        const container = readUtf16(args[1]);
        log(`CryptAcquireContextW: container="${container}"`);
      }
    },

    "OpenProcessToken": {
      onEnter(args) {
        const desiredAccess = args[1].toInt32();
        log(`OpenProcessToken: access=0x${desiredAccess.toString(16)}`);
      }
    }
  }
};

// Function hooking with forwarder detection
function hookFunctionByName(dllName, funcName, callbacks) {
  let funcAddr = getExportSafelyWithForwarderCheck(dllName, funcName);
  
  if (!funcAddr && dllName.toLowerCase() === 'kernel32.dll') {
    funcAddr = getExportSafely('kernelbase.dll', funcName);
  }
  
  if (!funcAddr) {
    return false;
  }

  try {
    // Validate the address before hooking
    const firstByte = funcAddr.readU8();
    
    Interceptor.attach(funcAddr, {
      onEnter(args) {
        this.args = args;
        if (callbacks && callbacks.onEnter) {
          callbacks.onEnter.call(this, args);
        } else {
          log(`Called ${funcName}`, funcName);
        }
      },
      onLeave(retval) {
        if (callbacks && callbacks.onLeave) {
          callbacks.onLeave.call(this, retval);
        }
      }
    });
    return true;
  } catch (e) {
    return false;
  }
}

function hookModuleFunctions(dllName, funcs) {
  let hookedCount = 0;
  let totalCount = 0;
  
  for (const [funcName, callbacks] of Object.entries(funcs)) {
    totalCount++;
    if (hookFunctionByName(dllName, funcName, callbacks)) {
      hookedCount++;
    }
  }
  
  log(`Hooked ${hookedCount}/${totalCount} functions in ${dllName}`);
}

function hookModule(dllName) {
  try {
    const module = Process.getModuleByName(dllName);
    hookModuleFunctions(dllName, TARGET_HOOKS[dllName] || {});
    return true;
  } catch (e) {
    return false;
  }
}

// Module loading hook to catch dynamically loaded modules
function setupModuleLoadHook() {
  const loadLibraryW = getExportSafelyWithForwarderCheck("kernel32.dll", "LoadLibraryW") ||
                       getExportSafely("kernelbase.dll", "LoadLibraryW");
  
  if (loadLibraryW) {
    Interceptor.attach(loadLibraryW, {
      onLeave(retval) {
        if (!retval.isNull()) {
          // Check if any of our target modules just loaded
          Object.keys(TARGET_HOOKS).forEach(dllName => {
            try {
              const module = Process.getModuleByName(dllName);
              if (module && !this.hookedModules?.has(dllName)) {
                log(`Newly loaded module detected: ${dllName}`);
                hookModule(dllName);
                if (!this.hookedModules) this.hookedModules = new Set();
                this.hookedModules.add(dllName);
              }
            } catch (e) {
              // Module not found yet
            }
          });
        }
      }
    });
  }
}

// Main hook setup function
function waitAndHook() {
  log("=== Starting Comprehensive Frida Hooks ===");
  log(`Log filtering: Throttling noisy APIs every ${LOG_CONFIG.throttle_interval} calls`);
  
  // Hook immediately available modules
  const modulesToHook = Object.keys(TARGET_HOOKS);
  const hookedModules = [];
  const pendingModules = [];
  
  modulesToHook.forEach(dllName => {
    if (hookModule(dllName)) {
      hookedModules.push(dllName);
    } else {
      pendingModules.push(dllName);
    }
  });
  
  log(`Successfully hooked modules: ${hookedModules.join(", ")}`);
  if (pendingModules.length > 0) {
    log(`Pending modules: ${pendingModules.join(", ")}`);
  }
  
  // Setup hook for dynamically loaded modules
  setupModuleLoadHook();
  
  log("=== Hook setup complete ===");
}

// Start the process
setTimeout(() => {
  //testBasicFunctionality();
  setTimeout(() => {
    waitAndHook();
  }, 500);
}, 100);