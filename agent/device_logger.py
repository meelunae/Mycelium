import threading
from win32 import win32file
import win32con
import struct
import json
import os
import time
from datetime import datetime

DEVICE_PATH = r"\\.\Mycelium"
IOCTL_GET_LOG_ENTRY = 0x222000  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# C++ LOG_ENTRY structure with padding:
# LARGE_INTEGER Timestamp;      // 8 bytes
# ULONG EventType;             // 4 bytes  
# ULONG ProcessId;             // 4 bytes
# ULONG ThreadId;              // 4 bytes
# ULONG ParentProcessId;       // 4 bytes
# WCHAR ImagePath[260];        // 520 bytes (260 * 2)
# WCHAR CommandLine[512];      // 1024 bytes (512 * 2)  
# WCHAR RegistryPath[260];     // 520 bytes (260 * 2)
# UCHAR Encrypted;             // 1 byte
# + 7 bytes padding to align to 8-byte boundary (2096 total)

LOG_ENTRY_SIZE = 2096

def read_wstring(raw_bytes):
    return raw_bytes.decode("utf-16le", errors="ignore").split('\x00')[0]

def parse_log_entry(data):
    # Handle different possible sizes
    if len(data) == 2085:
        fmt = "<Q4I520s1024s520sB"
    elif len(data) == 2088:
        fmt = "<Q4I520s1024s520sB3x"
    elif len(data) == 2089:
        fmt = "<Q4I520s1024s520sB4x"
    elif len(data) == 2092:
        fmt = "<Q4I520s1024s520sB3x"  # 4-byte aligned
    elif len(data) == 2096:
        fmt = "<Q4I520s1024s520sB7x"  # 8-byte aligned (7 bytes padding)
    else:
        # Let's debug what we're actually getting
        print(f"Unexpected data size: {len(data)} bytes")
        print(f"First 64 bytes as hex: {data[:64].hex()}")
        print(f"Last 32 bytes as hex: {data[-32:].hex()}")
        raise ValueError(f"Unexpected data size: {len(data)} bytes")
    
    try:
        ts, evt_type, pid, tid, ppid, img_raw, cmd_raw, reg_raw, encrypted = struct.unpack(fmt, data)
        return {
            "Timestamp": ts,
            "EventType": evt_type,
            "ProcessId": pid,
            "ThreadId": tid,
            "ParentProcessId": ppid,
            "ImagePath": read_wstring(img_raw),
            "CommandLine": read_wstring(cmd_raw),
            "RegistryPath": read_wstring(reg_raw),
            "Encrypted": bool(encrypted)
        }
    except struct.error as e:
        print(f"Struct unpack error: {e}")
        print(f"Format: {fmt}, Data size: {len(data)}")
        raise
class DeviceLogger(threading.Thread):
    def __init__(self):
        super().__init__()
        self.running = True
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = os.path.join(LOG_DIR, f"log_{timestamp_str}.json")
        self.hDevice = None

    def open_device(self):
        try:
            self.hDevice = win32file.CreateFileW(
                DEVICE_PATH,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )
            print(f"[MyceliumLogger] Opened device {DEVICE_PATH}")
            return True
        except Exception as e:
            print(f"[MyceliumLogger] Could not open device: {e}")
            return False

    def read_log_entry(self):
        try:
            output = win32file.DeviceIoControl(
                self.hDevice,
                IOCTL_GET_LOG_ENTRY,
                None,
                LOG_ENTRY_SIZE,
                None
            )
            if len(output) == 0:
                return None
            return parse_log_entry(output)
        except Exception as e:
            if "The operation completed successfully" not in str(e):
                print(f"[MyceliumLogger] IOCTL failed: {e}")
            return None

    def log_to_file(self, log):
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log, ensure_ascii=False) + '\n')

    def run(self):
        if not self.open_device():
            print("[MyceliumLogger] Exiting thread due to device open failure.")
            return

        print(f"[MyceliumLogger] Logging started — saving to {self.log_file}")
        while self.running:
            log = self.read_log_entry()
            if log:
                timestamp = datetime.fromtimestamp(log["Timestamp"] / 1e7 - 11644473600)
                log["TimestampISO"] = timestamp.isoformat()
                print(f"[MyceliumLogger] [{timestamp}] PID={log['ProcessId']} EVT={log['EventType']} Path={log['ImagePath']}")
                self.log_to_file(log)
                print(log)
            time.sleep(0.1)

    def stop(self):
        self.running = False
        if self.hDevice:
            win32file.CloseHandle(self.hDevice)
            print("[MyceliumLogger] Closed device handle")