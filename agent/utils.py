from win32 import win32file
import os
import json

def copy_malware_to_known_path(source_path: str, dest_path: str) -> bool:
    try:
        win32file.CopyFile(source_path, dest_path, 0)
        print("[+] Successfully copied malware to path.")
        return True
    except Exception as e:
        print(f"[!] Failed to copy malware to target path: {str(e)}")
        return False

def load_config(config_path: str):
    if not os.path.exists(config_path):
        log(f"[!] Failed to open config: {config_path}")
        return

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)
    except Exception as e:
        log(f"[!] Invalid JSON config: {str(e)}")
        return
    return {"executionTime": config_data["executionTime"], "sampleName": config_data["sampleName"]}

def move_logs_to_safe_dir():
    source_dir = f"./logs/"
    dest_dir = f"D:/execution_logs/"
    os.makedirs(dest_dir, exist_ok=True)
    if os.path.exists(source_dir):
        for file in os.listdir(source_dir):
                    win32file.CopyFile(os.path.join(source_dir, file), os.path.join(dest_dir, file), 0)
        print(f"[Main] Logs moved to {dest_dir}")
    else:
        print(f"[!] Log source directory not found: {source_dir}")
