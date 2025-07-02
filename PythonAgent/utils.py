from win32 import win32file

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
    