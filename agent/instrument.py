import threading
import frida
import json
import os
import subprocess
import time
from datetime import datetime

TARGET = r"C:\sample.exe"
HOOK_SCRIPT_PATH = "hooks.js"
LOG_DIR = "logs"

os.makedirs(LOG_DIR, exist_ok=True)

class FridaInstrument(threading.Thread):
    def __init__(self):
        super().__init__()
        self.running = True
        self.events = []
        self.attached_sessions = {}
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = os.path.join(LOG_DIR, f"frida_log_{timestamp_str}.json")
        self.device = frida.get_local_device()

    def log_event(self, event):
        event["timestamp"] = datetime.utcnow().isoformat()
        self.events.append(event)
        print(f"[Frida] [{event['timestamp']}] {event['type']}: {json.dumps(event, indent=2)}")

    def save_logs(self):
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(self.events, f, indent=2)
        print(f"[Frida] [+] Saved logs to {self.log_file}")

    def on_message(self, message, data):
        if message["type"] == "send":
            self.log_event(message["payload"])
        elif message["type"] == "error":
            print("[Frida] [!] Script error:", message["stack"])
    def inject(self, pid):
        print(f"[Frida] [*] Injecting into PID {pid}")
        try:
            session = self.device.attach(pid)
            with open(HOOK_SCRIPT_PATH, "r", encoding="utf-8") as f:
                script = session.create_script(f.read())
            script.on("message", self.on_message)
            script.load()
            self.attached_sessions[pid] = session
            print(f"[Frida] [+] Hooked PID {pid}")
        except Exception as e:
            print(f"[Frida] [!] Failed to inject into PID {pid}: {e}")
            
    def handle_spawn(self, spawn):
        print(f"[Frida] [+] Spawn detected: {spawn.identifier} (PID: {spawn.pid})")
        self.device.resume(spawn.pid)
        self.inject(spawn.pid)

    def run(self):
        pid = subprocess.Popen([TARGET]).pid 
        print(f"[Frida] [*] Launched process {TARGET} with PID {pid}")
        time.sleep(2)  # Allow time for process and modules to initialize
        self.inject(pid)

        print("[Frida] [*] Monitoring... Press Ctrl+C to stop.")
        while self.running:
            time.sleep(1)

        print("[Frida] [*] Exiting and saving logs...")
        self.save_logs()
        for session in self.attached_sessions.values():
            session.detach()

    def stop(self):
        self.running = False