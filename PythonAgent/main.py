import time
import platform
from device_logger import DeviceLogger
from instrument import FridaInstrument
from network_logger import NetworkMonitor
import utils

def main():
    CONFIG_PATH = "D:\\config.json"
    TARGET_PATH = "C:\\sample.exe"

    config = utils.load_config(CONFIG_PATH)
    if config == None: 
        print("[!] Something went wrong when loading config object")
        return

    exec_time = config["executionTime"] 

    device_logger = DeviceLogger()
    frida_instrument = FridaInstrument()
    network_monitor = NetworkMonitor(duration=config[executionTime], fakenet_config="fakenet.ini")

    utils.copy_malware_to_known_path(config["sampleName"], TARGET_PATH)
    device_logger.start()
    network_monitor.start()
    frida_instrument.start()
    print("[Main] All modules started. Press Ctrl+C to stop.")

    start_time = time.time()

    try:
        while time.time() - start_time < exec_time:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[Main] Interrupted by user. Stopping early...")

    print("[Main] Execution time reached or interrupted. Stopping modules...")
        device_logger.stop()
        network_monitor.stop()
        frida_instrument.stop()

        device_logger.join()
        network_monitor.join()
        frida_instrument.join()

        utils.move_logs_to_safe_dir()

        print("[Main] All modules stopped. Analysis completed.")

if __name__ == "__main__":
    main()