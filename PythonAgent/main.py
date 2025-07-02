import time
import platform
from device_logger import DeviceLogger
from instrument import FridaInstrument
import utils

def main():
    CONFIG_PATH = "D:\\config.json"
    TARGET_PATH = "C:\\sample.exe"
    device_logger = DeviceLogger()
    frida_instrument = FridaInstrument()
    config = utils.load_config(CONFIG_PATH)
    if config == None: 
        print("[!] Something went wrong when loading config object")
        return
    utils.copy_malware_to_known_path(config["sampleName"], TARGET_PATH)
    device_logger.start()
    frida_instrument.start()
    print("[Main] All modules started. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[Main] Stopping all modules...")
        device_logger.stop()
        frida_instrument.stop()

        device_logger.join()
        frida_instrument.join()

        print("[Main] All modules stopped.")

if __name__ == "__main__":
    main()