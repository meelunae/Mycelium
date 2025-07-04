import threading
import sys
import os
import logging
from datetime import datetime
from scapy.all import (
    sniff, Raw, IP, TCP, UDP, DNS, DNSQR, DNSRR,
    get_if_list, wrpcap
)
from fakenet import fakenet

class NetworkMonitor(threading.Thread):
    def __init__(self, interface=None, log_file="logs/network_log.txt", pcap_file="logs/network_capture.pcap", fakenet_config=None, duration=None):
        super().__init__()
        self.interface = interface or self._auto_detect_interface()
        self.log_file = log_file
        self.pcap_file = pcap_file
        self.fakenet_config = fakenet_config
        self.duration = duration
        self._stop_event = threading.Event()
        self._packets = []
        self._setup_logger()

    def _auto_detect_interface(self):
        interfaces = get_if_list()
        if len(interfaces) == 2:
            return interfaces[0]
        for name in interfaces:
            if "Ethernet" in name or "Wi-Fi" in name or "eth0" in name or "en0" in name:
                return name
        raise RuntimeError(f"Unable to auto-detect interface. Found: {interfaces}")

    def _setup_logger(self):
        self.logger = logging.getLogger("NetworkMonitor")
        self.logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler(self.log_file, mode="w", encoding="utf-8")
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def run(self):
        self._start_fakenet()
        self._start_sniffing()
        self._save_pcap()
        self._extract_iocs()

    def _start_fakenet(self):
        def run_fakenet():
            sys.argv = ['fakenet']
            if self.fakenet_config:
                sys.argv += ['-c', self.fakenet_config]
            try:
                fakenet.main()
            except SystemExit:
                pass
        self.fakenet_thread = threading.Thread(target=run_fakenet, daemon=True)
        self.fakenet_thread.start()
        self.logger.info("[*] FakeNet-NG started")

    def _start_sniffing(self):
        self.logger.info(f"[*] Starting packet sniffing on: {self.interface}")
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=True,
            timeout=self.duration,
            stop_filter=lambda _: self._stop_event.is_set(),
            lfilter=lambda p: IP in p
        )

    def _process_packet(self, packet):
        try:
            self._packets.append(packet)  # Save for pcap
            proto = "OTHER"
            src_ip = dst_ip = size = content = "-"

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                size = len(packet)

            if packet.haslayer(DNS):
                proto = "DNS"
                dns = packet[DNS]
                if dns.qr == 0 and dns.qd:
                    content = f"Query: {dns.qd.qname.decode()}"
                elif dns.qr == 1 and dns.an:
                    content = f"Response: {dns.an.rdata}"

            elif packet.haslayer(Raw):
                raw_data = packet[Raw].load
                if b"HTTP" in raw_data or b"GET" in raw_data or b"POST" in raw_data:
                    proto = "HTTP"
                    content = raw_data.decode(errors="ignore").strip().replace("\n", "\\n")[:200]
                else:
                    content = raw_data.hex()[:100]

            elif TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"

            self.logger.info(
                f"[{proto}] {src_ip} → {dst_ip} | {size} bytes | {content}"
            )

        except Exception as e:
            self.logger.warning(f"Error processing packet: {e}")

    def _save_pcap(self):
        try:
            wrpcap(self.pcap_file, self._packets)
            self.logger.info(f"[*] Saved capture to {self.pcap_file}")
        except Exception as e:
            self.logger.error(f"[!] Failed to save PCAP: {e}")

    def _extract_iocs(self, ioc_file="iocs.txt"):
    ips = set()
    domains = set()
    urls = set()

    for pkt in self._packets:
        if IP in pkt:
            ips.add(pkt[IP].dst)

        if pkt.haslayer(DNS) and pkt[DNS].qd:
            try:
                domains.add(pkt[DNS].qd.qname.decode())
            except Exception:
                continue

        if pkt.haslayer(Raw):
            try:
                raw = pkt[Raw].load.decode(errors="ignore")
                if "Host:" in raw or "GET" in raw or "POST" in raw:
                    lines = raw.split("\r\n")
                    host = path = ""
                    for line in lines:
                        if line.startswith("Host:"):
                            host = line.split("Host:")[1].strip()
                        if line.startswith("GET") or line.startswith("POST"):
                            parts = line.split(" ")
                            if len(parts) > 1:
                                path = parts[1]
                    if host and path:
                        urls.add(f"http://{host}{path}")
            except Exception:
                continue

    with open(ioc_file, "w", encoding="utf-8") as f:
        f.write("== IPs ==\n" + "\n".join(sorted(ips)) + "\n\n")
        f.write("== Domains ==\n" + "\n".join(sorted(domains)) + "\n\n")
        f.write("== URLs ==\n" + "\n".join(sorted(urls)) + "\n")
    
    self.logger.info(f"[*] Extracted IOCs saved to {ioc_file}")

    def stop(self):
        self.logger.info("[*] Stopping NetworkMonitor...")
        self._stop_event.set()