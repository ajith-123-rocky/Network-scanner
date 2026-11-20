"""
Network Scanner - single-file version
Run: pip install customtkinter requests
     python network_scanner.py
"""

import socket
import subprocess
import platform
import re
import threading
import concurrent.futures

import requests
import customtkinter as ctk

# ---------------- Config ----------------
PING_TIMEOUT_MS = 800
MAX_WORKERS = 60

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLUMNS = ["Device Name", "IP Address", "MAC Address", "Vendor", "Status", "Distance (RTT)"]
COL_WIDTHS = [160, 130, 150, 160, 90, 120]

_vendor_cache = {}
VENDOR_API_URL = "https://api.macvendors.com/{}"


# ---------------- Vendor lookup ----------------
def get_vendor(mac):
    if not mac or mac == "Unknown":
        return "Unknown"
    if mac in _vendor_cache:
        return _vendor_cache[mac]
    try:
        response = requests.get(VENDOR_API_URL.format(mac), timeout=2)
        vendor = response.text.strip() if response.status_code == 200 and response.text.strip() else "Unknown"
    except Exception:
        vendor = "Unknown"
    _vendor_cache[mac] = vendor
    return vendor


# ---------------- Scanning logic ----------------
def get_local_ip_and_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    prefix = ".".join(local_ip.split(".")[:3])
    return local_ip, prefix


def ping_host(ip):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, PING_TIMEOUT_MS // 1000)), ip]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=(PING_TIMEOUT_MS / 1000) + 1, text=True
        )
    except Exception:
        return None

    if result.returncode != 0:
        return None

    match = re.search(r"time[=<]\s*([\d.]+)", result.stdout, re.IGNORECASE)
    return float(match.group(1)) if match else 0.1


def get_arp_table(subnet_prefix):
    try:
        output = subprocess.run(
            ["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        ).stdout
    except Exception:
        return {}

    table = {}
    pattern = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"
        r"([0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}"
        r"[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2})"
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            ip, mac = m.group(1), m.group(2).replace("-", ":").upper()
            if ip.startswith(subnet_prefix + "."):
                table[ip] = mac
    return table


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def scan_network():
    local_ip, prefix = get_local_ip_and_subnet()
    ips = [f"{prefix}.{i}" for i in range(1, 255)]

    rtt_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            rtt = future.result()
            if rtt is not None:
                rtt_map[ip] = rtt

    arp_table = get_arp_table(prefix)
    all_ips = set(rtt_map.keys()) | set(arp_table.keys())

    devices = []
    for ip in sorted(all_ips, key=lambda x: int(x.split(".")[-1])):
        mac = arp_table.get(ip, "Unknown")
        online = ip in rtt_map
        devices.append({
            "name": resolve_hostname(ip),
            "ip": ip,
            "mac": mac,
            "vendor": get_vendor(mac) if mac != "Unknown" else "Unknown",
            "status": "Online" if online else "Offline",
            "distance_ms": f"{rtt_map[ip]:.1f} ms" if online else "N/A",
        })
    return devices, local_ip


# ---------------- GUI ----------------
class NetworkScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Network Scanner")
        self.geometry("900x600")
        self.minsize(820, 500)

        self._build_header()
        self._build_table()

        self.after(200, self.start_scan)

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))

        ctk.CTkLabel(header, text="Network Scanner",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")

        self.scan_button = ctk.CTkButton(header, text="Scan", width=100, command=self.start_scan)
        self.scan_button.pack(side="right")

        self.status_label = ctk.CTkLabel(header, text="", text_color="#8a8a8a")
        self.status_label.pack(side="right", padx=15)

        info_row = ctk.CTkFrame(self, fg_color="transparent")
        info_row.pack(fill="x", padx=20)

        self.local_ip_label = ctk.CTkLabel(info_row, text="Local IP: -", anchor="w")
        self.local_ip_label.pack(side="left")

        self.count_label = ctk.CTkLabel(info_row, text="Devices found: 0", anchor="e",
                                         font=ctk.CTkFont(weight="bold"))
        self.count_label.pack(side="right")

    def _build_table(self):
        container = ctk.CTkFrame(self)
        container.pack(fill="both", expand=True, padx=20, pady=10)

        header_row = ctk.CTkFrame(container, fg_color="#1f1f1f")
        header_row.pack(fill="x")
        for col_name, width in zip(COLUMNS, COL_WIDTHS):
            ctk.CTkLabel(header_row, text=col_name, width=width,
                         font=ctk.CTkFont(weight="bold"), anchor="w").pack(side="left", padx=5, pady=8)

        self.table_frame = ctk.CTkScrollableFrame(container, fg_color="#141414")
        self.table_frame.pack(fill="both", expand=True)

    def start_scan(self):
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.status_label.configure(text="Scanning local network...")
        threading.Thread(target=self._run_scan_thread, daemon=True).start()

    def _run_scan_thread(self):
        error = None
        try:
            devices, local_ip = scan_network()
        except Exception as e:
            devices, local_ip = [], "-"
            error = str(e)
        self.after(0, lambda: self._on_scan_complete(devices, local_ip, error))

    def _on_scan_complete(self, devices, local_ip, error):
        self.scan_button.configure(state="normal", text="Scan")
        self.local_ip_label.configure(text=f"Local IP: {local_ip}")
        self.status_label.configure(text=f"Scan failed: {error}" if error else "Scan complete")

        self._populate_table(devices)
        self.count_label.configure(text=f"Devices found: {len(devices)}")

    def _populate_table(self, devices):
        for widget in self.table_frame.winfo_children():
            widget.destroy()

        for i, device in enumerate(devices):
            row_color = "#1a1a1a" if i % 2 == 0 else "#141414"
            row = ctk.CTkFrame(self.table_frame, fg_color=row_color)
            row.pack(fill="x")

            status_color = "#2ecc71" if device["status"] == "Online" else "#e74c3c"
            values = [device["name"], device["ip"], device["mac"],
                      device["vendor"], device["status"], device["distance_ms"]]

            for val, width, col_name in zip(values, COL_WIDTHS, COLUMNS):
                color = status_color if col_name == "Status" else None
                ctk.CTkLabel(row, text=val, width=width, anchor="w",
                             text_color=color).pack(side="left", padx=5, pady=6)


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()