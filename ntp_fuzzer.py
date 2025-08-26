import socket
import random
import threading

# Server settings
HOST = "192.168.2.2"
PORT = 123  # NTP uses UDP port 123

# Generate fuzzed NTP response
def generate_fuzzed_response():
    # Normally NTP response is 48 bytes
    base = bytearray(48)

    # Fuzzing: inject random bytes or oversized payload
    fuzz_type = random.choice(["overflow", "inject", "corrupt"])

    if fuzz_type == "overflow":
        # Oversized payload to test buffer limits
        return bytes([random.randint(0, 255) for _ in range(1024)])
    elif fuzz_type == "inject":
        # Try command injection-like patterns in string fields
        injection = b";reboot;echo pwned;"
        base[40:40+len(injection)] = injection
        return bytes(base)
    else:
        # Corrupt fields with invalid values
        for i in range(len(base)):
            base[i] = random.randint(128, 255)
        return bytes(base)

# Handle incoming NTP request
def handle_request(data, addr, sock):
    print(f"[+] Received NTP request from {addr}")
    response = generate_fuzzed_response()
    sock.sendto(response, addr)
    print(f"[+] Sent fuzzed response ({len(response)} bytes)")

# Start UDP server
def start_ntp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[+] NTP server listening on {HOST}:{PORT}")

    while True:
        data, addr = sock.recvfrom(1024)
        threading.Thread(target=handle_request, args=(data, addr, sock)).start()

if __name__ == "__main__":
    start_ntp_server()
