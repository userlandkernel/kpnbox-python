#!/usr/bin/env python3
"""
Sagecom DHCP Fuzzer - Fixed version with proper byte handling
"""

import socket
import struct
import random
import time
import threading
import argparse
import sys
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import ipaddress
import logging
import concurrent.futures

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dhcp_fuzzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

@dataclass
class FuzzingResult:
    """Store fuzzing test results"""
    test_id: int
    payload: bytes
    response: Optional[bytes]
    response_time: float
    success: bool
    error: Optional[str] = None
    crash_detected: bool = False

class SagecomDHCPFuzzer:
    def __init__(self, target_ip: str, interface: str = None, 
                 timeout: int = 2, max_threads: int = 10):
        self.target_ip = target_ip
        self.interface = interface
        self.timeout = timeout
        self.max_threads = max_threads
        self.results: List[FuzzingResult] = []
        self.running = False
        self.test_counter = 0
        self.crash_counter = 0
        
        # Common Sagecom router ports
        self.dhcp_ports = [67, 68, 546, 547]
        
        # Setup socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)

    def safe_bytes(self, values: List[int]) -> bytes:
        """Ensure all byte values are within 0-255 range"""
        safe_values = [v % 256 for v in values]
        return bytes(safe_values)

    def generate_dhcp_discover(self, fuzz_level: int = 1) -> bytes:
        """Generate a DHCP Discover packet with various fuzzing techniques"""
        
        # Base DHCP Discover packet
        base_packet = (
            # OP Code
            self.safe_bytes([0x01]) +  # BOOTREQUEST
            # HTYPE
            self.safe_bytes([0x01]) +  # Ethernet
            # HLEN
            self.safe_bytes([0x06]) +  # MAC length
            # HOPS
            self.safe_bytes([0x00]) +
            # XID (Transaction ID)
            struct.pack('!I', random.randint(1, 0xFFFFFFFF)) +
            # SECS
            struct.pack('!H', 0) +
            # FLAGS
            struct.pack('!H', 0x8000) +  # Broadcast flag
            # CIADDR (Client IP)
            self.safe_bytes([0] * 4) +
            # YIADDR (Your IP)
            self.safe_bytes([0] * 4) +
            # SIADDR (Server IP)
            self.safe_bytes([0] * 4) +
            # GIADDR (Gateway IP)
            self.safe_bytes([0] * 4) +
            # CHADDR (Client MAC)
            self.safe_bytes([random.randint(0, 255) for _ in range(6)]) +
            # Padding
            self.safe_bytes([0] * 10) +
            # Server name
            self.safe_bytes([0] * 64) +
            # Boot file name
            self.safe_bytes([0] * 128) +
            # Magic cookie
            self.safe_bytes([0x63, 0x82, 0x53, 0x63])
        )
        
        # DHCP Options
        options = b''
        
        # Message type option (Discover)
        options += self.safe_bytes([53, 1, 1])  # DHCP Discover
        
        # Parameter request list
        param_request = [1, 3, 6, 15, 28, 42, 51, 58, 59]  # Common parameters
        options += self.safe_bytes([55, len(param_request)]) + self.safe_bytes(param_request)
        
        # Client identifier
        client_id = self.safe_bytes([1]) + self.safe_bytes([random.randint(0, 255) for _ in range(6)])
        options += self.safe_bytes([61, len(client_id)]) + client_id
        
        # Hostname (fuzzed)
        hostname = self.fuzz_string("test-client", fuzz_level)
        hostname_bytes = hostname.encode('latin-1', errors='ignore')[:255]
        options += self.safe_bytes([12, len(hostname_bytes)]) + hostname_bytes
        
        # End option
        options += self.safe_bytes([255])
        
        return base_packet + options

    def fuzz_string(self, base_string: str, fuzz_level: int) -> str:
        """Generate fuzzed strings with safe characters"""
        if fuzz_level == 0:
            return base_string
            
        fuzz_types = [
            # Random ASCII strings
            lambda: ''.join(chr(random.randint(32, 126)) for _ in range(random.randint(1, 100))),
            # Long strings
            lambda: 'A' * random.randint(100, 1000),
            # Format strings
            lambda: '%s' * random.randint(10, 50),
            # Special characters (ASCII only)
            lambda: ''.join(chr(random.randint(1, 127)) for _ in range(random.randint(1, 50))),
            # Null bytes
            lambda: '\x00' * random.randint(1, 50),
            # Numbers
            lambda: ''.join(str(random.randint(0, 9)) for _ in range(random.randint(1, 100))),
        ]
        
        if random.random() < 0.3 or fuzz_level > 2:
            result = random.choice(fuzz_types)()
            # Ensure result is ASCII safe
            return ''.join(c for c in result if ord(c) < 128)
        return base_string

    def generate_malformed_packets(self) -> List[bytes]:
        """Generate various malformed DHCP packets"""
        packets = []
        
        # 1. Empty packet
        packets.append(b'')
        
        # 2. Very short packet
        packets.append(b'\x01\x01\x06')
        
        # 3. Reasonable length packet (not too big)
        packets.append(b'\x01' * 300)
        
        # 4. Invalid magic cookie
        base = self.generate_dhcp_discover(0)
        malformed = base[:-4] + b'\x00\x00\x00\x00'  # Wrong magic cookie
        packets.append(malformed)
        
        # 5. Invalid options
        base = self.generate_dhcp_discover(0)
        malformed = base + b'\x00' * 50  # Extra garbage
        packets.append(malformed)
        
        # 6. Overflow transaction ID (but safe)
        overflow_packet = (
            base[:4] +  # First 4 bytes
            b'\xFF\xFF\xFF\xFF' +  # Max transaction ID
            base[8:]  # Rest of packet
        )
        packets.append(overflow_packet)
        
        # 7. Negative values in options
        negative_packet = base + self.safe_bytes([255, 255])  # Option 255, length 255
        packets.append(negative_packet)
        
        return packets

    def send_dhcp_packet(self, packet: bytes, port: int = 67) -> Optional[bytes]:
        """Send DHCP packet and wait for response"""
        try:
            self.sock.sendto(packet, (self.target_ip, port))
            
            start_time = time.time()
            response, addr = self.sock.recvfrom(4096)
            response_time = time.time() - start_time
            
            return response
            
        except socket.timeout:
            return None
        except Exception as e:
            logging.error(f"Error sending packet: {e}")
            return None

    def analyze_response(self, response: bytes) -> Dict[str, Any]:
        """Analyze DHCP response for anomalies"""
        analysis = {
            'has_response': response is not None,
            'response_length': len(response) if response else 0,
            'is_dhcp': False,
            'message_type': None,
            'anomalies': []
        }
        
        if not response or len(response) < 240:
            return analysis
            
        try:
            # Check magic cookie
            if len(response) >= 244 and response[236:240] == b'\x63\x82\x53\x63':
                analysis['is_dhcp'] = True
                
                # Try to parse options
                options_start = 240
                while options_start < len(response):
                    option = response[options_start]
                    if option == 0:  # Padding
                        options_start += 1
                        continue
                    if option == 255:  # End
                        break
                    
                    if options_start + 1 < len(response):
                        length = response[options_start + 1]
                        if option == 53 and length == 1 and options_start + 2 < len(response):
                            analysis['message_type'] = response[options_start + 2]
                        
                        options_start += 2 + length
                    else:
                        break
                        
        except Exception as e:
            analysis['anomalies'].append(f"Parse error: {e}")
            
        return analysis

    def run_fuzz_test(self, test_id: int, packet: bytes) -> FuzzingResult:
        """Run a single fuzz test"""
        if not self.running:
            return FuzzingResult(test_id, packet, None, 0, False, "Fuzzer stopped")
        
        start_time = time.time()
        response = None
        error = None
        crash_detected = False
        
        try:
            # Send to all DHCP ports
            for port in self.dhcp_ports:
                response = self.send_dhcp_packet(packet, port)
                if response:
                    break
                    
            response_time = time.time() - start_time
            
            # Check for potential crashes (no response to multiple probes)
            if response is None:
                # Send follow-up packet to check if service is responsive
                time.sleep(0.1)
                test_packet = self.generate_dhcp_discover(0)
                test_response = self.send_dhcp_packet(test_packet, 67)
                
                if test_response is None:
                    crash_detected = True
                    self.crash_counter += 1
                    logging.critical(f"CRASH DETECTED in test {test_id}! Service may be down.")
            
            analysis = self.analyze_response(response)
            if analysis['anomalies']:
                logging.warning(f"Anomalies in test {test_id}: {analysis['anomalies']}")
                
            return FuzzingResult(
                test_id=test_id,
                payload=packet,
                response=response,
                response_time=response_time,
                success=response is not None,
                error=error,
                crash_detected=crash_detected
            )
            
        except Exception as e:
            error = str(e)
            logging.error(f"Error in test {test_id}: {error}")
            return FuzzingResult(
                test_id=test_id,
                payload=packet,
                response=None,
                response_time=time.time() - start_time,
                success=False,
                error=error,
                crash_detected=False
            )

    def generate_test_cases(self, count: int) -> List[bytes]:
        """Generate various test cases"""
        test_cases = []
        
        # Add malformed packets
        test_cases.extend(self.generate_malformed_packets())
        
        # Add various fuzz levels
        for fuzz_level in range(5):
            for _ in range(count // 5):
                test_cases.append(self.generate_dhcp_discover(fuzz_level))
        
        # Add specific Sagecom attack vectors (safe versions)
        sagecom_specific = [
            self.create_overflow_packet('hostname', 500),
            self.create_invalid_option_lengths(),
            self.create_repeated_options(),
        ]
        test_cases.extend(sagecom_specific)
        
        return test_cases[:count]

    def create_overflow_packet(self, field: str, length: int) -> bytes:
        """Create packet with overflow in specific field"""
        base = self.generate_dhcp_discover(0)
        
        if field == 'hostname':
            # Safe overflow data (ASCII only)
            overflow_data = b'A' * min(length, 1000)  # Limit to 1000 bytes
            # Create new option
            new_option = self.safe_bytes([12, len(overflow_data)]) + overflow_data
            # Append to existing options (before end marker)
            if base.endswith(b'\xff'):
                return base[:-1] + new_option + b'\xff'
        
        return base

    def create_invalid_option_lengths(self) -> bytes:
        """Create packet with invalid option lengths"""
        base = self.generate_dhcp_discover(0)
        # Add option with incorrect length
        invalid_option = self.safe_bytes([12, 10]) + b'A' * 5  # Length 10 but only 5 bytes
        if base.endswith(b'\xff'):
            return base[:-1] + invalid_option + b'\xff'
        return base

    def create_repeated_options(self) -> bytes:
        """Create packet with repeated options"""
        base = self.generate_dhcp_discover(0)
        # Add multiple hostname options
        repeated = (self.safe_bytes([12, 5]) + b'test1' + 
                   self.safe_bytes([12, 5]) + b'test2' + 
                   self.safe_bytes([12, 5]) + b'test3')
        if base.endswith(b'\xff'):
            return base[:-1] + repeated + b'\xff'
        return base

    def start_fuzzing(self, test_count: int = 1000):
        """Start the fuzzing process"""
        self.running = True
        self.test_counter = 0
        self.crash_counter = 0
        
        logging.info(f"Starting Sagecom DHCP fuzzer against {self.target_ip}")
        logging.info(f"Generating {test_count} test cases...")
        
        test_cases = self.generate_test_cases(test_count)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for i, test_case in enumerate(test_cases):
                if not self.running:
                    break
                    
                future = executor.submit(self.run_fuzz_test, i, test_case)
                futures.append(future)
                self.test_counter += 1
                
                # Throttle to avoid overwhelming the target
                if i % 100 == 0:
                    time.sleep(0.1)
                    logging.info(f"Progress: {i}/{len(test_cases)} tests")
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                self.results.append(result)
                
                if result.crash_detected:
                    logging.critical(f"CRASH CONFIRMED in test {result.test_id}")
        
        self.running = False
        self.generate_report()

    def generate_report(self):
        """Generate fuzzing report"""
        total_tests = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        crashes = sum(1 for r in self.results if r.crash_detected)
        errors = sum(1 for r in self.results if r.error)
        
        report = f"""
        === SAGECOM DHCP FUZZING REPORT ===
        Target: {self.target_ip}
        Total tests: {total_tests}
        Successful responses: {successful}
        Potential crashes: {crashes}
        Errors: {errors}
        Test duration: {sum(r.response_time for r in self.results):.2f}s
        
        CRASHES DETECTED: {crashes}
        """
        
        logging.info(report)
        
        # Save detailed results
        with open('fuzzing_results.txt', 'w') as f:
            f.write(report)
            for result in self.results:
                if result.crash_detected or result.error:
                    f.write(f"\nTest {result.test_id}: {result.error or 'CRASH'}")
        
        print(report)

    def stop(self):
        """Stop fuzzing"""
        self.running = False
        logging.info("Fuzzing stopped by user")

def main():
    parser = argparse.ArgumentParser(description="Sagecom DHCP Fuzzer")
    parser.add_argument("target", help="Target router IP address")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-c", "--count", type=int, default=1000, help="Number of test cases")
    parser.add_argument("-T", "--timeout", type=int, default=2, help="Socket timeout")
    
    args = parser.parse_args()
    
    # Warning
    print("""
    ⚠️  WARNING: This tool is for educational and research purposes only.
    ⚠️  Do not use on networks without explicit permission.
    ⚠️  Fuzzing may cause service disruptions.
    """)
    
    fuzzer = SagecomDHCPFuzzer(
        target_ip=args.target,
        timeout=args.timeout,
        max_threads=args.threads
    )
    
    try:
        fuzzer.start_fuzzing(args.count)
    except KeyboardInterrupt:
        print("\nStopping fuzzer...")
        fuzzer.stop()
    except Exception as e:
        logging.error(f"Fatal error: {e}")

if __name__ == "__main__":
    main()