#!/usr/bin/env python3
import argparse
from kpnboxapi import KPNBoxAPI

class KPNBoxWithPortMapping(KPNBoxAPI):
    def add_port_mapping(self, external_port, internal_ip, internal_port=None, protocol="TCP", description="AutoRule"):
        if internal_port is None:
            internal_port = external_port
        action = self._get_action("WANIPConnection", "AddPortMapping")
        return action(
            NewRemoteHost="",
            NewExternalPort=external_port,
            NewProtocol=protocol,
            NewInternalPort=internal_port,
            NewInternalClient=internal_ip,
            NewEnabled=1,
            NewPortMappingDescription=description,
            NewLeaseDuration=0
        )

def main():
    parser = argparse.ArgumentParser(description="🔧 KPN Box Port Mapping CLI")
    parser.add_argument("--host", default="192.168.2.254", help="KPN Box URL")
    parser.add_argument("--user", default="admin", help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--external-port", type=int, required=True, help="External port to open")
    parser.add_argument("--internal-ip", required=True, help="Internal IP address to forward to")
    parser.add_argument("--internal-port", type=int, help="Internal port (defaults to external)")
    parser.add_argument("--protocol", choices=["TCP", "UDP"], default="TCP", help="Protocol type")
    parser.add_argument("--description", default="AutoRule", help="Rule description")

    args = parser.parse_args()

    try:
        box = KPNBoxWithPortMapping(host=args.host)
        box.login(username=args.user, password=args.password)

        result = box.add_port_mapping(
            external_port=args.external_port,
            internal_ip=args.internal_ip,
            internal_port=args.internal_port,
            protocol=args.protocol,
            description=args.description
        )

        print("✅ Port mapping added successfully:")
        print(result)
    except Exception as e:
        print("❌ Failed to add port mapping:")
        print(e)

if __name__ == "__main__":
    main()
