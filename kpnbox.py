import tkinter as tk
from tkhtmlview import HTMLLabel
from tkinter import ttk, messagebox
import requests
import json
import argparse
import sys

# ─── KPNBoxV10 Class ────────────────────────────────────────────────────────────
class KPNBoxV10:
    def __init__(self, ip="192.168.2.254"):
        self.ip = ip
        self.base_url = f"http://{ip}"
        self.api_url = f"{self.base_url}/ws/NeMo/Intf/lan:getMIBs"
        self.session = requests.Session()
        self.cookies = self.session.get(self.base_url).cookies
        self.headers = {"Content-Type": "application/json"}
        self.context_id = None

        self.deviceInfo = self.DeviceInfoService(self)
        self.httpService = self.HTTPService(self)
        self.mss = self.MSSService(self)
        self.mssConfig = self.MSSConfigService(self)
        self.nmc = self.NMCService(self)
        self.nmcDevices = self.NMCDevicesService(self)
        self.devices = self.DevicesService(self)

    def _call(self, service, method, parameters=None, content_type="application/x-sah-ws-4-call+json"):
        self.headers["Content-Type"] = content_type
        payload = {"service": service, "method": method, "parameters": parameters or {}}
        if self.context_id:
            self.headers["X-Context"] = self.context_id
        response = self.session.post(self.api_url, headers=self.headers, cookies=self.cookies, json=payload)
        self.headers["Content-Type"] = "application/json"
        return response.json()

    def login(self, username, password):
        self.headers["Authorization"] = "X-Sah-Login"
        response = self._call(
            "sah.Device.Information", "createContext",
            {"applicationName": "KPN Box v10 Python Framework", "username": username, "password": password},
            content_type="application/x-sah-ws-4-call+js"
        )
        self.headers["Authorization"] = None
        self.context_id = response.get("data", {}).get("contextID")
        return bool(self.context_id)

    def set_port_forwarding(self, rule_id, internal_ip, internal_port, external_port=None, protocol="6", description="Port Forward"):
        external_port = external_port or internal_port
        return self._call("Firewall", "setPortForwarding", {
            "id": rule_id,
            "internalPort": str(internal_port),
            "externalPort": str(external_port),
            "destinationIPAddress": str(internal_ip),
            "enable": True,
            "persistent": True,
            "protocol": protocol,
            "description": description,
            "sourceInterface": "data",
            "origin": "webui",
            "destinationMACAddress": "",
            "sourcePrefix": internal_ip
        })

    class DeviceInfoService:
        def __init__(self, box): self.box = box
        def default(self): return self.box._call("DeviceInfo", "get", {}, content_type="application/json")

    class HTTPService:
        def __init__(self, box): self.box = box
        def get_current_user(self): return self.box._call("HTTPService", "getCurrentUser", content_type="application/json")

    class MSSService:
        def __init__(self, box): self.box = box
        def default(self): return self.box._call("MSS", "get", content_type="application/json")

    class MSSConfigService:
        def __init__(self, box): self.box = box
        def default(self): return self.box._call("MSS.Config", "get", content_type="application/json")

    class NMCService:
        def __init__(self, box): self.box = box
        def get_wan_status(self): return self.box._call("NMC", "getWANStatus", content_type="application/json")

    class NMCDevicesService:
        def __init__(self, box): self.box = box
        def find_ssw(self): return self.box._call("NMC.Devices", "findSSW", content_type="application/json")

    class DevicesService:
        def __init__(self, box): self.box = box
        def default(self, expression={}):
            return self.box._call("Devices", "get", {"expression": expression}, content_type="application/x-sah-ws-4-call+json")

# ─── GUI Functions ──────────────────────────────────────────────────────────────
def show_result(frame, data):
    for widget in frame.winfo_children():
        widget.destroy()

    def render_html(obj):
        if isinstance(obj, dict):
            html = ""
            for key, value in obj.items():
                html += f"<details><summary><b>{key}</b></summary>{render_html(value)}</details>"
            return html
        elif isinstance(obj, list):
            html = ""
            for i, item in enumerate(obj):
                html += f"<details><summary><b>Item {i+1}</b></summary>{render_html(item)}</details>"
            return html
        else:
            return f"<div style='margin-left:20px;'>{str(obj)}</div>"

    html_content = f"""
    <html>
    <body style='font-family:Arial; font-size:14px;'>
        {render_html(data)}
    </body>
    </html>
    """

    label = HTMLLabel(frame, html=html_content)
    label.pack(fill="both", expand=True, padx=10, pady=10)



def launch_dashboard(box):
    root = tk.Tk()
    root.title("KPN Box Dashboard")
    root.geometry("1000x700")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    tabs = {
        "Device Info": lambda: box.deviceInfo.default(),
        "Current User": lambda: box.httpService.get_current_user(),
        "MSS": lambda: box.mss.default(),
        "MSS Config": lambda: box.mssConfig.default(),
        "WAN Status": lambda: box.nmc.get_wan_status(),
        "Find SSW": lambda: box.nmcDevices.find_ssw(),
        "Devices": lambda: box.devices.default(expression={
            "wifi": "not interface and wifi and .Active==true",
            "ethernet": "not interface and eth and .Active==true"
        }),
        "Port Forwarding": None
    }

    tab_frames = {}
    result_frames = {}

    for name, func in tabs.items():
        frame = tk.Frame(notebook)
        notebook.add(frame, text=name)

        if name == "Port Forwarding":
            form = {
                "Rule ID": "HTTP",
                "Internal IP": "192.168.2.2",
                "Internal Port": "80",
                "External Port": "80",
                "Protocol": "6",
                "Description": "HTTP"
            }
            entries = {}
            for i, (label, default) in enumerate(form.items()):
                tk.Label(frame, text=label).grid(row=i, column=0, sticky="e", padx=5, pady=2)
                entry = tk.Entry(frame, width=40)
                entry.insert(0, default)
                entry.grid(row=i, column=1, padx=5, pady=2)
                entries[label] = entry

            def submit():
                try:
                    result = box.set_port_forwarding(
                        rule_id=entries["Rule ID"].get(),
                        internal_ip=entries["Internal IP"].get(),
                        internal_port=int(entries["Internal Port"].get()),
                        external_port=int(entries["External Port"].get()),
                        protocol=entries["Protocol"].get(),
                        description=entries["Description"].get()
                    )
                    messagebox.showinfo("Result", json.dumps(result, indent=2))
                except Exception as e:
                    messagebox.showerror("Error", str(e))

            tk.Button(frame, text="Add Port Forwarding", command=submit).grid(row=len(form), columnspan=2, pady=10)
        else:
            result_frame = tk.Frame(frame)
            result_frame.pack(fill="both", expand=True, padx=10, pady=10)
            tab_frames[frame] = func
            result_frames[frame] = result_frame

    def on_tab_changed(event):
        selected_tab = event.widget.select()
        selected_frame = event.widget.nametowidget(selected_tab)
        if selected_frame in tab_frames:
            try:
                result = tab_frames[selected_frame]()
                data = result.get("data", result)
                show_result(result_frames[selected_frame], data)
            except Exception as e:
                messagebox.showerror("Error", str(e))

    notebook.bind("<<NotebookTabChanged>>", on_tab_changed)
    root.mainloop()

def run_login(args):
    login_root = tk.Tk()
    login_root.title("KPN Box Login")
    login_root.geometry("400x200")

    fields = {
        "Router IP": "192.168.2.254",
        "Username": args.user,
        "Password": args.password
    }
    entries = {}

    for i, (label, default) in enumerate(fields.items()):
        tk.Label(login_root, text=label).grid(row=i, column=0, sticky="e", padx=5, pady=5)
        entry = tk.Entry(login_root, width=30, show="*" if label == "Password" else None)
        entry.insert(0, default)
        entry.grid(row=i, column=1, padx=5, pady=5)
        entries[label] = entry  # ✅ Store entry by label

    def try_login():
        box = KPNBoxV10(ip=entries["Router IP"].get())
        if box.login(entries["Username"].get(), entries["Password"].get()):
            login_root.destroy()
            launch_dashboard(box)
        else:
            messagebox.showerror("Login Failed", "Could not log in to KPN Box")

    tk.Button(login_root, text="Login", command=try_login).grid(row=len(fields), columnspan=2, pady=10)
    login_root.mainloop()


# ─── CLI Mode ───────────────────────────────────────────────────────────────────
def run_cli(args):
    box = KPNBoxV10(ip=args.host)
    if not box.login(args.user, args.password):
        print("❌ Login failed")
        sys.exit(1)

    result = box.set_port_forwarding(
        rule_id=args.rule_id,
        internal_ip=args.internal_ip,
        internal_port=args.internal_port,
        external_port=args.external_port,
        protocol=args.protocol,
        description=args.description
    )

    if result.get("status") == "success":
        print("✅ Port forwarding rule added successfully")
    else:
        print("❌ Failed to add rule:")
        print(json.dumps(result, indent=2))

# ─── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KPN Box Control Panel")
    parser.add_argument("--gui", action="store_true", help="Launch GUI dashboard")
    parser.add_argument("--host", default="192.168.2.254", help="Router IP address")
    parser.add_argument("--user", default="admin", help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--rule-id", default="HTTP", help="Rule ID")
    parser.add_argument("--internal-ip", help="Internal IP address")
    parser.add_argument("--internal-port", type=int, help="Internal port")
    parser.add_argument("--external-port", type=int, help="External port")
    parser.add_argument("--protocol", default="6", help="Protocol (6=TCP, 17=UDP)")
    parser.add_argument("--description", default="HTTP", help="Rule description")

    args = parser.parse_args()

    # 🧠 Enforce required arguments only if not in GUI mode
    if not args.gui:
        missing = []
        for arg_name in ["internal_ip", "internal_port", "external_port"]:
            if getattr(args, arg_name) is None:
                missing.append(f"--{arg_name.replace('_', '-')}")

        if missing:
            print(f"❌ Missing required arguments: {', '.join(missing)}")
            parser.print_help()
            sys.exit(1)

        run_cli(args)
    else:
        run_login(args)
