import tkinter as tk
from tkinter import ttk, messagebox
from kpnboxapi import KPNBoxAPI

class KPNBoxGUI:
    def __init__(self, root):
        self.api = KPNBoxAPI(host="192.168.2.254")
        self.api.login(username="admin", password="your_password")  # Replace with actual credentials

        self.root = root
        self.root.title("KPN Box Control Panel")
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(expand=1, fill="both")

        self.build_status_tab()
        self.build_wifi_tab()
        self.build_dhcp_tab()
        self.build_port_tab()
        self.build_device_tab()

    def build_status_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Status")

        info = self.api.get_device_info()
        ttk.Label(tab, text=f"Model: {info['ModelName']}").pack()
        ttk.Label(tab, text=f"Firmware: {info['SoftwareVersion']}").pack()
        ttk.Label(tab, text=f"WAN IP: {self.api.get_wan_ip()}").pack()
        ttk.Label(tab, text=f"Uptime: {info['Uptime']}").pack()

    def build_wifi_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="WiFi")

        wifi = self.api.get_wifi_network()
        self.ssid_var = tk.StringVar(value=wifi["SSID"])
        self.pass_var = tk.StringVar(value=wifi["Security"]["KeyPassphrase"])
        self.enabled_var = tk.BooleanVar(value=(wifi["VAPStatus"] == "Enabled"))

        ttk.Label(tab, text="SSID").pack()
        ttk.Entry(tab, textvariable=self.ssid_var).pack()

        ttk.Label(tab, text="Password").pack()
        ttk.Entry(tab, textvariable=self.pass_var, show="*").pack()

        ttk.Checkbutton(tab, text="WiFi Enabled", variable=self.enabled_var).pack()

        ttk.Button(tab, text="Apply", command=self.apply_wifi).pack(pady=5)

    def apply_wifi(self):
        ssid = self.ssid_var.get()
        password = self.pass_var.get()
        enabled = self.enabled_var.get()
        config = {
            "SSID": ssid,
            "Security": {"ModeEnabled": "WPA2-Personal", "KeyPassphrase": password},
            "VAPStatus": "Enabled" if enabled else "Disabled"
        }
        self.api.set_wifi_network(config)
        messagebox.showinfo("WiFi", "Configuration applied.")

    def build_dhcp_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="DHCP")

        dhcp = self.api.get_dhcp_settings()
        self.start_var = tk.StringVar(value=dhcp["Start"])
        self.end_var = tk.StringVar(value=dhcp["End"])
        self.lease_var = tk.StringVar(value=str(dhcp["LeaseTime"]))

        ttk.Label(tab, text="Start IP").pack()
        ttk.Entry(tab, textvariable=self.start_var).pack()

        ttk.Label(tab, text="End IP").pack()
        ttk.Entry(tab, textvariable=self.end_var).pack()

        ttk.Label(tab, text="Lease Time (sec)").pack()
        ttk.Entry(tab, textvariable=self.lease_var).pack()

        ttk.Button(tab, text="Apply", command=self.apply_dhcp).pack(pady=5)

    def apply_dhcp(self):
        start = self.start_var.get()
        end = self.end_var.get()
        lease = int(self.lease_var.get())
        self.api.set_dhcp_settings(start=start, end=end, lease_time=lease)
        messagebox.showinfo("DHCP", "Settings updated.")

    def build_port_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Port Forwarding")

        self.port_list = tk.Listbox(tab)
        self.port_list.pack(fill="both", expand=True)
        self.refresh_ports()

        self.ext_var = tk.StringVar()
        self.int_var = tk.StringVar()
        self.proto_var = tk.StringVar(value="TCP")

        ttk.Label(tab, text="External Port").pack()
        ttk.Entry(tab, textvariable=self.ext_var).pack()

        ttk.Label(tab, text="Internal IP").pack()
        ttk.Entry(tab, textvariable=self.int_var).pack()

        ttk.Label(tab, text="Protocol").pack()
        ttk.Combobox(tab, textvariable=self.proto_var, values=["TCP", "UDP"]).pack()

        ttk.Button(tab, text="Add", command=self.add_port).pack()
        ttk.Button(tab, text="Delete Selected", command=self.delete_port).pack()

    def refresh_ports(self):
        self.port_list.delete(0, tk.END)
        for rule in self.api.get_port_mappings():
            self.port_list.insert(tk.END, f"{rule['ExternalPort']} → {rule['InternalClient']} ({rule['Protocol']})")

    def add_port(self):
        ext = int(self.ext_var.get())
        ip = self.int_var.get()
        proto = self.proto_var.get()
        self.api.add_port_mapping(external_port=ext, internal_client=ip, protocol=proto)
        self.refresh_ports()

    def delete_port(self):
        selection = self.port_list.curselection()
        if selection:
            line = self.port_list.get(selection[0])
            ext_port = int(line.split("→")[0].strip())
            self.api.delete_port_mapping(external_port=ext_port)
            self.refresh_ports()

    def build_device_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Devices")

        self.device_list = tk.Listbox(tab, selectmode=tk.MULTIPLE)
        self.device_list.pack(fill="both", expand=True)
        self.refresh_devices()

        ttk.Button(tab, text="Delete Selected", command=self.delete_devices).pack()

    def refresh_devices(self):
        self.device_list.delete(0, tk.END)
        for dev in self.api.get_devices():
            status = "Active" if dev["Active"] else "Inactive"
            self.device_list.insert(tk.END, f"{dev['IPAddress']} - {dev['Name']} ({status})")

    def delete_devices(self):
        selected = self.device_list.curselection()
        for i in selected:
            line = self.device_list.get(i)
            ip = line.split(" - ")[0]
            self.api.delete_device(ip)
        self.refresh_devices()

if __name__ == "__main__":
    root = tk.Tk()
    app = KPNBoxGUI(root)
    root.mainloop()
