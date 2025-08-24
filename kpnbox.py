import os
import sys
import json
import requests
from bs4 import BeautifulSoup as Soup

class KPNBoxV10:

	def __init__(self, ip="192.168.2.254"):
		self.ip = ip
		self.url = f"http://{ip}"
		self.s = requests.Session()
		resp = self.s.get(self.url)
		self.cookies = resp.cookies
		self.headers = {"Content-Type":"application/json"}
		self.message = {"service":None,"method":"get","parameters":{}}
		self.deviceInfo = self.DeviceInfoService(box = self)
		self.httpService = self.HTTPService(box = self)
		self.mss = self.MSSService(box = self)
		self.mssConfig = self.MSSConfigService(box = self)
		self.nmc = self.NMCService(box = self)
		self.nmcDevices = self.NMCDevicesService(box = self)
		self.devices = self.DevicesService(box = self)

	def Login(self, username=None, password=None):
		url = self.url + "/ws/NeMo/Intf/lan:getMIBs"
		self.message["service"] = "sah.Device.Information"
		self.message["method"] = "createContext"
		self.message["parameters"] = {"applicationName":"KPN Box v10 Python Framework", "username":username,"password":password}
		oldHeaders = self.headers
		self.headers["Content-Type"] = "application/x-sah-ws-4-call+js"
		self.headers["Authorization"] = "X-Sah-Login"
		rsp = self.s.post(url, headers=self.headers, cookies=self.cookies, json=self.message)
		data = rsp.json()
		self.headers["Content-Type"] = "application/json"
		self.headers["Authorization"] = None
		self.message["parameters"] = {}
		if "result" in data.keys():
			if "errors" in data["result"].keys():
				if data["result"]["errors"][0]["error"] == 13:
					return False
				else:
					print(data["result"]["errors"][0])
			else:
				print(data["result"])
		else:
			if "data" in data.keys():
				if "contextID" in data["data"].keys():
					self.headers["X-Context"] = data["data"]["contextID"]
					return True
				else:
					print("Login failed: Missing contextID")
					return False
			else:
				print("Login failed: Unknown error")

	class DeviceInfoService:
		def __init__(self, box = None):
			self.box = box
			self.service = "DeviceInfo"
			self.url = self.box.url + "/ws/NeMo/Intf/lan:getMIBs"

		def Default(self):
			self.box.message["service"] = self.service
			self.box.message["method"] = "get"
			resp = self.box.s.post(self.url, headers=self.box.headers, cookies=self.box.cookies, json=self.box.message)
			return resp.json()

	class HTTPService:
		def __init__(self, box = None):
			self.box = box
			self.service = "HTTPService"
			self.url = self.box.url + "/ws/NeMo/Intf/lan:getMIBs"

		def GetCurrentUser(self):
			self.box.message["service"] = self.service
			self.box.message["method"] = "getCurrentUser"
			resp = self.box.s.post(self.url, headers=self.box.headers, cookies=self.box.cookies, json=self.box.message)
			return resp.json()

	class MSSService:
		def __init__(self, box = None):
			self.box = box
			self.service = "MSS"
			self.url = self.box.url + "/ws/NeMo/Intf/lan:getMIBs"

		def Default(self):
			self.box.message["service"] = self.service
			self.box.message["method"] = "get"
			resp = self.box.s.post(self.url, headers=self.box.headers, cookies=self.box.cookies, json=self.box.message)
			return resp.json()

	class MSSConfigService:
		def __init__(self, box = None):
			self.box = box
			self.service = "MSS.Config"
			self.url = self.box.url + "/ws/NeMo/Intf/lan:getMIBs"

		def Default(self):
			self.box.message["service"] = self.service
			self.box.message["method"] = "get"
			resp = self.box.s.post(self.url, headers=self.box.headers, cookies=self.box.cookies, json=self.box.message)
			return resp.json()

	class NMCService:
		def __init__(self, box = None):
			self.box = box
			self.service = "NMC"
			self.url = self.box.url + "/ws/NeMo/Intf/lan:getMIBs"

		def GetWanStatus(self):
			self.box.message["service"] = self.service
			self.box.message["method"] = "getWANStatus"
			resp = self.box.s.post(self.url, headers=self.box.headers, cookies=self.box.cookies, json=self.box.message)
			return resp.json()

	class NMCDevicesService:
		def __init__(self, box = None):
			self.box = box
			self.service = "NMC.Devices"
			self.url = self.box.url + "/ws/NeMo/Intf/lan:getMIBs"

		def FindSSW(self):
			self.box.message["service"] = self.service
			self.box.message["method"] = "findSSW"
			resp = self.box.s.post(self.url, headers=self.box.headers, cookies=self.box.cookies, json=self.box.message)
			return resp.json()

	class DevicesService:
		def __init__(self, box = None, expression=""):
			self.box = box
			self.service = "Devices"
			self.url = self.box.url + "/ws/NeMo/Intf/lan:getMIBs"

		def Default(self, expression={}):
			self.box.message["service"] = self.service
			self.box.message["method"] = "get"
			self.box.message["parameters"] = {"expression": expression}
			self.box.message["flags"] = "full_links"
			self.box.headers["Content-Type"] = "application/x-sah-ws-4-call+json"
			resp = self.box.s.post(self.url, headers=self.box.headers, cookies=self.box.cookies, json=self.box.message)
			self.box.headers["Content-Type"] = "application/json"
			self.box.message["parameters"] = {}
			self.box.message["flags"] = None
			return resp.json()

if __name__ == "__main__":
	kpnBox = KPNBoxV10()
	print("Login: ", kpnBox.Login(username="admin", password="MODEM_PASSWORD_HERE"))
	print(kpnBox.deviceInfo.Default())
	print(kpnBox.httpService.GetCurrentUser())
	print(kpnBox.mss.Default())
	print(kpnBox.mssConfig.Default())
	print(kpnBox.nmc.GetWanStatus())
	print(kpnBox.nmcDevices.FindSSW())
	print(kpnBox.devices.Default(expression={"wifi":"not interface and wifi and .Active==true", "ethernet":"not interface and eth and .Active==true"}))
