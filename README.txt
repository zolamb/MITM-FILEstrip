Author: Zachary Lamb
__________________________

FILEstrip is to be run while MITM (Man In The Middle) with SSLstrip. 
Scapy library handles the packet information.

When a download request for an executable is made, the raw layer of that packet contains
various pieces of information about that download. FIILEstrip will use the link and name
of the file being download to begin generating a trojan. Once the trojan has been generated
through PyInstaller, the target will get a 503 http response to the original download request
and will be redirected to a new link where the trojan is stored. 

This trojan file is created by editing 'NAME' within trojan_filestrip so that it can open the correct
executable at runtime. The executable is combined with trojan_filestrip through PyInstaller.

Once the user runs the trojan, the real file is opened in the temp directory and a backdoor is generated.
