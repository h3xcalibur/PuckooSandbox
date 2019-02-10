#!/usr/bin/env python

import socket
import os
import sys
import time
from shutil import copyfile

TCP_IP = '0.0.0.0'
TCP_PORT = 5005
BUFFER_SIZE = 3000  # Normally 1024, but we want fast response

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)
cur_malware_index = 0
homefolder = sys.argv[2]
screenfolder = homefolder + "/screenshots/"
malware_to_execute = sys.argv[1]
malware_name = malware_to_execute.split("/")[-1]

def main(argv):
	while 1:
		try:
			time.sleep(3)
			print 'Connecting to tcp client'
			conn, addr = s.accept()
			print 'Connection address:', addr
			data = conn.recv(BUFFER_SIZE)
			conn.send(malware_name)
			#if not data: break
			if data:
				print "received data:", data
				data = None
				f= open(malware_to_execute,'rb')
				l = f.read(1024)
				print('Sending malware to analysis machine...')
				while(l):
					conn.send(l)
					sys.stdout.write('..')
					sys.stdout.flush()
					l = f.read(1024)
				f.close()
				print("\nTransmission completed.")

#TODO: make sure the client send the screenshots
		time.sleep(100)
		print "copying screenshots from analysis machine"
		while (conn):
			num = 1
			scrpath = "puckoo_screen" + `num` + ".jpg"
			with open(scrpath, 'wb') as f:
				print "copying screenshot"
				while True:
					data = s.recv(1024)
					if not data:
						break
					f.write(data)
			f.close()
				
		data = None
		except Exception as e:
			#print "no connection available now. trying again.. "
			print(e)
			conn.close()

if __name__ == "__main__":
	#getting the following arguments: path of the virus, task id
	main(sys.argv[1:])

