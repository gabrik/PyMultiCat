import socket as sck
import time
import sys

HOST = 'localhost'
PORT = 8001
MESSAGE = 'Ciao'

addr = (HOST,PORT)
host=sys.argv[1]

addr = (host,8001)
sock = sck.socket(sck.AF_INET,sck.SOCK_DGRAM)
print "Sending to " , host , PORT , MESSAGE

while True:
    print "Sending to " , HOST , PORT , MESSAGE
    sock.sendto(MESSAGE, addr)
    time.sleep(1)
