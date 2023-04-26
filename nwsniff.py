from scapy.all import *
from scapy.layers.inet import IP
import datetime

filename = "packet_data.txt"


def packet_callback(packet):
    if packet[IP].src == 'fill in your ip address here':
        with open(filename, "a") as f:
            now = datetime.datetime.now()
            f.write(now.strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write(str(packet) + "\n")
            if Raw in packet:
                f.write(packet[Raw].load.hex() + "\n\n")
            else:
                f.write("\n")


sniff(prn=packet_callback, filter="ip",
      iface="Fill in your interface name here")
