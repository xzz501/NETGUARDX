from scapy.all import *
def pachet_info(packet):
    if ARP in packet:
        arp=packet[ARP]
        print(f"sors ip :{arp.psrc} mac :{arp.hwsrc} :: dest ip :{arp.pdst} MAC :{arp.hwdst}")
    # print(str(packet.summary))

try:
    sniff(prn=pachet_info,store=0,count=0,timeout=60)
except KeyboardInterrupt:
    print("ree")
