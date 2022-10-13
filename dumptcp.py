#!/usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IP, Ether, Packet, wrpcap
from argparse import ArgumentParser
from dataclasses import dataclass
from termcolor import colored
from os import get_terminal_size, system, geteuid
from time import sleep

types = {
    "0x800":	"IPv4",
    "0x806":	"ARP",
    "0x842":	"Wake-on-LAN",
    "0x22F0":	"AVTP",
    "0x22F3":	"IETF TRILL Protocol",
    "0x22EA":	"Stream Reservation Protocol",
    "0x6002":	"DEC MOP RC",
    "0x6003":	"DECnet Phase IV, DNA Routing",
    "0x6004":	"DEC LAT",
    "0x8035":	"Reverse Address Resolution Protocol (RARP)",
    "0x809B":	"AppleTalk (Ethertalk)",
    "0x80F3":	"AppleTalk Address Resolution Protocol (AARP)",
    "0x8100":	"VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[9]",
    "0x8102":	"Simple Loop Prevention Protocol (SLPP)",
    "0x8103":	"Virtual Link Aggregation Control Protocol (VLACP)",
    "0x8137":	"IPX",
    "0x8204":	"QNX Qnet",
    "0x86DD":	"IPv6",
    "0x8808":	"Ethernet flow control",
    "0x8809":	"LACP",
    "0x8819":	"CobraNet",
    "0x8847":	"MPLS unicast",
    "0x8848":	"MPLS multicast",
    "0x8863":	"PPPoE Discovery Stage",
    "0x8864":	"PPPoE Session Stage",
    "0x887B":	"HomePlug 1.0 MME",
    "0x888E":	"IEEE 802.1X",
    "0x8892":	"PROFINET Protocol",
    "0x889A":	"HyperSCSI (SCSI over Ethernet)",
    "0x88A2":	"ATA over Ethernet",
    "0x88A4":	"EtherCAT Protocol",
    "0x88A8":	"Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel.",
    "0x88AB":	"Ethernet Powerlink[citation needed]",
    "0x88B8":	"GOOSE (Generic Object Oriented Substation event)",
    "0x88B9":	"GSE (Generic Substation Events) Management Services",
    "0x88BA":	"SV",
    "0x88BF":	"MikroTik RoMON",
    "0x88CC":	"LLDP",
    "0x88CD":	"SERCOS III",
    "0x88E1":	"HomePlug Green PHY",
    "0x88E3":	"IEC62439-2",
    "0x88E5":	"MACsec",
    "0x88E7":	"PBB",
    "0x88F7":	"PTP",
    "0x88F8":	"NC-SI",
    "0x88FB":	"PRP",
    "0x8902":	"CFM",
    "0x8906":	"FCoE",
    "0x8914":	"FCoE-I",
    "0x8915":	"RoCE",
    "0x891D":	"TTE",
    "0x893a":	"1905.1-IEEE-P",
    "0x892F":	"HSR",
    "0x9000":	"Ethernet Configuration Testing Protocol[11]",
    "0xF1C1":	"Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)"
}


def isSudo():
    """
    Checking if the euid of the process is 0 (root)
    """
    return geteuid() == 0

@dataclass
class PacketInfo():
    """
    Packet info is a data class that holds the relevent info about
    the packet we have sniffed.
    """
    layer:str           # The last layer in the packet.    
    content:bytes = b'' # The actual content of the packet in bytes
    length:int = 0      # The length of the packet.
    srcMac:str = ''     # The Ether src mac address.
    dstMac:str = ''     # The Ether dst mac address.
    srcIp:str = ''      # The Ip src ip address.
    dstIp:str = ''      # The Ip dst ip address.
    

def feedToPacketInfo(packet:Packet):
    layer = ""
    content = str(packet)
    length = len(content)
    srcMac:str = ''
    dstMac:str = ''
    srcIp:str = 'No Ip Header' 
    dstIp:str = 'No Ip Header'
    if packet.haslayer(Ether):
        srcMac = packet[Ether].dst
        dstMac = packet[Ether].src
        try:
            layer = types[hex(packet[Ether].type)]
        except:
            layer = "Unknown"
        if packet.haslayer(IP):
            srcIp = packet[IP].src
            dstIp = packet[IP].dst
    return PacketInfo(layer, content, length, srcMac, dstMac, srcIp, dstIp)

def handlePacket(packet:Packet)->None:
    """
    Handling the packet -> printing the values to the screen.
    """
    info = feedToPacketInfo(packet)
    t = colored(info.layer.center(20, ' '), "cyan")
    sip = colored(info.srcIp.center(15, ' '), "green") if info.srcIp != "No Ip Header" else colored(info.srcIp.center(15, ' '), "yellow")
    smac = colored(info.srcMac.center(17, ' '), "magenta")
    dip = colored(info.dstIp.center(15, ' '), "green") if info.dstIp != "No Ip Header" else colored(info.dstIp.center(15, ' '), "yellow")
    dmac = colored(info.dstMac.center(17, ' '), "magenta")
    l = colored(str(info.length).center(13, ' '), "cyan")
    print(f"[{t}] [ {sip} ] ({smac}) -> [ {dip} ] ({dmac}) [{l}]")

class Filters():
    def __init__(self,ip:str, mac:str) -> None:
        self.mac = mac
        self.ip = ip
        self.none = self.ip == "" and self.mac == ""
        self.activationFucntion = None
        if self.none == True:
            self.activationFucntion = self.NoFilter
        elif (self.mac != ""):
            self.activationFucntion = self.MacFilter
        else:
            self.activationFucntion = self.IpFilter

    def NoFilter(self, packet:Packet):
        return True

    def IpFilter(self, packet:Packet):
        return packet.haslayer(IP) and (packet[IP].src == self.ip or packet[IP].dst == self.ip)

    def MacFilter(self, packet:Packet):
        return packet.haslayer(Ether) and (packet[Ether].src == self.mac or packet[Ether].dst ==self.mac)

    def lfilter(self, packet:Packet):
        return self.activationFucntion(packet)

def bunner(output, filter:Filters):
    width = get_terminal_size().columns
    filter = str(filter.activationFucntion).split(" ")[2]
    output = output if output != "" else "No Output Filte"
    print("dumptcp".center(width, "-"))
    print("\tFilter: "+filter)
    print("\tOutput file: "+output)
    print("dumptcp".center(width, "-"))
    sleep(1)

def getArgs():
    parser = ArgumentParser(prog="dumptcp", description="A packet sniffer writen in python3.")
    parser.add_argument("iface", type=str, help="Specify the network interface you wish to use.")
    parser.add_argument("-i", "--ip", type=str, required=False, dest="ip", help="Specify if you want to capture packet only from or for a specific IP address.", default="")
    parser.add_argument("-m", "--mac", type=str, required=False, dest="mac", help="Specify if you want to capture packet only from or for a specific MAC address.", default="")
    parser.add_argument("-o", "--output", type=str, required=False, dest="output", help="Specify if you want to write to a .pcap file.", default="")
    return parser.parse_args()


def main()->int:
    "Main function"
    try:
        args = getArgs()
        if not isSudo():
            print(colored("sudo is required to sniff packets!", "red"))
            return 2
        t = colored("Packet Type".center(20, ' '), "cyan")
        sip = colored("Source IP".center(15, ' '), "green")
        smac = colored("Source MAC".center(17, ' '), "magenta")
        dip = colored("Dest IP".center(15, ' '), "green")
        dmac = colored("Dest MAC".center(17, ' '), "magenta")
        l = colored("Packet Length".center(13, ' '), "cyan") 
        f = Filters(args.ip, args.mac)
        bunner(args.output, f)
        print(f"[{t}] [ {sip} ] ({smac}) -> [ {dip} ] ({dmac}) [{l}]")
        sniffed = sniff(iface=args.iface,lfilter=f.lfilter, prn=handlePacket)
        print(f"\n\nCaptured {len(sniffed)} packets!")
        if args.output != "":
            print("\nWriting to "+colored(args.output, on_color="on_blue"))
            wrpcap(args.output, sniffed)
    except Exception as e:
        print(str(e))
        return 1
    print(colored("Done!", "blue", "on_green"))
    return 0


if __name__ == '__main__':
    exit(main())
