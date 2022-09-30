#!/usr/bin/env python3
from scapy.all import sniff, IP, Ether, Packet, wrpcap
from argparse import ArgumentParser
from dataclasses import dataclass
from termcolor import colored
from os import get_terminal_size, system, geteuid
from time import sleep


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
    layer = str(packet.layers()[-1]).split(".")[-1].replace("'>", "")
    content = str(packet)
    length = len(content)
    srcMac:str = ''
    dstMac:str = ''
    srcIp:str = 'No Ip Header' 
    dstIp:str = 'No Ip Header'
    if packet.haslayer(Ether):
        srcMac = packet[Ether].dst
        dstMac = packet[Ether].src
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
