# dumptcp
## The packet sniffer
written in python3, dumptcp will let you sniff packets of a given interface!

# Usage
## Installation:
### Installer:
```bash
$ sudo sh -c "$(wget -qO- https://raw.githubusercontent.com/idobarel/dumptcp/main/installer.sh)" # to run the installer
dumptcp -h # to get the help menu
```
### Github:
```bash
git clone https://github.com/idobarel/dumptcp.git #clone the repo
cd dumptcp # navigate into the directory
pip3 install -r requirements.txt # install the requirements. 
chmod +x dumptcp.py # give execute permissions
./dumptcp.py -h # run the app!
```

## Syntax
the _-h_ argument should give you all the options in the app. but I would like to put it here as well;

### Args:
iface -> required | possitinal arg, no flag. | Takes the network adapter you want to use. <br>
output -> not required | -o OR --output flag | defualt = None. | Specify with file name if you want to write the captured packets to a .pcap file<br>
ip -> not required | -i OR --ip flag | defualt = "". | An IP filter, only capture traffic that related to the specified IP address (sender OR reciver)<br>
mac -> not required | -m OR --mac flag | defualt = "". | A MAC filter, only capture traffic that related to the specified MAC address (sender OR reciver)<br>

### Command syntax:
dumptcp [ IFACE ] [ ARGS... ]

### Examples:
```bash
$ dumptcp eth0 -o out.pcap 
```
will capture all the packets, and write to a pcap file.
```bash
$ dumptcp eth0 -o out.pcap -i 10.0.0.10
```
will capture all the packets that sent or recived by the IP address: 10.0.0.10, and write to a pcap file.

# Notice
I do not promote any illigal actions, please do not use this script for malicuse activities!

# _hope yall having a blast_🫶
