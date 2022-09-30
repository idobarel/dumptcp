#/bin/bash
echo "Downloading the program..."
wget https://raw.githubusercontent.com/idobarel/dumptcp/main/dumptcp.py
echo "Installing dumptcp..."
wget https://raw.githubusercontent.com/idobarel/dumptcp/main/requirements.txt
pip3 install -r requirements.txt
python3 -m nuitka --clang dumptcp.py # Compiling the main.py file.
sleep 5
rm -rf dumptcp.build
sudo rm dumptcp.py
sudo rm requirements.txt
mv dumptcp.bin dumptcp
clear
echo "Complied"
echo "Creating a global executable (at /usr/bin/)..."
sudo mv dumptcp /usr/bin
echo "Done!"
echo "Run: dumptcp -h : to start!"
