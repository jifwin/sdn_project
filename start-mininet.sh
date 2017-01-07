sudo mn -c
sudo mn --topo linear,3 --mac --switch ovsk,protocols=OpenFlow13 --controller remote
#sudo mn --custom ./topology/fattree.py --topo fattree --mac --switch ovsk,protocols=OpenFlow13 --controller remote
