1.0 When running for the first time run setup.sh.
1.1 Run start-mininet.sh
2. Run openflow13-support.sh to support OpenFlow 1.3 (or install Mininet 2.2.0)
3. Run start-controller.sh
4. In mininet call pingall command and be happy :)


workaround for arp problem:
1. run mininet
2. run openflow13-support.sh
3. in mininet terminal run:
	h1 . set_arps.sh
	h2 . set_arps.sh
	....

	don't worry about error ;)

4. run contrller
5. test ping:
	h1 ping -c 1 h2
