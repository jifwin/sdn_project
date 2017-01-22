#!/bin/bash
for i in {1..6}
do
   echo "Turn on OpenFlow 1.3 support on s$i switch"
   sudo ovs-vsctl set bridge s$i protocols=OpenFlow13
done
