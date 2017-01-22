#!bin/bash
NUMBER_OF_HOSTS=8

for j in $(seq 1 $NUMBER_OF_HOSTS);
do
	for i in $(seq 1 $NUMBER_OF_HOSTS); 
	do 
		if [ "$i" -ne "$j" ];
		then
			echo h$j arp -s 10.0.0.$i 00:00:00:00:00:0$i
		fi
	done
done
