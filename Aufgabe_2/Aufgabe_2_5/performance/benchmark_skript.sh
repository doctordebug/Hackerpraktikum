#!/bin/bash
TIMESTAMP=$(date +%s)
USERNAME=saenger
HOSTS="infcip"
SCRIPT="cd Hack_WEP/Hackerpraktikum/Aufgabe_2 && python3 ~/Hack_WEP/Hackerpraktikum/Aufgabe_2/benchmark.py"

for j in {0..5..1} ; do
	for i in {10..65..1} ; do
		echo "${i} wird angelegt"
		FILE="/home/saenger/Hack_WEP/Hackerpraktikum/benchmark_104/${TIMESTAMP}_${i}_${j}.txt"
		SCRIPT2="cat /proc/cpuinfo | grep -m 1 'model name' >> ${FILE}"
		(ssh -o StrictHostKeyChecking=no -l ${USERNAME} ${HOSTS}$i "${SCRIPT} > ${FILE} && ${SCRIPT2}" ) &
		echo "${i} beendet"
	done
done