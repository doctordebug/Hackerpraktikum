import struct
from pcap import PCAP
from wlan import IEEE802_11
from wep import WEP

mypcap = PCAP("../output-05.cap")
pcaph = mypcap.header()

print("Verison: " + `pcaph['major']` + "." + `pcaph['minor']`)
print("Type: " + pcaph['captypestring'] + "(" + `pcaph['captype']` + ") MaxLen: " + `pcaph['maxlen']`)

print("Number of Packets: " + `sum(1 for _ in mypcap)`)
for packet in mypcap:
	if packet['len'] == 68:
		#for debugging:
		# WEP( IEEE802_11(packet['data']).get_payload() ).print_wep()
		#for actual use:
		iv, k, ciphertext, icv = WEP( IEEE802_11(packet['data']).get_payload() ).get()
