import struct

class IEEE802_11:
	def __init__( self, packet ):
		self.frame = self.parse_frame( packet )

	def get_payload( self ):
		return self.frame['payload']

	def parse_frame( self, packet ):
		frame = {}
		frame['Version'] 		= packet[0] & 0b00000011
		frame['Type'] 		= (packet[0] & 0b00001100) >> 2
		frame['SubType'] 		= (packet[0] & 0b11110000) >> 4
		frame['toDS'] 		= (packet[1] & 0b00000001) == 0b00000001
		frame['fromDS'] 		= (packet[1] & 0b00000010) == 0b00000010
		frame['moreFragments']= (packet[1] & 0b00000100) == 0b00000100
		frame['retry']		= (packet[1] & 0b00001000) == 0b00001000
		frame['pwrmgt']		= (packet[1] & 0b00010000) == 0b00010000
		frame['moreData']		= (packet[1] & 0b00100000) == 0b00100000
		frame['protected']	= (packet[1] & 0b01000000) == 0b01000000
		frame['order']		= (packet[1] & 0b10000000) == 0b10000000
		frame['duration']	= struct.unpack('h', packet[2:4])[0] 
		
		frame['fragmentnum']= (struct.unpack('h', packet[22:24])[0] & 0b1111000000000000) >> 12
		frame['sequenznum']= (struct.unpack('h', packet[22:24])[0] & 0b0000111111111111) >> 12

		Adress1 = packet[4:10]
		Adress2 = packet[10:16]
		Adress3 = packet[16:22]
		Adress4 = packet[24:30]

		if not frame['toDS'] and not frame['fromDS']:
			frame['DA'] = Adress1
			frame['SA'] = Adress2
			frame['RA'] = None
			frame['TA'] = None
			frame['BSSID'] = Adress3
			frame['payload'] = packet[24:-4]
		elif not frame['toDS'] and frame['fromDS']:
			frame['DA'] = Adress1
			frame['SA'] = Adress3
			frame['RA'] = None
			frame['TA'] = None
			frame['BSSID'] = Adress2
			frame['payload'] = packet[24:-4]
		elif frame['toDS'] and not frame['fromDS']:
			frame['DA'] = Adress3
			frame['SA'] = Adress2
			frame['RA'] = None
			frame['TA'] = None
			frame['BSSID'] = Adress1
			frame['payload'] = packet[24:-4]
		elif frame['toDS'] and frame['fromDS']:
			frame['DA'] = Adress3
			frame['SA'] = Adress4
			frame['RA'] = Adress1
			frame['TA'] = Adress2
			frame['BSSID'] = None
			frame['payload'] = packet[30:-4]
		return frame

	def print_meta( self ):
		print("Version: " + `self.frame['Version']`)
		print("Type: " + `self.frame['Type']`)
		print("SubType: " + `self.frame['SubType']`)
		print("toDS: " + `self.frame['toDS']`)
		print("fromDS: " + `self.frame['fromDS']`)
		print("moreFragments: " + `self.frame['moreFragments']`)
		print("retry: " + `self.frame['retry']`)
		print("pwrmgt: " + `self.frame['pwrmgt']`)
		print("moreData: " + `self.frame['moreData']`)
		print("protected: " + `self.frame['protected']`)
		print("order: " + `self.frame['order']`)
		print("fragmentnum: " + `self.frame['fragmentnum']`)
		print("sequenznum: " + `self.frame['sequenznum']`)
		if self.frame['DA']:
			print "DA: " + ''.join(format(x, '02x') for x in self.frame['DA'])
		if self.frame['SA']:
			print "SA: " + ''.join(format(x, '02x') for x in self.frame['SA'])
		if self.frame['RA']:
			print "RA: " + ''.join(format(x, '02x') for x in self.frame['RA'])
		if self.frame['TA']:
			print "TA: " + ''.join(format(x, '02x') for x in self.frame['TA'])
		if self.frame['BSSID']:
			print "BSSID: " +''.join(format(x, '02x') for x in self.frame['BSSID'])
