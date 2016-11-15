import struct
from wlan import IEEE802_11

class WEP:
	def __init__( self, packet ):
		self.wep = self.parse_wep( packet )
	
	def parse_wep( self, packet ):
		frame = IEEE802_11(packet)
		payload = frame.get_payload()
		wep = {}
		wep['iv'] = payload[:3]
		wep['k'] = payload[3:4]
		wep['ciphertext'] = payload[4:-4]
		wep['icv'] = payload[-4:]
		return wep

	def iv( self ):
		wep = self.wep
		return wep['iv']

	def icv( self ):
		wep = self.wep
		return wep['icv']

	def k( self ):
		wep = self.wep
		return wep['k']

	def ciphertext( self ):
		wep = self.wep
		return wep['cipertext']

	def get( self ):
		wep = self.wep
		return wep['iv'], wep['k'], wep['ciphertext'], wep['icv']

	def print_wep( self, wep = None ):
		if not wep:
			wep=self.wep
		print "IV: " + ''.join(format(x, '02x') for x in wep['iv'])
		print "Key Index: " + ''.join(format(x, '02x') for x in wep['k'])
		print "Ciphertext: " + ''.join(format(x, '02x') for x in wep['ciphertext'])
		print "ICV: " + ''.join(format(x, '02x') for x in wep['icv'])
