import struct


class PCAP:
    def __init__(self, filename):
        self.f = open(filename, "rb")
        byte = self.f.read(4)
        self.pcap = self.parse_pcap_header(self.f.read(20))
        self.phead = self.f.read(16)

    def __iter__(self):
        return self

    def captype_to_string(self, captype):
        if captype == 105:
            return "LINKTYPE_IEEE802_11"
        else:
            return "UNKNOWN_CAPTYPE_" + str(captype)

    def header(self):
        return self.pcap

    def __next__(self):
        if self.phead:
            packet, datalen = self.parse_packet_header(self.phead)
            packet['data'] = bytearray(self.f.read(datalen))
            self.phead = self.f.read(16)
            return packet
        else:
            self.reset()
            raise StopIteration()

    def reset(self):
        self.f.seek(24)
        self.phead = self.f.read(16)

    def parse_pcap_header(self, bytearr):
        header = {}
        header['major'] = struct.unpack('h', bytearr[:2])[0]
        header['minor'] = struct.unpack('h', bytearr[2:4])[0]
        header['GMToff'] = struct.unpack('i', bytearr[4:8])[0]
        header['tsacc'] = struct.unpack('i', bytearr[8:12])[0]
        header['maxlen'] = struct.unpack('i', bytearr[12:16])[0]
        header['captype'] = struct.unpack('i', bytearr[16:20])[0]
        header['captypestring'] = self.captype_to_string(header['captype'])
        return header

    def parse_packet_header(self, bytearr):
        ph = {}
        ph['ts'] = struct.unpack('i', bytearr[:4])[0]
        ph['ms'] = struct.unpack('i', bytearr[4:8])[0]
        ph['len'] = struct.unpack('i', bytearr[8:12])[0]
        ph['reallen'] = struct.unpack('i', bytearr[12:16])[0]
        return ph, ph['len']
