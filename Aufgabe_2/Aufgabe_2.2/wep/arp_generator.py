import base64


def generate_arp_request_package():
    llc_header = base64.b16decode(b'AAAA030000000806')
    arp_header = base64.b16decode(b'0001080006040001')
    source_mac =  base64.b16decode(b'AAAAAAAAAAAA')
    source_ip =  base64.b16decode(b'BBBBBBBB')
    target_mac =  base64.b16decode(b'FFFFFFFFFFFF')
    target_ip =  base64.b16decode(b'EEEEEEEE')

    return llc_header+arp_header+source_mac+source_ip+target_mac+target_ip

def generate_arp_response_package():
    """
    Quell-MAC-Adresse (6 Byte) enthält in einer ARP-Anforderung die MAC-Adresse des Senders. In einer ARP-Antwort enthält es die MAC-Adresse des antwortenden Hosts oder Next-Hop-Routers.
    Quell-IP-Adresse (4 Bytes bei IPv4) enthält bei einer ARP-Anforderung die IP-Adresse des anfragenden Hosts. In einer ARP-Antwort enthält es die IP-Adresse des antwortenden Hosts oder Next-Hop-Routers.
    Ziel-MAC-Adresse (6 Byte) ist in einer ARP-Anforderung ein Broadcast (FF:FF:FF:FF:FF:FF). In einer ARP-Antwort enthält es die MAC-Adresse des anfragenden Hosts.
    Ziel-IP-Adresse (4 Bytes bei IPv4) ist bei einer ARP-Anforderung die IP-Adresse des gesuchten Hosts. In einer ARP-Antwort enthält es die IP-Adresse des anfragenden Hosts.
    """
    llc_header = base64.b16decode(b'AAAA030000000806')
    arp_header = base64.b16decode(b'0001080006040002')
    source_mac =  base64.b16decode(b'AAAAAAAAAAAA')
    source_ip =  base64.b16decode(b'BBBBBBBB')
    target_mac =  base64.b16decode(b'FFFFFFFFFFFF')
    target_ip =  base64.b16decode(b'EEEEEEEE')

    return llc_header+arp_header+source_mac+source_ip+target_mac+target_ip
