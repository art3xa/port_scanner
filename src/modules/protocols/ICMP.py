import struct


class ICMP:
    """ ICMP Package """
    def __init__(self, data):
        self.data = data

    def decode_icmp_type(self) -> int:
        """
        Decoding the ICMP packet type
        """
        type = struct.unpack('B', self.data[20:][0:1])
        return type[0]

    def get_destination_port(self) -> int:
        """
        Decoding the UDP packet destination port
        """
        port = struct.unpack('!H', self.data[50:][0:2])
        return port[0]
