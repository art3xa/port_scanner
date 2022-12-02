from dataclasses import dataclass
import struct
from socket import inet_aton, IPPROTO_TCP
from array import array


"""
TCP Header Format

                                    
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""


@dataclass
class TCPData:
    from_port: int
    to_port: int
    sequence: int
    acknowledgment: int
    flag_urg: int
    flag_ack: int
    flag_psh: int
    flag_rst: int
    flag_syn: int
    flag_fin: int


class TCPPackage:
    """ TCP package data """
    def __init__(self, from_host: str, from_port: int, to_host: str, to_port: int, flags: int = 0):
        self.from_host = from_host
        self.from_port = from_port
        self.to_host = to_host
        self.to_port = to_port
        self.flags = flags

    def build(self) -> bytes:
        """
        Build tcp package
        """
        package = struct.pack(
            '!HHIIBBHHH',
            self.from_port,  # Source Port
            self.to_port,  # Destination Port
            0,  # Sequence Number
            0,  # Acknoledgement Number
            5 << 4,  # Data offset
            self.flags,  # Flags
            8192,  # Window
            0,  # Checksum (initial value)
            0)  # Urgent pointer
        pseudo_hdr = struct.pack(
            '!4s4sHH',
            inet_aton(self.from_host),  # Source Address
            inet_aton(self.to_host),  # Destination Address
            IPPROTO_TCP,  # Protocol ID
            len(package)  # TCP Length
        )
        checksum = self.check_sum(pseudo_hdr + package)
        package = package[:16] + struct.pack('H', checksum) + package[18:]
        return package

    @staticmethod
    def check_sum(package: bytes) -> int:
        """
        Calculate checksum
        """
        if len(package) % 2 != 0:
            package += b'\0'
        res = sum(array("H", package))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16
        return (~res) & 0xffff

    @staticmethod
    def tcp_head_parse(data: bytes) -> TCPData:
        """
        Parse tcp header
        """
        (from_port, to_port, sequence, acknowledgment, offset_flags) = \
            struct.unpack('! H H L L H', data[:14])
        flag_urg = (offset_flags & 32) >> 5
        flag_ack = (offset_flags & 16) >> 4
        flag_psh = (offset_flags & 8) >> 3
        flag_rst = (offset_flags & 4) >> 2
        flag_syn = (offset_flags & 2) >> 1
        flag_fin = offset_flags & 1
        return TCPData(from_port, to_port, sequence, acknowledgment, flag_urg, flag_ack,
                       flag_psh, flag_rst, flag_syn, flag_fin)
