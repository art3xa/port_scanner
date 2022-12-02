import struct
import socket

_HTTP_REQUESTS = b'GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 OPR/92.0.0.0\r\n\r\n\r\n'
_DNS_PACKAGE = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
_DNS_RESPONSE_PACKAGE = b'\x00\x00\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00'


def is_dns_on_udp(ip: str, port: int) -> bool:
    """
    Checking to dns protocol on udp port
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.sendto(_DNS_PACKAGE, (ip, port))
        try:
            data = sock.recv(2048)
        except socket.timeout:
            return False

        return data == _DNS_RESPONSE_PACKAGE


def is_dns_on_tcp(ip: str, port: int) -> bool:
    """
    Checking to dns protocol on tcp port
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.send(_DNS_PACKAGE)
        try:
            data = sock.recv(1024)
        except ConnectionResetError:
            return False

        return data == _DNS_RESPONSE_PACKAGE


def get_port_from_data(data: bytes) -> int:
    ip_header_len = (data[0] & 0b1111) * 4

    return struct.unpack('!H', data[ip_header_len:ip_header_len + 2])[0]


def is_http_on_tcp(ip: str, port: int) -> bool:
    """
    Checking to http
    """
    if port == 443:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.send(_HTTP_REQUESTS)
        try:
            data = sock.recv(1024)
        except ConnectionResetError:
            return False

        return data.decode().find('HTTP') != -1 and data.decode().find('HTTPS') == -1


def is_echo_on_udp(ip: str, port: int) -> bool:
    """
    Checking to echo protocol on udo port
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.sendto(b'echo', (ip, port))
        try:
            data, conn = sock.recvfrom(1024)
        except socket.timeout:
            return False

        return data == b'echo'


def is_echo_on_tcp(ip: str, port: int) -> bool:
    """
    Checking to echo protocol on tcp port
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.settimeout(2)
        sock.send(b'echo')
        try:
            data = sock.recv(1024)
        except socket.timeout:
            return False

        return data == b'echo'


def get_protocols_to_udp_port(port: int, ip: str) -> str:
    """
    Get protocol on udp port
    """
    if is_dns_on_udp(ip, port):
        return 'DNS'
    elif is_echo_on_udp(ip, port):
        return 'ECHO'
    else:
        return ''


def get_protocols_to_tcp_port(port: int, ip: str) -> str:
    """
    Get protocol on tcp port
    """
    if is_echo_on_tcp(ip, port):
        return 'ECHO'
    elif is_http_on_tcp(ip, port):
        return 'HTTP'
    elif is_dns_on_tcp(ip, port):
        return 'DNS'
    else:
        return ''
