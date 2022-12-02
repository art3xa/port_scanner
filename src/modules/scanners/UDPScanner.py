import socket
import selectors
import time
from src.modules.scanners.BaseScanner import BaseScanner
from typing import Set, List, Tuple
import sys
from src.modules.protocols.ICMP import ICMP
from src.modules.helpers import get_port_from_data


class UDPScanner(BaseScanner):
    """Async udp port scanner """
    def __init__(self, ip: str, ports: Set[int], timeout: float):
        """
        Init udp scanner
        :param ip: ip address from which you need to scan the ports.
        :param ports: ports to scan.
        :param timeout: Timeout waiting for a response from (ip, port)
        """
        super().__init__(ip, ports, timeout)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setblocking(False)

        self.icmp_socket = self.create_raw_icmp_socket()
        self.icmp_socket.setblocking(False)

        self.closed_ports = set()
        self.open_ports = set()

        self.answer = set((port, 0) for port in self.ports)
        self.result = set()

    def create_raw_icmp_socket(self):
        """
        Create raw icmp socket
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            print('Requires root')
            sys.exit()
        return sock

    def read_package(self, sock: selectors.SelectorKey.fileobj):
        """
        Recv package from (ip, port)
        """
        data, address = sock.recvfrom(1024)
        finish = time.perf_counter()
        if address[0] == self.ip:
            if sock == self.udp_socket:
                port = get_port_from_data(data)
                if port in self.port_states:
                    time_delta = finish - self.port_states[port]
                    self.open_ports.add((port, round(time_delta * 1000)))
            elif sock == self.icmp_socket:
                icmp = ICMP(data)
                icmp_type = icmp.decode_icmp_type()
                port = icmp.get_destination_port()
                if icmp_type == 3 and port in self.port_states:
                    time_delta = finish - self.port_states[port]
                    self.closed_ports.add((port, round(time_delta * 1000)))

    def write_package(self, sock: selectors.SelectorKey.fileobj):
        """
        Send package to (ip, port)
        """
        if len(self.ports) > 0:
            cur_port = self.ports.pop()
            sock.sendto(b'', (self.ip, cur_port))
            self.port_states[cur_port] = time.perf_counter()

    def start_scan(self) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
        """
        Start scan udp ports.
        :returns: Filtered and Open ports.
        """
        sel = selectors.DefaultSelector()
        sel.register(self.udp_socket, selectors.EVENT_WRITE | selectors.EVENT_READ)
        sel.register(self.icmp_socket, selectors.EVENT_READ)

        while True:
            events = sel.select()
            for key, mask in events:
                if mask & selectors.EVENT_READ:
                    self.read_package(key.fileobj)
                elif mask & selectors.EVENT_WRITE:
                    self.write_package(key.fileobj)
                if len(self.ports) == 0 and len(self.port_states) == 0:
                    self.port_states.destroy()
                    self.udp_socket.close()
                    self.icmp_socket.close()
                    return sorted(list(self.answer - self.closed_ports - self.open_ports)), \
                           sorted(list(self.open_ports))
