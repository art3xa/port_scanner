import time
import socket
import sys
import selectors
from random import randint
from typing import Set, List, Tuple
from src.modules.scanners.BaseScanner import BaseScanner
from src.modules.protocols.TCPPackage import TCPPackage


class TCPScanner(BaseScanner):
    """ Async tcp port scanner """
    def __init__(self, ip: str, ports: Set[int], timeout: float):
        """
        Init tcp scanner
        :param ip: ip address from which you need to scan the ports.
        :param ports: ports to scan.
        :param timeout: Timeout waiting for a response from (ip, port)
        """
        super().__init__(ip, ports, timeout)
        self.tcp_socket = self.create_raw_tcp_socket()
        self.tcp_socket.setblocking(False)
        self.answer = set()

    def create_raw_tcp_socket(self):
        """
        Create raw tcp socket
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except PermissionError as e:
            print('Requires root privileges')
            sys.exit()
        except Exception as e:
            print(e)
            sys.exit()
        return sock

    def write_package(self, sock: selectors.SelectorKey.fileobj):
        """
        Send package to (ip, port)
        :param sock: Socket
        """
        if len(self.ports) > 0:
            cur_port = self.ports.pop()
            package = TCPPackage(self.localhost, randint(35000, 40000), self.ip, cur_port, 2).build()
            sock.sendto(package, (self.ip, cur_port))
            self.port_states[cur_port] = time.perf_counter()

    def read_package(self, sock: selectors.SelectorKey.fileobj):
        """
        Recv package from (ip, port)
        """
        data, address = sock.recvfrom(1024)
        finish = time.perf_counter()
        if address[0] == self.ip:
            tcp_package = TCPPackage.tcp_head_parse(data[20:])
            if tcp_package.from_port in self.port_states:
                if tcp_package.flag_syn and tcp_package.flag_ack:
                    time_to_answer = finish - self.port_states[tcp_package.from_port]
                    if self.timeout - time_to_answer > 0:
                        self.answer.add((tcp_package.from_port, round(time_to_answer * 1000)))
                        self.port_states.__delitem__(tcp_package.from_port)
                elif tcp_package.flag_rst and tcp_package.flag_ack:
                    self.port_states.__delitem__(tcp_package.from_port)

    def start_scan(self) -> List[Tuple[int, float]]:
        """
        Start scan tcp ports.
        :return: List of open ports and time to answer.
        """
        sel = selectors.DefaultSelector()
        sel.register(self.tcp_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)

        while True:
            events = sel.select()
            for key, mask in events:
                if mask & selectors.EVENT_READ:
                    self.read_package(key.fileobj)
                elif mask & selectors.EVENT_WRITE:
                    self.write_package(key.fileobj)

                if len(self.ports) == 0 and len(self.port_states) == 0:
                    self.port_states.destroy()
                    self.tcp_socket.close()
                    return sorted(list(self.answer))
