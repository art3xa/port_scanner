import selectors
from abc import ABC, abstractmethod
from typing import Set
import socket
import logging
from collections import namedtuple
from src.modules.imported.TimeDict import TimeDict

logger = logging.getLogger()
TimedValue = namedtuple('TimedValue', ['time', 'value'])


class BaseScanner(ABC):
    """ Base class for scanners """

    def __init__(self, ip, ports: Set[int], timeout: float):
        """
        Initialize scanner
        """
        self.localhost = \
            [l for l in
             ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if
               not ip.startswith("127.")][:1],
              [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for
                s in
                [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if
             l][0][0]
        self.port_states = TimeDict(timeout, timeout)
        self.timeout = timeout
        self.ip = ip
        self.ports = ports

    @abstractmethod
    def write_package(self, sock: selectors.SelectorKey.fileobj):
        """
        Send package to (ip, port) specified in sock
        """
        pass

    @abstractmethod
    def read_package(self, sock: selectors.SelectorKey.fileobj):
        """
        Recv package from (ip, port) specified in sock
        """
        pass

    @abstractmethod
    def start_scan(self):
        """
        Start scanning
        """
        pass
