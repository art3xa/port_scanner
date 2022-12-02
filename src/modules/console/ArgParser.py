import sys
from argparse import ArgumentParser
from typing import List
from src.modules.console.DataArguments import DataArguments
from ping3 import ping
import re

port_regex = re.compile(r'^(tcp|udp)\/\d+(-\d+)?')


class ArgParser:
    """ Argument Parser"""
    def __init__(self, args):
        self._parser = ArgumentParser(prog="Port Scanner",
                                      description="TCP and UDP port scanner",
                                      )
        self._args = args
        self._add_arguments()

    def _add_arguments(self):
        """
        Add arguments to the parser
        """
        self._parser.add_argument("ip", type=str,  # required=True,
                                  help="IP address")
        self._parser.add_argument("ports", type=str, metavar='PORT', nargs='*',
                                  default=['tcp', 'udp'],
                                  help="ports")
        self._parser.add_argument("--timeout", "-t", dest="timeout",
                                  type=float, default=2.0,
                                  help="response timeout (2s by default)")
        self._parser.add_argument("--num-threads", "-j", type=int, default=100, dest="threads",
                                  help="number of threads (100 by default)")
        self._parser.add_argument("-v", "--verbose", action="store_true",
                                  help="verbose mode")
        self._parser.add_argument("-g", "--guess", action="store_true",
                                  help="application layer protocol definition")

    def is_correct_ip(self, ip: str):
        """ Checking the correctness of the IP address """
        nums = ip.split('.')
        if len(nums) != 4:
            return False
        for num in nums:
            if not 0 <= int(num) <= 255 and num:
                raise False
        return True

    def is_correct_port(self, port: str):
        """ Checking the correctness of the port """
        return port_regex.match(port) or port in ['tcp', 'udp']

    def parse_ports(self, ports: List[str]):
        """
        Parsing ports of the form: tcp/*, udp/*, tcp/*-*, * - number
        """
        new_ports = {}
        for p in ports:
            if p.find('/') == -1:
                new_ports[p] = {x for x in range(1, 1001)}
            else:
                temp = p.split('/')
                if temp[0] not in new_ports:
                    new_ports[temp[0]] = set()
                for port in temp[1].split(','):
                    if '-' in port:
                        number_one, number_two = map(int, port.split('-'))
                        if not (0 < number_one < 65536 and 0 < number_two < 65536):
                            raise ValueError('Port should be less 65536 and more 0')
                        for portt in range(number_one, number_two + 1):
                            new_ports[temp[0]].add(portt)
                    else:
                        if not 0 < int(port) < 65536:
                            raise ValueError(
                                'Port should be less 65536 and more 0')
                        new_ports[temp[0]].add(int(port))

        return new_ports

    def parse(self):
        """
        Parsing arguments
        """
        args = self._parser.parse_args(self._args)

        if not self.is_correct_ip(args.ip):
            raise ValueError(f'IP address {args.ip} is not correct.')

        if not ping(args.ip, timeout=args.timeout):
            raise ValueError(f'Host {args.ip} seems down.')

        for port in args.ports:
            if not self.is_correct_port(port):
                raise ValueError(f"Port {port} is not correct.")

        try:
            ports = self.parse_ports(args.ports)
        except ValueError as e:
            print(str(e))
            sys.exit()

        return DataArguments(args.ip, ports, args.timeout, args.verbose, args.guess, args.threads)
