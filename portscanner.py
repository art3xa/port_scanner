import socket
import time
import sys
from src.modules.console.ArgParser import ArgParser
from src.modules.scanners.UDPScanner import UDPScanner
from src.modules.console.ConsoleUI import ConsoleUI, add_data_to_console_column, add_filtered_udp_ports_to_console_if_open
from src.modules.helpers import get_protocols_to_udp_port, get_protocols_to_tcp_port
from src.modules.scanners.TCPScanner import TCPScanner


def get_args():
    """ Get arguments from command line """
    arg_parser = ArgParser(sys.argv[1:])
    try:
        args = arg_parser.parse()
    except ValueError as e:
        print(str(e))
        sys.exit()
    return args


def start_udp_scan(console_ui, args):
    """ Start UDP scan """
    filtered_ports, open_ports = UDPScanner(args.ip,
                                            args.ports['udp'],
                                            args.timeout).start_scan()
    for port, t in open_ports:
        add_data_to_console_column(console_ui,
                                   'UDP',
                                   get_protocols_to_udp_port,
                                   args,
                                   port,
                                   f'{t}')

    if args.guess:
        for port, t in filtered_ports:
            add_filtered_udp_ports_to_console_if_open(
                console_ui, 'UDP', get_protocols_to_udp_port, args, port, f'{t}')


def start_tcp_scan(console_ui, args):
    """ Start TCP scan """
    tcp_ports = TCPScanner(args.ip, args.ports['tcp'],
                           args.timeout).start_scan()
    for port, t in tcp_ports:
        add_data_to_console_column(console_ui, 'TCP',
                                   get_protocols_to_tcp_port, args, port,
                                   f'{t}')


def start_scan(console_ui, args):
    """ Start scan and create console UI """
    start = time.perf_counter()
    try:
        domain = socket.gethostbyaddr(args.ip)
    except socket.herror:
        domain = args.ip
    console_ui.add_start_msg(
        f'Starting PortScan for {domain[0]} ({args.ip})\n')
    console_ui.add_column('TCP|UDP')
    console_ui.add_column('PORT')

    if args.verbose:
        console_ui.add_column('[TIME, ms]')
    if args.guess:
        console_ui.add_column('PROTOCOL')

    if 'udp' in args.ports:
        start_udp_scan(console_ui, args)
    if 'tcp' in args.ports:
        start_tcp_scan(console_ui, args)

    console_ui.add_end_msg(
        f'PortScan done: scanned in {round(time.perf_counter() - start, 2)} seconds')
    console_ui.print()


def main():
    """ Main function """
    console_ui = ConsoleUI()
    args = get_args()
    start_scan(console_ui, args)


if __name__ == '__main__':
    try:
        main()
    except PermissionError:
        print('Permission denied, please use sudo')
    except KeyboardInterrupt:
        print('Interrupted by user')
        sys.exit()
