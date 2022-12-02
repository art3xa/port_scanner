from prettytable import PrettyTable, PLAIN_COLUMNS


class ConsoleUI:
    """ ConsoleUI class """
    def __init__(self):
        self.start_msg = ''
        self.column = {}
        self.end_msg = ''
        self.columns = []

    def add_column(self, name: str):
        """ Add column to console ui """
        self.column[name] = []
        self.columns.append(name)

    def add_value_to_column(self, name: str, value: str):
        """ Add value to column """
        self.column[name].append(value)

    def add_start_msg(self, msg: str):
        """ Add start message """
        self.start_msg = msg

    def add_end_msg(self, msg: str):
        """ Add end message """
        self.end_msg = msg

    def print(self):
        """ Print full console answer """
        print(self.start_msg)
        pretty_table = PrettyTable(self.columns)
        pretty_table.set_style(PLAIN_COLUMNS)
        temp = list(zip(*[self.column[column] for column in self.columns]))
        pretty_table.add_rows(temp)
        if len(temp) > 0:
            print(pretty_table)
        else:
            print('Nothing found')
        print()
        print(self.end_msg)


def add_data_to_console_column(console_ui, transport_protocol, get_protocol_func, args, port, t=''):
    """ Add data to console column """
    console_ui.add_value_to_column('TCP|UDP', transport_protocol)
    console_ui.add_value_to_column('PORT', port)
    if args.verbose:
        console_ui.add_value_to_column('[TIME, ms]', t)

    if args.guess:
        protocol = get_protocol_func(port, args.ip)
        console_ui.add_value_to_column('PROTOCOL', protocol)


def add_filtered_udp_ports_to_console_if_open(console_ui, transport_protocol, get_protocol_func,
                                              args, port, t=''):
    """ Add filtered udp ports to console if open """
    protocol = get_protocol_func(port, args.ip)
    if protocol:
        console_ui.add_value_to_column('TCP|UDP', transport_protocol)
        console_ui.add_value_to_column('PORT', port)
        if args.verbose:
            console_ui.add_value_to_column('[TIME, ms]', t)
        console_ui.add_value_to_column('PROTOCOL', protocol)
