# PortScanner
Async fast UDP and TCP port scanner with protocol detection and timeout support

# Usage
Use WSL or Linux for best performance

Install requirements:
`sudo pip install -r requirements.txt`

Run:
`sudo python3 portscan.py [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...`

# Options
Options `[OPTIONS]` must be the following:

`--timeout` — response timeout (2s by default)

`-v, --verbose` — verbose mode

`-g, --guess` — application layer protocol definition

`-j, --num-threads` — number of threads (100 by default)

# Examples
`sudo python3 portscan.py 1.1.1.1 tcp/80 tcp/12000-12500 udp/3000-3100,3200,3300-4000`

`sudo python3 portscan.py 1.1.1.1 tcp udp/40000`

`sudo python3 portscan.py 1.1.1.1 tcp udp/40000 -v -g`

`sudo python3 portscan.py 1.1.1.1 -v -g`  (it's scanning tcp and udp ports from 1 to 1000)

`sudo python3 portscanner.py 87.250.250.242 udp/53 tcp/53 udp/80 tcp/80 udp/443 tcp/443 -g -v`

`sudo python3 portscanner.py 8.8.8.8 udp/53 tcp/53 udp/80 tcp/80 udp/443 tcp/443 -g -v`

`sudo python3 portscanner.py 91.198.174.192 udp/53 tcp/53 udp/80 tcp/80 udp/443 tcp/443 -g -v`


## Functionality
- UDP scanning
- TCP scanning SYN with manual packet generation
- Using selectors for asynchronous I/O
- Verbose mode
- Application layer protocol definition (guess) (`HTTP`, `DNS`, `ECHO`)

# Requirements
- Python 3.8+
- ping3~=4.0.3
- prettytable~=3.5.0

