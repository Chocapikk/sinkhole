# Python Sinkhole Script

This Python script is a simple implementation of a network sinkhole. It captures and logs packets destined to non-existent IP addresses within a specified network range, acting as a useful tool for network administrators to monitor and analyze potentially malicious network activity.

## Features

1. Captures packets with non-existent destination IP addresses.
2. Logs packet details, including source IP, destination IP, protocol, and destination port.
3. Displays detected attacks in real time in a clear, tabular format.

## Usage

To use the sinkhole script, you need to specify the network interface to monitor:

```bash
python sinkhole.py -i eth0
```

In this example, `eth0` is the network interface to be monitored.

You can also specify a log file for the script to write to:

```bash
python sinkhole.py -i eth0 -l my_log_file.log
```

In this example, `my_log_file.log` is the file where log entries will be written.

## Requirements

This script requires the following Python libraries:
- Scapy
- ipaddress
- prettytable
- argparse

You can install these libraries using pip:

```bash
pip install install -r requirements.txt
```

## Disclaimer

This script should be used for lawful and legitimate purposes only. Always get proper authorization before performing any kind of network scanning or monitoring.

---

