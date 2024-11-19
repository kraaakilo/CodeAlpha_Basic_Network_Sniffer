# Network Sniffer in Python

## Overview

This is a simple network sniffer built using Python and the `Scapy` library. The sniffer captures and analyzes network packets in real time, extracting key information from various network layers such as Ethernet, IP, TCP, UDP, and ICMP. It helps you understand how data flows across a network and how network packets are structured.

## Features

- Capture and analyze network traffic in real-time.
- Extract information from different layers:
  - **Ethernet**: MAC source, MAC destination, Ethernet type.
  - **IP**: Source and destination IP addresses, IP version.
  - **TCP**: Source and destination ports, flags.
  - **UDP**: Source and destination ports, UDP length.
  - **ICMP**: Type and code of ICMP packets.
- Displays decoded raw data from packets.
  
## Requirements

- Python 3.x
- `Scapy` library

## Installation

1. Install the required dependencies in a python virtual environment:

   ```bash
   pip install scapy
   ```

## Usage

Run the script to start sniffing network traffic. You can also apply a filter to capture specific types of packets (e.g., only TCP or UDP).

### Basic Command:

```bash
sudo python3 main.py
```

### Command with Filter:

You can specify a filter when running the script. For example, to capture only TCP packets:

```bash
python3 main.py "tcp"
```

### Example Output:

```
--------------------------------------------------
MAC Source: 00:14:22:01:23:45
MAC Destination: 00:14:22:67:89:AB
Ethernet Type: 0x0800

IP Version: 4
Source IP: 192.168.1.10
Destination IP: 192.168.1.1

TCP - Layer
Source Port: 80
Destination Port: 443
Flags: S

Raw Data:
GET / HTTP/1.1
Host: example.com
...
--------------------------------------------------
```