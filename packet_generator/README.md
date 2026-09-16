# packet_generator

An educational packet-generation tool for networking and security labs.
Students install dependencies with one script, then generate packets for a
handful of protocols with a single command.

> **Authorized use only.** Use this tool solely against systems you own or
> have explicit, written permission to test — for example, VMs on an isolated
> lab network. Unauthorized traffic against third-party systems may be illegal.
> The tool caps packet counts, prompts before flood/DoS demos, and does **not**
> spoof source IP addresses, so lab traffic stays traceable.

## Supported protocols

| Protocol    | Description                                    | Needs root |
|-------------|------------------------------------------------|:----------:|
| `arp`       | ARP who-has request (layer 2)                  | yes        |
| `icmp`      | ICMP echo request (ping)                       | yes        |
| `udp`       | UDP datagram with optional payload             | yes        |
| `dns`       | DNS query over UDP                             | yes        |
| `http`      | HTTP GET request(s) over a TCP socket          | no         |
| `syn-flood` | Limited TCP SYN flood (teaching demo)          | yes        |
| `http-dos`  | Limited HTTP request flood (teaching demo)     | no         |

## 1. Install dependencies

Works on Debian-family (apt) and RedHat-family (dnf/yum) Linux.

```bash
chmod +x install_deps.sh
sudo ./install_deps.sh
```

This installs `python3`, `pip`, and `scapy` (the core requirements), plus
`tcpdump` as an optional convenience for watching traffic. On modern distros
that use PEP 668 "externally-managed" Python (Debian 12+, Ubuntu 23.04+, recent
Fedora), the script automatically retries the pip fallback with
`--break-system-packages` if the system package is unavailable.

> **Targets are IPv4 only.** The raw-packet layers used here (scapy's `IP()`
> and ARP) are IPv4-only, so an IPv6 target is rejected with a clear message.

## 2. Run the generator

General form:

```bash
sudo python3 packet_generator.py --protocol <name> --target <ip> [options]
```

Common options:

| Option              | Meaning                                             |
|---------------------|-----------------------------------------------------|
| `--protocol`        | One of the protocols above (required)               |
| `--target`          | Target IP address (required)                        |
| `--port`            | Target port (udp/dns/http/syn-flood/http-dos)       |
| `--count`           | Number of packets/requests (default 1, capped)      |
| `--interval`        | Seconds to wait between packets (default 0)         |
| `--payload`         | ASCII payload (icmp/udp)                             |
| `--query`           | DNS name to query (dns)                              |
| `--path`            | URL path (http/http-dos, default `/`)               |
| `--iface`           | Network interface (arp)                              |
| `--yes`             | Skip confirmation prompt for flood/DoS modes        |
| `--verbose`         | Verbose output                                       |

## Examples

```bash
# ICMP echo request x5
sudo python3 packet_generator.py --protocol icmp --target 192.168.56.10 --count 5

# ARP who-has x3
sudo python3 packet_generator.py --protocol arp --target 192.168.56.10 --count 3

# UDP datagrams with a payload
sudo python3 packet_generator.py --protocol udp --target 192.168.56.10 --port 9999 --count 10 --payload "hello"

# DNS query over UDP
sudo python3 packet_generator.py --protocol dns --target 192.168.56.53 --query example.com --count 5

# HTTP GET (no root required)
python3 packet_generator.py --protocol http --target 192.168.56.10 --port 80 --count 5 --path /

# SYN flood teaching demo (capped, prompts for confirmation)
sudo python3 packet_generator.py --protocol syn-flood --target 192.168.56.10 --port 80 --count 200

# HTTP request-flood teaching demo (capped)
python3 packet_generator.py --protocol http-dos --target 192.168.56.10 --port 80 --count 100
```

## Safety limits

- **Packet caps.** Per-protocol packet/request caps are defined at the top of
  `packet_generator.py` in the `MAX_COUNT` dictionary. Instructors may adjust
  them, but they are intentionally small.
- **Confirmation.** The `syn-flood` and `http-dos` modes require an interactive
  `yes` confirmation (bypass with `--yes` in scripted lab exercises).
- **No source-IP spoofing.** SYN packets randomise only the source *port*, so
  traffic stays traceable to the sending host.
- **No amplification targets.** ICMP/UDP/DNS/SYN sends to multicast or the
  `255.255.255.255` broadcast address are refused (smurf / amplification).
- **No request-line injection.** `--path` rejects spaces and control/CRLF bytes.

## Running the tests

The suite uses only the Python standard library (no pytest required). Raw
packets are captured instead of transmitted, so no root or network is needed;
scapy-dependent tests skip automatically if scapy is absent.

```bash
cd packet_generator
python3 -m unittest discover -s tests -v
```

## Suggested lab setup

Run against isolated VMs (e.g. VirtualBox host-only network `192.168.56.0/24`)
and watch the traffic with `tcpdump` or Wireshark on the target:

```bash
sudo tcpdump -i any host 192.168.56.10 -n
```
