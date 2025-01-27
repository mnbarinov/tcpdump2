# tcpdump2 script
<img src="t2header.jpg" alt="Tcpdump2 Script: Just Try It" width=100% align=center >

## Description
<img src="tcpdump12.svg" alt="Tcpdump2 Script is Here" width=160 align=right >
The tcpdump2 script is a powerful tool for automating tasks with the tcpdump utility. It simplifies the process of diagnosing and analyzing network traffic by providing ready-made filters for various protocols, groups, and use cases.

The script includes many features such as filtering by VLAN, MAC addresses, port ranges, packet sizes, and capturing only packet headers. This allows you to quickly identify anomalies, investigate network attacks, and analyze traffic without needing to memorize complex commands.

We’re always open to improvements! If you have suggestions or spot issues, we welcome your feedback.

## Installation
Чтобы установить tcpdump2, выполните следующие команды в терминале:To install tcpdump2, run the following commands in your terminal:
```
git clone https://github.com/mnbarinov/tcpdump2.git
cd tcpdump2
chmod +x tcpdump2.sh
ln -s $(pwd)/tcpdump2.sh /usr/local/bin/tcpdump2
```

### Installing tcpdump
Make sure tcpdump is installed on your server or computer. Below are installation commands for popular distributions:

#### Debian/Ubuntu:
```
sudo apt update
sudo apt install tcpdump
```
#### CentOS/RHEL:
```
sudo yum install tcpdump
```
#### Fedora:
```
sudo dnf install tcpdump
```
#### Arch Linux:
```
sudo pacman -S tcpdump
```

## Command Syntax
After installing the script, you can use it with the following format:
```
tcpdump2 -i <interface_name> <FILTER> [additional_options]
```
### Parameters:
- <interface_name> — the name of the network interface (e.g., eth0).

- <FILTER> — one of the predefined filters (e.g., web, vpn, bgp).

- [additional_options] — additional parameters such as:

    - -o <file> — save the output to a file.
    - -c <count> — limit the number of captured packets.
    - -h — capture only packet headers.
    - -m <MAC> — filter by MAC address.
    - -vlan <VLAN> — filter by VLAN ID.
    - -p <port_range> — filter by port range.
    - -t <time> — capture traffic for a specified duration (in seconds).
    - -s <size> — filter by packet size (greater than the specified value).
    - -color —  enable colorized output for key protocols (IP, TCP, UDP, ICMP).

To see the list of all available filters, run:
```
tcpdump2
```
## Usage Examples
### Capture HTTP traffic:
```
tcpdump2 -i eth0 web
```
### Capture traffic for VLAN 208:
```
tcpdump2 -i eth0 vpn -vlan 208
```
### Capture only 100 DNS packets:
```
tcpdump2 -i eth0 dns -c 100
```
### Capture traffic filtered by MAC address:
```
tcpdump2 -i eth0 tcp -m 00:11:22:33:44:55
```
### Capture traffic for port range 1000-2000:
```
tcpdump2 -i eth0 tcp -p 1000-2000
```
### Capture traffic with colorized output:
```
tcpdump2 -i eth0 web -color
```
### Save output to a file:
```
tcpdump2 -i eth0 web -o output.pcap
```
### Capture traffic for 10 seconds:
```
tcpdump2 -i eth0 web -t 10
```

## Supported Filters
The script supports a variety of filters, including:

- Core protocols: tcp, udp, icmp, arp, ip, ip6.

- Protocol groups: vpn, routing, p2p, voip, management, web, email.

- Network services: dhcp, dns, ntp, radius, snmp, ldap, ssh, ftp, smb, tftp.

- Routing protocols: bgp, ospf, rip, eigrp, isis.

- VPN and tunneling: gre, ipsec, pptp, openvpn, wireguard.

- Multimedia and VoIP: rtp, sip, rtsp, h323.

- Anomalies and attacks: scan, ddos, suspicious_ports, anomaly, port_hopping, burst, suspicious_traffic.

You can view the full list of filters by running the tcpdump2 command without parameters.

## Contribution
If you have ideas for improving the script or have found any errors, feel free to open a pull request or leave your comments in the Issues section.

Thank you for using tcpdump2! We hope it becomes a valuable tool in your work.

<img src="t2banner.jpg" alt="Tcpdump2 Script: Just Try It" width=100% align=center >
