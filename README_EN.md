# tcpdump2

## Description

The tcpdump2 script is designed to automate the work with the tcpdump utility, simplifying the process of diagnosing and troubleshooting network connections.

This script already includes various preconfigured filters that allow for quick and effective traffic analysis, anomaly detection, and investigation of network attacks. Of course, you can use tcpdump without this script, but it will make your work much more convenient and productive.

We are always open to improvements: if you notice any issues or have ideas on how to enhance the script, we would be happy to hear your suggestions!

## Installation

To install tcpdump2, execute the following commands in the terminal:

```bash
git clone https://github.com/mnbarinov/tcpdump2.git
cd tcpdump2
chmod +x tcpdump2.sh
ln -s $(pwd)/tcpdump2.sh /usr/local/bin/tcpdump2
```

## Installing tcpdump

Please note that tcpdump must be installed on your server or computer. Below are the commands to install tcpdump on popular distributions:

### Debian/Ubuntu:
```bash
sudo apt update
sudo apt install tcpdump
```
### CentOS/RHEL
```bash
sudo yum install tcpdump
```
### Fedora
```bash
sudo dnf install tcpdump
```
### Arch Linux
```bash
sudo pacman -S tcpdump
```
# Command Syntax

After installing the script, you can use it by executing the command in the following format:
```bash
tcpdump2 -i <interface_name> <FILTER> [other standard tcpdump filters]
```
Parameters:

    <interface_name> — the name of the network interface (e.g., eth0).
    <FILTER> — one of the preconfigured filters or a custom filter.
    [other standard tcpdump filters] — any additional parameters supported by tcpdump.

    Execute the tcpdump2 command without parameters to see the available filters.

# Usage Examples

## To capture HTTP traffic:

```bash
tcpdump2 -i eth0 web
```

## To detect anomalies in the network:

```bash
tcpdump2 -i eth0 anomaly
```

## To monitor BGP:

```bash
tcpdump2 -i eth0 bgp
```


# Contribution

If you have ideas for improving the script or have found bugs, feel free to open pull requests or leave your comments in the Issues section.

Thank you for using tcpdump2! We hope it becomes a useful tool in your work.
