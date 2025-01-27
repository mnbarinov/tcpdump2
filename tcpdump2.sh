#!/bin/bash
# Mikhail Barinov <dev#mbarinov.ru>
# Tcpdump Script
# Version 2.3

# Определяем ассоциативный массив для поддерживаемых протоколов и групп
declare -A PROTOCOLS=(
    [tcp]="TCP"
    [udp]="UDP"
    [icmp]="ICMP"
    [icmp6]="ICMPv6"
    [arp]="ARP"
    [rarp]="RARP"
    [ip]="IP"
    [ip6]="IPv6"
    [vpn]="VPN group"
    [routing]="Routing group"
    [p2p]="P2P group"
    [voip]="VoIP group"
    [management]="Management group"
    [web]="Web group"
    [email]="Email group"
    [dhcp]="DHCP"
    [dns]="DNS"
    [ntp]="NTP"
    [radius]="RADIUS"
    [snmp]="SNMP"
    [ldap]="LDAP"
    [ssh]="SSH"
    [ftp]="FTP"
    [smb]="SMB"
    [tftp]="TFTP"
    [bgp]="BGP"
    [ospf]="OSPF"
    [rip]="RIP"
    [eigrp]="EIGRP"
    [isis]="ISIS"
    [lldp]="LLDP"
    [bfd]="BFD"
    [gre]="GRE"
    [ipsec]="IPSec"
    [pptp]="PPTP"
    [openvpn]="OpenVPN"
    [wireguard]="WireGuard"
    [bittorrent]="BitTorrent"
    [edonkey]="eDonkey"
    [gnutella]="Gnutella"
    [rtp]="RTP"
    [sip]="SIP"
    [rtsp]="RTSP"
    [h323]="H.323"
    [rdp]="RDP"
    [vnc]="VNC"
    [syslog]="Syslog"
    [scan]="Scan for anomalies"
    [ddos]="DDoS attack detection"
    [suspicious_ports]="Suspicious ports"
    [anomaly]="Anomaly detection"
    [port_hopping]="Port hopping"
    [burst]="Traffic burst"
    [suspicious_traffic]="Suspicious traffic"
    [telnet]="Telnet traffic"
    [kms]="Windows activation"
    [erps]="ERPS"
)

# Проверка количества аргументов
if [ "$#" -lt 3 ] || [ "$1" != "-i" ]; then
    echo "Usage: $0 -i <interface> {protocol|group} [additional filters...]"
    echo "Options:"
    echo "  -o <file>       Save output to file"
    echo "  -c <count>      Limit the number of packets to capture"
    echo "  -h              Capture only headers (no payload)"
    echo "  -m <mac>        Filter by MAC address"
    echo "  -host <IP>      Filter by HOST address"
    echo "  -vlan <vlan>    Filter by VLAN ID"
    echo "  -p <port_range> Filter by port range"
    echo "  -t <time>       Capture for a specific time (in seconds)"
    echo "  -s <size>       Filter by packet size (greater than)"
    echo "  -color          Enable colorized output"
    echo "Supported protocols/groups:"
    for protocol in "${!PROTOCOLS[@]}"; do
        echo " - $protocol: ${PROTOCOLS[$protocol]}"
    done
    exit 1
fi

# Интерфейс и протокол или группа
INTERFACE=$2
PROTOCOL=$3


# Параметры по умолчанию
OUTPUT_FILE=""
PACKET_COUNT=""
HEADERS_ONLY=""
MAC_FILTER=""
VLAN_FILTER=""
PORT_RANGE=""
CAPTURE_TIME=""
SIZE_FILTER=""
COLOR_OUTPUT=""

# Обработка дополнительных аргументов
shift 3
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -o)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -c)
            PACKET_COUNT="-c $2"
            shift 2
            ;;
        -h)
            HEADERS_ONLY="-s 0"
            shift
            ;;
        -m)
            MAC_FILTER="and ether host $2"
            shift 2
            ;;
        -vlan)
            VLAN_FILTER="and vlan $2"
            shift 2
            ;;
        -p)
            PORT_RANGE="and portrange $2"
            shift 2
            ;;
        -t)
            CAPTURE_TIME="timeout $2"
            shift 2
            ;;
        -s)
            SIZE_FILTER="and greater $2"
            shift 2
            ;;
        -color)
            COLOR_OUTPUT="yes"
            shift
            ;;
	-host)
             HOST_FILTER="and host $2"
            shift 2
            ;;
        *)
            ADDITIONAL_FILTERS="$ADDITIONAL_FILTERS and $1"
            shift
            ;;
    esac
done

# Установка фильтра в зависимости от протокола или группы
case "$PROTOCOL" in
    # Основные протоколы, которые понимает tcpdump напрямую
    tcp | udp | icmp | icmp6 | arp | rarp | ip | ip6)
        FILTER="$PROTOCOL"
        ;;
    
    # Группы протоколов
    vpn)
        FILTER="(proto gre or udp port 1194 or udp port 51820 or tcp port 1723)"
        ;;
    routing)
        FILTER="(tcp port 179 or proto ospf or udp port 520)"
        ;;
    p2p)
        FILTER="(tcp portrange 6881-6889 or udp portrange 6881-6889 or tcp port 4662 or udp port 4665 or tcp port 6346)"
        ;;
    voip)
        FILTER="(udp portrange 16384-32767 or udp port 5060 or udp port 5061)"
        ;;
    management)
        FILTER="(udp port 161 or udp port 162 or udp port 514 or tcp port 3389 or tcp port 5900)"
        ;;
    web)
        FILTER="(tcp port 80 or tcp port 443)"
        ;;
    email)
        FILTER="(tcp port 25 or tcp port 110 or tcp port 143)"
        ;;
    dhcp)
        FILTER="(udp port 67 or udp port 68)"
        ;;
    dns)
        FILTER="(udp port 53)"
        ;;
    ntp)
        FILTER="(udp port 123)"
        ;;
    radius)
        FILTER="(udp port 1812 or udp port 1813)"
        ;;
    snmp)
        FILTER="(udp port 161 or udp port 162)"
        ;;
    ldap)
        FILTER="(tcp port 389)"
        ;;
    ssh)
        FILTER="(tcp port 22)"
        ;;
    ftp)
        FILTER="(tcp port 21)"
        ;;
    smb)
        FILTER="(tcp port 445)"
        ;;
    tftp)
        FILTER="(udp port 69)"
        ;;
    bgp)
        FILTER="(tcp port 179)"
        ;;
    ospf)
        FILTER="(proto ospf)"
        ;;
    rip)
        FILTER="(udp port 520)"
        ;;
    eigrp)
        FILTER="(ip proto 88)"
        ;;
    isis)
        FILTER="(proto isis)"
        ;;
    lldp)
        FILTER="(ether proto 0x88cc)"
        ;;
    bfd)
        FILTER="(tcp port 3784 or udp port 3784 or tcp port 3785 or udp port 3785 or tcp port 4784 or udp port 4784 or udp port 6784 or udp port 7784)"
        ;;
    gre)
        FILTER="(proto gre)"
        ;;
    ipsec)
        FILTER="(proto esp or proto ah)"
        ;;
    pptp)
        FILTER="(tcp port 1723)"
        ;;
    openvpn)
        FILTER="(udp port 1194)"
        ;;
    wireguard)
        FILTER="(udp port 51820)"
        ;;
    bittorrent)
        FILTER="(tcp portrange 6881-6889 or udp portrange 6881-6889)"
        ;;
    edonkey)
        FILTER="(tcp port 4662 or udp port 4665)"
        ;;
    gnutella)
        FILTER="(tcp port 6346)"
        ;;
    rtp)
        FILTER="(udp portrange 16384-32767)"
        ;;
    sip)
        FILTER="(udp port 5060 or udp port 5061)"
        ;;
    rtsp)
        FILTER="(tcp port 554)"
        ;;
    h323)
        FILTER="(tcp port 1720)"
        ;;
    rdp)
        FILTER="(tcp port 3389)"
        ;;
    vnc)
        FILTER="(tcp port 5900)"
        ;;
    syslog)
        FILTER="(udp port 514)"
        ;;
    scan)
        FILTER="(tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-psh|tcp-urg) != 0)"
        ;;
    ddos)
        FILTER="(icmp or udp portrange 33434-33600 or udp port 80 or udp port 53)"
        ;;
    suspicious_ports)
        FILTER="(tcp port 445 or tcp port 3389 or tcp port 23 or tcp port 1433 or tcp port 3306)"
        ;;
    anomaly)
        FILTER="(tcp[tcpflags] == 0 or tcp[tcpflags] == tcp-fin)"
        ;;
    port_hopping)
        FILTER="(tcp[2:2] != 0)"
        ;;
    burst)
        FILTER="(tcp or udp and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-rst != 0))"
        ;;
    suspicious_traffic)
        FILTER="(tcp or udp)"
        ;;
    telnet)
        FILTER="(tcp port 23)"
        ;;
    kms)
        FILTER="(tcp port 1688)"
        ;;
    erps)
        FILTER="(ether proto 0x8902)"
        ;;
    *)
        echo "Unsupported protocol or group: $PROTOCOL"
        exit 1
        ;;
esac

# Добавление дополнительных фильтров
FILTER="$FILTER $MAC_FILTER $HOST_FILTER $VLAN_FILTER $PORT_RANGE $SIZE_FILTER $ADDITIONAL_FILTERS"

# Запуск tcpdump
CMD="tcpdump -i $INTERFACE \"$FILTER\" $PACKET_COUNT $HEADERS_ONLY"
if [ -n "$OUTPUT_FILE" ]; then
    CMD="$CMD -w $OUTPUT_FILE"
fi
if [ -n "$CAPTURE_TIME" ]; then
    CMD="$CAPTURE_TIME $CMD"
fi
if [ "$COLOR_OUTPUT" == "yes" ]; then
    CMD="$CMD | grep --color=always -E 'IP|TCP|UDP|ICMP'"
fi

echo "Running: $CMD"
eval "$CMD"
