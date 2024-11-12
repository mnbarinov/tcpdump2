#!/bin/bash
# Mikhail Barinov <dev#mbarinov.ru>
# Tcpdump  Script
# Version 1.1

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
    )


# Проверка количества аргументов
if [ "$#" -lt 3 ] || [ "$1" != "-i" ]; then
    echo "Usage: $0 -i <interface> {protocol|group} [additional filters...]"
    
    echo "Supported protocols/groups:"
    for protocol in "${!PROTOCOLS[@]}"; do
        echo " - $protocol: ${PROTOCOLS[$protocol]}"
    done
    
    exit 1
fi

# Интерфейс и протокол или группа
INTERFACE=$2
PROTOCOL=$3

# Установка фильтра в зависимости от протокола или группы
case "$PROTOCOL" in
    # Основные протоколы, которые понимает tcpdump напрямую
    tcp | udp | icmp | icmp6 | arp | rarp | ip | ip6)
        FILTER="$PROTOCOL"
        ;;
    
    
    # Группы протоколов
    vpn)
        FILTER="proto gre or udp port 1194 or udp port 51820 or tcp port 1723"
        ;;
    routing)
        FILTER="tcp port 179 or proto ospf or udp port 520" # or ip proto 88 or proto isis or ether proto 0x88cc"
        ;;
    p2p)
        FILTER="tcp portrange 6881-6889 or udp portrange 6881-6889 or tcp port 4662 or udp port 4665 or tcp port 6346"
        ;;
    voip)
        FILTER="udp portrange 16384-32767 or udp port 5060 or udp port 5061"
        ;;
    management)
        FILTER="udp port 161 or udp port 162 or udp port 514 or tcp port 3389 or tcp port 5900"
        ;;
    web)
        FILTER="tcp port 80 or tcp port 443"
        ;;
    email)
        FILTER="tcp port 25 or tcp port 110 or tcp port 143"
        ;;
    
    # Сетевые службы и управление
    dhcp)
        FILTER="udp port 67 or udp port 68"
        ;;
    dns)
        FILTER="udp port 53"
        ;;
    ntp)
        FILTER="udp port 123"
        ;;
    radius)
        FILTER="udp port 1812 or udp port 1813"
        ;;
    snmp)
        FILTER="udp port 161 or udp port 162"
        ;;
    ldap)
        FILTER="tcp port 389"
        ;;
    ssh)
        FILTER="tcp port 22"
        ;;
    ftp)
        FILTER="tcp port 21"
        ;;
    smb)
        FILTER="tcp port 445"
        ;;
    tftp)
        FILTER="udp port 69"
        ;;
    # Протоколы управления и диагностики
    arp)
        FILTER="arp"
        ;;
    icmp)
        FILTER="icmp"
        ;;
    icmpv6)
        FILTER="icmp6"
        ;;
    stp)
        FILTER="stp"
        ;;
    rstp)
        FILTER="stp"  # RSTP тоже использует STP-фильтр
        ;;
    
    # Протоколы маршрутизации (индивидуальные протоколы, если требуется)
    bgp)
        FILTER="tcp port 179"
        ;;
    ospf)
        FILTER="proto ospf"
        ;;
    rip)
        FILTER="udp port 520"
        ;;
    eigrp)
        FILTER="ip proto 88"
        ;;
    isis)
        FILTER="proto isis"
        ;;
    lldp)
        FILTER="ether proto 0x88cc"
        ;;
    bfd)
        FILTER="tcp port 3784 or udp port 3784 or tcp port 3785 or udp port 3785 or tcp port 4784 or udp port 4784 or udp port 6784 or udp port 7784"
        ;;
    
    # VPN и туннельные протоколы (индивидуальные протоколы, если требуется)
    gre)
        FILTER="proto gre"
        ;;
    ipsec)
        FILTER="proto esp or proto ah"
        ;;
    pptp)
        FILTER="tcp port 1723"
        ;;
    openvpn)
        FILTER="udp port 1194"
        ;;
    wireguard)
        FILTER="udp port 51820"
        ;;
    
    # P2P-протоколы (индивидуальные протоколы, если требуется)
    bittorrent)
        FILTER="tcp portrange 6881-6889 or udp portrange 6881-6889"
        ;;
    edonkey)
        FILTER="tcp port 4662 or udp port 4665"
        ;;
    gnutella)
        FILTER="tcp port 6346"
        ;;
    
    # Протоколы VoIP и мультимедиа (индивидуальные протоколы, если требуется)
    rtp)
        FILTER="udp portrange 16384-32767"
        ;;
    sip)
        FILTER="udp port 5060 or udp port 5061"
        ;;
    
    # Протоколы потоковой передачи данных
    rtsp)
        FILTER="tcp port 554"
        ;;
    h323)
        FILTER="tcp port 1720"
        ;;
    
    # Протоколы администрирования и управления (индивидуальные протоколы, если требуется)
    rdp)
        FILTER="tcp port 3389"
        ;;
    vnc)
        FILTER="tcp port 5900"
        ;;
    
    # Другие часто используемые протоколы
    syslog)
        FILTER="udp port 514"
        ;;
    mikrotik)
        FILTER="tcp port 8291 or tcp port 8728 or tcp port 8729 or tcp port 20561"
        ;;
    
    # Группы для выявления аномалий и атак
    scan)
        # Сканирование портов с использованием нестандартных флагов TCP
        FILTER="tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-psh|tcp-urg) != 0"
        ;;
    ddos)
        # Высокочастотный ICMP и порты UDP, часто используемые в UDP-флудах
        FILTER="icmp or udp portrange 33434-33600 or udp port 80 or udp port 53"
        ;;
    suspicious_ports)
        # Подозрительные порты: 445 (SMB), 3389 (RDP), 23 (Telnet), 1433 (SQL Server), 3306 (MySQL)
        FILTER="tcp port 445 or tcp port 3389 or tcp port 23 or tcp port 1433 or tcp port 3306"
        ;;
    anomaly)
        # Общие аномалии: NULL-сканирование, FIN-сканирование
        FILTER="tcp[tcpflags] == 0 or tcp[tcpflags] == tcp-fin"
        ;;
    port_hopping)
        # Непредсказуемые изменения портов
        FILTER="tcp[2:2] != 0"
        ;;
    burst)
        # Всплески трафика
        FILTER="tcp or udp and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-rst != 0)"
        ;;
    suspicious_traffic)
        # Необычные объемы трафика
        FILTER="tcp or udp"
        ;;
    telnet)
         #telnet
         FILTER="tcp port 23"
        ;;
    kms)
        #windows kms
        FILTER="tcp port 1688"
        ;;
    *)
        echo "Unsupported protocol or group: $PROTOCOL"
        exit 1
        ;;
esac

# Если есть дополнительные аргументы, добавляем их к фильтру
if [ "$#" -gt 3 ]; then
    shift 3  # Убираем первые три аргумента
    ADDITIONAL_FILTERS="$*"
    FILTER="$FILTER $ADDITIONAL_FILTERS"
fi

# Запуск tcpdump с нужным фильтром
echo "Running: tcpdump -i $INTERFACE $FILTER"
tcpdump -i "$INTERFACE" $FILTER
