import dpkt
import socket
import nmap

def extract_ip_addresses_from_pcap(pcap_file):
    ip_addresses = set()
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data.dst
                ip_addresses.add(socket.inet_ntoa(ip))
    return ip_addresses

def get_hostname(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Unknown"

def perform_port_scan(ip_addresses, pcap_file):
    scanner = nmap.PortScanner()
    for ip_address in ip_addresses:
        print(f"Scanning port for IP: {ip_address}")
        hostname = get_hostname(ip_address)
        print(f"Hostname: {hostname}")
        scanner.scan(ip_address)
        for host in scanner.all_hosts():
            print(f"Hostname: {host} ({scanner[host].hostname()})")
            for proto in scanner[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = scanner[host][proto].keys()
                for port in ports:
                    state = scanner[host][proto][port]['state']
                    print(f"Port: {port}\tState: {state}")

                    if port == 80 or port == 8080:
                        print("HTTP Service Detected")
                        print_http_queries(ip_address, pcap_file)

                    if port == 53:
                        print("DNS Service Detected")
                        print_dns_queries(ip_address, pcap_file)

def print_http_queries(ip_address, pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap_obj:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if socket.inet_ntoa(ip.dst) == ip_address:
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        if tcp.dport == 80 or tcp.dport == 8080:
                            try:
                                http_request = dpkt.http.Request(tcp.data)
                                print("HTTP Request:")
                                print(http_request.uri)
                            except (dpkt.UnpackError,dpkt.dpkt.NeedData):
                                pass
                        elif tcp.sport == 80 or tcp.sport == 8080:
                            try:
                                http_response = dpkt.http.Response(tcp.data)
                                print("HTTP Response:")
                                print(http_response.status)
                            except (dpkt.UnpackError,dpkt.dpkt.NeedData):
                                pass

def print_dns_queries(ip_address, pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap_obj:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if socket.inet_ntoa(ip.dst) == ip_address:
                    if isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        if udp.dport == 53:
                            print("DNS Query:")
                            # Implement logic to extract and print DNS queries here
                            try:
                                dns = dpkt.dns.DNS(udp.data)
                                for q in dns.qd:
                                    print(q.name)
                            except dpkt.UnpackError:
                                pass

# Usage
pcap_file = 'arper.pcap'
ip_addresses = extract_ip_addresses_from_pcap(pcap_file)
perform_port_scan(ip_addresses, pcap_file)
