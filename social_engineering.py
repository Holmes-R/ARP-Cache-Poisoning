from scapy.all import *
import re

def extract_information(packet):
    email_addresses = []
    urls = []
    user_agents = []
    dns_queries = []
    tcp_info = []

    # Extract email addresses
    if packet.haslayer('Raw'):
        try:
            decoded_payload = packet.getlayer('Raw').load.decode('utf-8')
            if '@' in decoded_payload:
                email_addresses.extend(re.findall(r'[\w\.-]+@[\w\.-]+', decoded_payload))
        except UnicodeDecodeError:
            pass

    # Extract URLs
    if packet.haslayer('HTTPRequest'):
        url = packet.getlayer('HTTPRequest').Host.decode('utf-8') + packet.getlayer('HTTPRequest').Path.decode('utf-8')
        urls.append(url)

    # Extract User-Agents
    if packet.haslayer('HTTP') and packet.haslayer('Raw'):
        user_agent = re.search(b'User-Agent: (.*?)\r\n', packet.getlayer('Raw').load)
        if user_agent:
            try:
                decoded_user_agent = user_agent.group(1).decode('utf-8')
                user_agents.append(decoded_user_agent)
            except UnicodeDecodeError:
                pass

    # Extract DNS queries
    if packet.haslayer(DNSQR):
        dns_query = packet[DNSQR].qname.decode('utf-8')
        dns_queries.append(dns_query)

    # Extract TCP header information
    if packet.haslayer(TCP):
        # Check if ACK flag is set
        if packet[TCP].flags & 0x10:
            tcp_info.append("ACK")
        else:
            tcp_info.append("Not ACK")

        # Get TCP flags
        flags = []
        if packet[TCP].flags & 0x01:
            flags.append("FIN")
        if packet[TCP].flags & 0x02:
            flags.append("SYN")
        if packet[TCP].flags & 0x04:
            flags.append("RST")
        if packet[TCP].flags & 0x08:
            flags.append("PSH")
        if packet[TCP].flags & 0x10:
            flags.append("ACK")
        if packet[TCP].flags & 0x20:
            flags.append("URG")
        if packet[TCP].flags & 0x40:
            flags.append("ECE")
        if packet[TCP].flags & 0x80:
            flags.append("CWR")

        # Append TCP flags to information
        tcp_info.append("Flags: " + ", ".join(flags))

    return email_addresses, urls, user_agents, dns_queries, tcp_info

def analyze_pcap(pcap_file):
    email_addresses = []
    urls = []
    user_agents = []
    dns_queries = []
    tcp_info = []

    packets = rdpcap(pcap_file)

    for packet in packets:
        email, url, user_agent, dns_query, tcp = extract_information(packet)
        email_addresses.extend(email)
        urls.extend(url)
        user_agents.extend(user_agent)
        dns_queries.extend(dns_query)
        tcp_info.extend(tcp)

    return email_addresses, urls, user_agents, dns_queries, tcp_info

if __name__ == "__main__":
    pcap_file = "arper.pcap"
    extracted_email_addresses, extracted_urls, extracted_user_agents, extracted_dns_queries, extracted_tcp_info = analyze_pcap(pcap_file)

    # Print extracted information
    print("Extracted Email Addresses:")
    for email in extracted_email_addresses:
        print(email)

    print("\nExtracted URLs:")
    for url in extracted_urls:
        print(url)

    print("\nExtracted User Agents:")
    for user_agent in extracted_user_agents:
        print(user_agent)

    print("\nExtracted DNS Queries:")
    for dns_query in extracted_dns_queries:
        print(dns_query)

    print("\nExtracted TCP Information:")
    for tcp in extracted_tcp_info:
        print(tcp)
