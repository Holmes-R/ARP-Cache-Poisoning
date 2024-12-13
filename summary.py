import pyshark

def print_packet_info_and_headers(pcap_file):
    # Open the pcap file for reading
    capture = pyshark.FileCapture(pcap_file)

    # Initialize variables for packet count and a list to store packet information
    packet_count = 0
    packet_info = []

    # Initialize variables for header counts
    total_tcp_packets = 0
    total_udp_packets = 0
    total_http_requests = 0
    total_dns_requests = 0

    # Iterate over each packet in the capture
    for packet in capture:
        packet_count += 1  # Increment packet count

        # Extract packet information
        src_ip = packet.ip.src if 'IP' in packet else 'N/A'
        dst_ip = packet.ip.dst if 'IP' in packet else 'N/A'

        # Extract source and destination MAC addresses if present
        if hasattr(packet, 'eth'):
            src_mac = packet.eth.src
            dst_mac = packet.eth.dst
        else:
            src_mac = 'N/A'
            dst_mac = 'N/A'

        length = packet.length

        # Extract source and destination ports if present
        src_port = packet.tcp.srcport if 'TCP' in packet else (packet.udp.srcport if 'UDP' in packet else 'N/A')
        dst_port = packet.tcp.dstport if 'TCP' in packet else (packet.udp.dstport if 'UDP' in packet else 'N/A')

        try:
            # Extract the protocol for each layer in the packet
            protocols = [layer.layer_name for layer in packet.layers]

            # Count headers
            protocol = packet.transport_layer
            if protocol == 'TCP':
                total_tcp_packets += 1
            elif protocol == 'UDP':
                total_udp_packets += 1
            if 'HTTP' in packet:
                total_http_requests += 1
            if 'DNS' in packet:
                total_dns_requests += 1

            # Append packet information and protocols to the packet_info list
            packet_info.append({
                'Number': packet_count,
                'Source IP': src_ip,
                'Destination IP': dst_ip,
                'Source MAC': src_mac,
                'Destination MAC': dst_mac,
                'Length': length,
                'Protocols': protocols,
                'Source Port': src_port,
                'Destination Port': dst_port
            })

        except AttributeError:
            # Skip packets that don't have any layers
            pass

    # Close the capture file
    capture.close()

    # Print out the summary
    print("\nSummary of Packets:")
    for info in packet_info:
        print(f"\nPacket Number: {info['Number']}")
        print(f"Source IP: {info['Source IP']}, Destination IP: {info['Destination IP']}, Source MAC: {info['Source MAC']}, Destination MAC: {info['Destination MAC']}, Length: {info['Length']}")
        print(f"Source Port: {info['Source Port']}, Destination Port: {info['Destination Port']}")
        print(f"Protocols: {info['Protocols']}")
        print("-" * 40)  # Underline between packets

    # Print double line for the total number of captured packets
    print("\n" + "=" * 80)
    print(f"\nTotal number of packets captured: {packet_count}")
    print(f"Total TCP Packets: {total_tcp_packets}")
    print(f"Total UDP Packets: {total_udp_packets}")
    print(f"Total HTTP Requests: {total_http_requests}")
    print(f"Total DNS Requests: {total_dns_requests}")
    print("=" * 80)

# Specify the path to the pcap input file
pcap_file = 'arper.pcap'

# Print the packet information and headers
print_packet_info_and_headers(pcap_file)
