from modules.model.tcp_connection import TCPConnection

def parse_ethernet_header(packet_data):
    if len(packet_data) < 14:
        return None
    
    # Get EtherType (bytes 12-13)
    ether_type = int.from_bytes(packet_data[12:14], byteorder='big')
    
    return {
        'ether_type': ether_type,
        'payload': packet_data[14:]
    }


def parse_ip_header(ip_data):
    if len(ip_data) < 20:
        return None
    
    version = (ip_data[0] >> 4) & 0x0F
    if version != 4: 
        return None
    
    ihl = (ip_data[0] & 0x0F) * 4  # Header length in bytes
    protocol = ip_data[9]
    src_ip = '.'.join(str(b) for b in ip_data[12:16])
    dst_ip = '.'.join(str(b) for b in ip_data[16:20])

    return {
        'version': version,
        'header_length': ihl,
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'payload': ip_data[ihl:]
    }


def parse_tcp_header(tcp_data):
    if len(tcp_data) < 20:
        return None
    
    src_port = int.from_bytes(tcp_data[0:2], byteorder='big')
    dst_port = int.from_bytes(tcp_data[2:4], byteorder='big')
    
    # Data offset (header length) is in the upper 4 bits of byte 12
    data_offset = ((tcp_data[12] >> 4) & 0x0F) * 4

    # TCP flags are in byte 13 since we are only considering the SYN FIN RST, which are all 1 byte
    flags = tcp_data[13]
    
    tcp_data_len = len(tcp_data) - data_offset
    
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'header_length': data_offset,
        'flags': flags,
        'data_length': tcp_data_len
    }


def get_connection_key(src_ip, dst_ip, src_port, dst_port):
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port)
    else:
        return (dst_ip, src_ip, dst_port, src_port)


def analyze_tcp_connections(packets):
    connections = {}
    
    # Find the first packet's timestamp to use as baseline (relative time)
    first_timestamp = None
    if packets:
        first_timestamp = packets[0]['timestamp_sec'] + packets[0]['timestamp_usec'] / 1000000.0
    
    for packet in packets:
        # Get timestamp (relative to first packet)
        timestamp = packet['timestamp_sec'] + packet['timestamp_usec'] / 1000000.0
        if first_timestamp is not None:
            timestamp = timestamp - first_timestamp
        
        # Parse Ethernet header
        eth = parse_ethernet_header(packet['data'])
        if not eth or eth['ether_type'] != 0x0800:  # 0x0800 = IPv4
            continue
        
        # Parse IP header
        ip = parse_ip_header(eth['payload'])
        if not ip or ip['protocol'] != 6:  # 6 = TCP
            continue
        
        # Parse TCP header
        tcp = parse_tcp_header(ip['payload'])
        if not tcp:
            continue
        
        # Create keys for both directions
        key = (ip['src_ip'], ip['dst_ip'], tcp['src_port'], tcp['dst_port'])
        reverse_key = (ip['dst_ip'], ip['src_ip'], tcp['dst_port'], tcp['src_port'])
        
        # Check if connection exists in either direction
        if key in connections:
            # Connection already exists in this direction
            connections[key].add_packet(
                ip['src_ip'],
                ip['dst_ip'],
                tcp['flags'],
                tcp['data_length'],
                timestamp
            )
        elif reverse_key in connections:
            # Connection exists in reverse direction, add packet there
            connections[reverse_key].add_packet(
                ip['src_ip'],
                ip['dst_ip'],
                tcp['flags'],
                tcp['data_length'],
                timestamp
            )
        else:
            # New connection - create with this packet's direction
            connections[key] = TCPConnection(ip['src_ip'], ip['dst_ip'], tcp['src_port'], tcp['dst_port'])
            connections[key].add_packet(
                ip['src_ip'],
                ip['dst_ip'],
                tcp['flags'],
                tcp['data_length'],
                timestamp
            )
    
    return list(connections.values())


def print_connection_summary(connections):
    for i, conn in enumerate(connections, 1):
        print(f"Connection {i}:")
        print(f"Source Address: {conn.src_ip}")
        print(f"Destination Address: {conn.dst_ip}")
        print(f"Source Port: {conn.src_port}")
        print(f"Destination Port: {conn.dst_port}")
        print(f"Status: {conn.get_status()}")
        
        if conn.is_complete():
            print(f"Start time: {conn.start_time:.6f} seconds")
            print(f"End Time: {conn.end_time:.6f} seconds")
            print(f"Duration: {conn.get_duration():.6f} seconds")
            print(f"Number of packets sent from Source to Destination: {conn.packets_src_to_dst}")
            print(f"Number of packets sent from Destination to Source: {conn.packets_dst_to_src}")
            print(f"Total number of packets: {conn.get_total_packets()}")
            print(f"Number of data bytes sent from Source to Destination: {conn.data_bytes_src_to_dst}")
            print(f"Number of data bytes sent from Destination to Source: {conn.data_bytes_dst_to_src}")
            print(f"Total number of data bytes: {conn.get_total_data_bytes()}")
        
        print("END")
        print("\n" + "-"*70 + "\n")
