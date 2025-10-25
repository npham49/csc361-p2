class TCPConnection:
    """Represents a TCP connection with tracking of packets and flags"""
    
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        
        # Track SYN and FIN counts
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        
        # Track packets and data
        self.packets_src_to_dst = 0
        self.packets_dst_to_src = 0
        self.data_bytes_src_to_dst = 0
        self.data_bytes_dst_to_src = 0
        
        # Timing information
        self.start_time = None
        self.end_time = None
        
    def add_packet(self, src_ip, dst_ip, tcp_flags, tcp_data_len, timestamp):
        if self.start_time is None:
            self.start_time = timestamp
        
        self.end_time = timestamp
        
        # Count SYN flags (0x012 for SYN ACK and 0x002 for SYN so we use 0x02)
        if tcp_flags & 0x02:  # SYN flag
            self.syn_count += 1
        
        # Count FIN flags
        if tcp_flags & 0x01:  # FIN flag
            self.fin_count += 1
        
        # Count RST flags
        if tcp_flags & 0x04:  # RST flag
            self.rst_count += 1
        
        # Track packet direction
        if src_ip == self.src_ip and dst_ip == self.dst_ip:
            self.packets_src_to_dst += 1
            self.data_bytes_src_to_dst += tcp_data_len
        else:
            self.packets_dst_to_src += 1
            self.data_bytes_dst_to_src += tcp_data_len
    
    def get_status(self):
        if self.rst_count > 0:
            return "S{}F{}/R".format(self.syn_count, self.fin_count)
        return "S{}F{}".format(self.syn_count, self.fin_count)
    
    def is_complete(self):
        return self.syn_count >= 1 and self.fin_count >= 1
    
    def get_duration(self):
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time
    
    def get_total_packets(self):
        return self.packets_src_to_dst + self.packets_dst_to_src
    
    def get_total_data_bytes(self):
        return self.data_bytes_src_to_dst + self.data_bytes_dst_to_src


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
    
    for packet in packets:
        # Get timestamp
        timestamp = packet['timestamp_sec'] + packet['timestamp_usec'] / 1000000.0
        
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

        # Create a connection key that would reflect both directions
        key = get_connection_key(ip['src_ip'], ip['dst_ip'], tcp['src_port'], tcp['dst_port'])
        
        # Once we have the key then the process would just be finding out packets in
        # that connection, if not exist create it
        if key not in connections:
            connections[key] = TCPConnection(key[0], key[1], key[2], key[3])
        
        connections[key].add_packet(
            ip['src_ip'], 
            ip['dst_ip'], 
            tcp['flags'], 
            tcp['data_length'],
            timestamp
        )
    
    return list(connections.values())


def print_connection_summary(connections):
    print("\n" + "-"*70 + "\n")
    print("TCP Connection Summary")
    print("\n" + "-"*70 + "\n")
    print(f"\nTotal TCP connections found: {len(connections)}")
    
    complete_count = sum(1 for conn in connections if conn.is_complete())
    print(f"Complete connections (with SYN and FIN): {complete_count}")
    print(f"Incomplete connections: {len(connections) - complete_count}")
    
    print("\n" + "-"*70 + "\n")
    
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
