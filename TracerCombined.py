import sys

def main():
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        packets = []
        try:
            with open(file_path, 'rb') as file:
                # Read .cap file in binary mode
                data = file.read()
                
                # Parse pcap header
                header = parse_pcap_header(data)
                if not header:
                    print("Error: Invalid pcap file format")
                    return
                
                # Parse packets
                offset = 24  # Start after global header
                packet_num = 1
                while offset < len(data):
                    packet, new_offset = parse_packet(data, offset, header['byteorder'])
                    
                    if packet is None:
                        break

                    packets.append(packet)
                    
                    offset = new_offset
                    packet_num += 1
                
                print(f"Total packets: {packet_num - 1}")
                
                # Analyze TCP connections
                print("\nAnalyzing TCP connections...")
                connections = analyze_tcp_connections(packets)
                print("\n" + "="*70 + "\n")
                print(f"A) Total Number of TCP Connections: {len(connections)}")

                print("\n" + "="*70 + "\n")
                print("B) Connections' details")
                print_connection_summary(connections)
                print_general_statistics(connections)
                print_complete_connection_statistics(connections)
                
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
        except PermissionError:
            print(f"Error: Permission denied to read '{file_path}'.")
        except Exception as e:
            print(f"Error reading file: {e}")
    else:
        print("Usage: python Tracer.py <FilePath>")

# modules/model/tcp_connection.py
# Class instance to represent a TCP connection and track its state
# each attribute represents a metric we want to track for the connection as required in the assignment description
class TCPConnection:
    
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
        
        # Track first packet
        self.first_packet_is_syn = None
        
    def add_packet(self, src_ip, dst_ip, tcp_flags, tcp_data_len, timestamp):
        # this is the first time we see a packet in this connection
        if self.start_time is None:
            self.start_time = timestamp
            # Check if first packet has SYN flag
            self.first_packet_is_syn = bool(tcp_flags & 0x02)
        
        # Count SYN flags (0x012 for SYN ACK and 0x002 for SYN so we use 0x02)
        if tcp_flags & 0x02:  # SYN flag
            self.syn_count += 1
        
        # Count FIN flags
        if tcp_flags & 0x01:  # FIN flag
            self.fin_count += 1
            self.end_time = timestamp
        
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
    
    def is_reset(self):
        return self.rst_count > 0
    
    def established_before_capture(self):
        return self.first_packet_is_syn is False
    
    def get_duration(self):
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time
    
    def get_total_packets(self):
        return self.packets_src_to_dst + self.packets_dst_to_src
    
    def get_total_data_bytes(self):
        return self.data_bytes_src_to_dst + self.data_bytes_dst_to_src

# modules/tcp_analyzer.py
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

# modules/pcap_parser.py
def parse_pcap_header(data):
    if len(data) < 24:
        return None
    
    # Read magic number (4 bytes)
    magic = int.from_bytes(data[0:4], byteorder='little')
    
    # Check if it's a valid pcap file
    if magic == 0xa1b2c3d4:
        byteorder = 'little'
    elif magic == 0xd4c3b2a1:
        byteorder = 'big'
    else:
        print(f"Invalid pcap magic number: {magic:08x}")
        return None
    
    return {
        'magic': magic,
        'byteorder': byteorder,
    }

def parse_packet(data, offset, byteorder):
    if offset + 16 > len(data):
        return None, offset
    
    # Parse packet header (16 bytes)
    ts_sec = int.from_bytes(data[offset:offset+4], byteorder=byteorder)
    ts_usec = int.from_bytes(data[offset+4:offset+8], byteorder=byteorder)
    incl_len = int.from_bytes(data[offset+8:offset+12], byteorder=byteorder)
    orig_len = int.from_bytes(data[offset+12:offset+16], byteorder=byteorder)
    
    # Get packet data
    packet_start = offset + 16
    packet_end = packet_start + incl_len
    
    if packet_end > len(data):
        return None, offset
    
    packet_data = data[packet_start:packet_end]
    
    packet_info = {
        'timestamp_sec': ts_sec,
        'timestamp_usec': ts_usec,
        'captured_length': incl_len,
        'original_length': orig_len,
        'data': packet_data
    }
    
    return packet_info, packet_end

# modules/general_analyzer.py
# Print out some general anaytics from the list of connections returned
def print_general_statistics(connections):
    print("\n" + "="*70)
    print("C) General")
    print("="*70 + "\n")
    
    # Count complete connections
    complete_count = sum(1 for conn in connections if conn.is_complete())
    print(f"The total number of complete TCP connections: {complete_count}")
    
    # Count reset connections
    reset_count = sum(1 for conn in connections if conn.is_reset())
    print(f"The number of reset TCP connections: {reset_count}")
    
    # Count connections still open when capture ended
    open_count = sum(1 for conn in connections if not conn.is_complete())
    print(f"The number of TCP connections that were still open when the trace capture ended: {open_count}")
    
    # Count connections established before capture
    before_capture_count = sum(1 for conn in connections if conn.established_before_capture())
    print(f"The number of TCP connections established before the capture started: {before_capture_count}")

# modules/complete_analyzer.py
def print_complete_connection_statistics(connections):
    print("\n" + "="*70)
    print("D) Complete TCP connections:")
    print("="*70 + "\n")
    
    # Filter only complete connections
    complete_connections = [conn for conn in connections if conn.is_complete()]
    
    if len(complete_connections) == 0:
        print("No complete TCP connections found.")
        print("\n" + "="*70 + "\n")
        return
    
    # Calculate duration statistics
    durations = [conn.get_duration() for conn in complete_connections]
    min_duration = min(durations)
    mean_duration = sum(durations) / len(durations)
    max_duration = max(durations)
    
    # Calculate packet count statistics
    packet_counts = [conn.get_total_packets() for conn in complete_connections]
    min_packets = min(packet_counts)
    mean_packets = sum(packet_counts) / len(packet_counts)
    max_packets = max(packet_counts)
    
    print(f"Minimum time duration: {min_duration:.6f} seconds")
    print(f"Mean time duration: {mean_duration:.6f} seconds")
    print(f"Maximum time duration: {max_duration:.6f} seconds")
    print()
    print(f"Minimum number of packets including both send/received: {min_packets}")
    print(f"Mean number of packets including both send/received: {mean_packets:.2f}")
    print(f"Maximum number of packets including both send/received: {max_packets}")
    
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    main()
