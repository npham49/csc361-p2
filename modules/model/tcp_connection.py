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
