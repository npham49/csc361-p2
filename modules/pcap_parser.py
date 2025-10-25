def parse_pcap_header(data):
    """Parse the global pcap header (24 bytes)"""
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
        'version_major': int.from_bytes(data[4:6], byteorder=byteorder),
        'version_minor': int.from_bytes(data[6:8], byteorder=byteorder),
        'snaplen': int.from_bytes(data[16:20], byteorder=byteorder),
        'network': int.from_bytes(data[20:24], byteorder=byteorder)
    }

def parse_packet(data, offset, byteorder):
    """Parse a single packet starting at offset"""
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

