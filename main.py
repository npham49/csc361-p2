import sys
from modules.pcap_parser import parse_pcap_header, parse_packet
from modules.tcp_analyzer import analyze_tcp_connections, print_connection_summary

def main():
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        packets = []
        try:
            with open(file_path, 'rb') as file:
                # Read .cap file in binary mode
                data = file.read()
                
                print(f"Successfully opened {file_path}")
                print(f"File size: {len(data)} bytes\n")
                
                # Parse pcap header
                header = parse_pcap_header(data)
                if not header:
                    print("Error: Invalid pcap file format")
                    return
                
                print("=== PCAP File Header ===")
                print(f"Version: {header['version_major']}.{header['version_minor']}")
                print(f"Snaplen: {header['snaplen']}")
                print(f"Network type: {header['network']}")
                print(f"Byte order: {header['byteorder']}\n")
                
                # Parse packets
                offset = 24  # Start after global header
                packet_num = 1
                
                print("=== Packets ===\n")
                while offset < len(data):
                    packet, new_offset = parse_packet(data, offset, header['byteorder'])
                    
                    if packet is None:
                        break

                    packets.append(packet)
                    
                    print(f"--- Packet #{packet_num} ---")
                    print(f"Timestamp: {packet['timestamp_sec']}.{packet['timestamp_usec']:06d}")
                    print(f"Captured length: {packet['captured_length']} bytes")
                    print(f"Original length: {packet['original_length']} bytes")
                    print()
                    
                    offset = new_offset
                    packet_num += 1
                
                print(f"Total packets: {packet_num - 1}")
                
                # Analyze TCP connections
                print("\nAnalyzing TCP connections...")
                connections = analyze_tcp_connections(packets)
                print_connection_summary(connections)
                
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
        except PermissionError:
            print(f"Error: Permission denied to read '{file_path}'.")
        except Exception as e:
            print(f"Error reading file: {e}")
    else:
        print("Usage: python Tracer.py <FilePath>")

if __name__ == "__main__":
    main()
