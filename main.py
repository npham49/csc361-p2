import sys
from modules.pcap_parser import parse_pcap_header, parse_packet
from modules.tcp_analyzer import analyze_tcp_connections, print_connection_summary
from modules.general_analyzer import print_general_statistics
from modules.complete_analyzer import print_complete_connection_statistics

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

if __name__ == "__main__":
    main()
