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