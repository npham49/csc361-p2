# Print out some general anaytics from the list of connections returned
def print_general_statistics(connections):
    """Print general statistics about TCP connections"""
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

