# WebTester

## Overview

Tracer analyzes a capture file from Wireshark.

**NOTE**: I decided to skip RTT and window calculation due to running out of time and focusing on reviewing the midterm exam material.
**NOTE 2**: This project was originally built using multiple modules approach to mimic real-world Python projects. However, to accommodate the request for a single combined file, I have created `TracerCombined.py` which consolidates all the necessary code into one file while maintaining the original functionality.

## Running the tester

### Prerequisites

- Python 3.x installed on your machine

### Steps

Run the following command in your terminal:

```bash
python TracerCombined.py <path_to_pcap_file>
```

Or if you have Python 3 specifically:

```bash
python3 TracerCombined.py <path_to_pcap_file>
```

Replace `<path_to_pcap_file>` with the actual path to your pcap file.

## Architecture:

The `modules` directory contains majority of the code that parses and display information from the pcap input file.

There is a model to handle parsing and creating instances of each TCP connection declared in `tcp_connection.py`.

Each module handles a specific part of the parsing and displaying process:

- `pcap_parser.py`: Responsible for reading and parsing the pcap file.
- `tcp_analyzer.py`: Analyzes TCP packets and extracts relevant information. (Section A and B)
- `general_analyzer.py`: Provides general statistics about the captured packets. (Section C)
- `complete_analyzer.py`: Offers detailed statistics about the complete TCP connections. (Section D)

## How it works:

When a file is provided as input, the `main.py` script orchestrates the parsing and analysis process by utilizing the modules mentioned above. It reads the pcap file, parses the header out first, then look at each of the packets by parsing the data in 24-byte chunks. For each packet entry we parse out the 3 headers (Ethernet, IP, TCP) and extract relevant information. Then we use these information to create or update TCP connection instances based on the 4 tuples (source IP, source port, destination IP, destination port).

Information parsing is also done by parsing for the specific data index of each field in the headers, by also using smart AND bitmasking and shifting to extract the relevant bits for each field.

Once this list of TCP connections is built, we then proceed to display the information in 4 sections:

- Section A: Summary of TCP connections
- Section B: Details of each TCP connection
- Section C: General statistics about the captured packets
- Section D: Complete statistics about each TCP connection

## LLM Usage

This is covered in [LLM.md](LLM.md)
