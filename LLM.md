# LLM Usage

## Overview

This document describes how LLM was utilized in the development of this assignment.

## LLM utilization

- List all byte positions of the TCP header fields in a pcap file in respect to their offsets in the headers. - this provided me with the byte positions of each headers, I used this initially and then validated with Wireshark later on.

- How to handle reading byte data from a pcap file in Python. - this helped me understand how to read binary data from a pcap file using the read function in Python, also told me to use the rb option.

- I have an issue where the connections source and destination are reversed sometimes, how to handle this? - this helped me understand the concept of 4-tuples and how to handle connections in both directions by checking for both key and reverse_key in the connections dictionary.

- little vs big endian byte order - this helped me understand the difference between little and big endian byte order, and how to use the struct module in Python to unpack data accordingly.
