This repository contains an advanced cybersecurity toolset built in Python, incorporating various security functionalities such as:

Advanced Port Scanner: Performs multi-host, multi-port scanning with banner grabbing and service detection.
RSA Encryption/Decryption: Utilizes RSA public/private key encryption to securely encrypt and decrypt messages.
ECC Digital Signatures: Implements Elliptic Curve Cryptography (ECC) for message signing and verification.
Malware Signature Detection: Simulates basic malware detection by checking files against known malware hashes.
ICMP Ping Sweep: Discovers live hosts within a subnet by sending ICMP ping requests.
The tool leverages multiple cryptography libraries, threading for performance, and logging for detailed monitoring of operations.

Features:
Asymmetric Encryption/Decryption using RSA and ECC for secure communication.
Port Scanning with service detection and banner grabbing.
Signature-based Malware Detection using a simulated database of malware hashes.
Live Host Detection with ICMP Ping Sweeping.
This project can be easily extended to include additional scanning techniques or more sophisticated malware detection methods.

Dependencies:
pycryptodome for cryptography
scapy for network packet crafting and manipulation
requests for handling web requests (if needed in future extensions)
