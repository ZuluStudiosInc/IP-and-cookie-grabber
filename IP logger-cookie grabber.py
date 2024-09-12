import hashlib
import socket
import threading
import os
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
import scapy.all as scapy
from itertools import product
import string
import time
import hmac
import logging
from datetime import datetime
import requests

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global AES Key for Encryption/Decryption
AES_KEY = get_random_bytes(32)

# RSA key pair for public/private encryption
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# ECC key pair for asymmetric encryption
ecc_private_key = ECC.generate(curve='P-256')
ecc_public_key = ecc_private_key.public_key()

# Global storage for malware signatures (simulated)
malware_signatures = ["5d41402abc4b2a76b9719d911017c592", "098f6bcd4621d373cade4e832627b4f6"]

# Port scanner with banner grabbing, service detection, and multi-host support
def advanced_port_scanner(target_ips, start_port, end_port):
    logging.info(f"Advanced scanning {target_ips} for open ports and services between {start_port} and {end_port}...")

    def scan_ip(ip):
        logging.info(f"Scanning IP: {ip}")
        open_ports = []

        def scan_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    try:
                        banner = s.recv(1024).decode('utf-8')
                        logging.info(f"Port {port} is open on {ip}. Banner: {banner}")
                    except Exception as e:
                        logging.warning(f"Port {port} on {ip} is open but no banner detected.")
            except socket.error as e:
                logging.error(f"Error scanning port {port} on {ip}: {e}")
            finally:
                s.close()

        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        if not open_ports:
            logging.info(f"No open ports found on {ip}.")
        else:
            logging.info(f"Open ports on {ip}: {open_ports}")

    for target_ip in target_ips:
        scan_ip(target_ip)

# RSA encryption and decryption
def rsa_encrypt_message(message, public_key):
    logging.info("Encrypting message using RSA...")
    cipher_rsa = public_key.encrypt(message.encode('utf-8'), 32)
    logging.info("Message encrypted successfully.")
    return cipher_rsa

def rsa_decrypt_message(ciphertext, private_key):
    logging.info("Decrypting message using RSA...")
    decrypted_message = private_key.decrypt(ciphertext)
    logging.info("Message decrypted successfully.")
    return decrypted_message.decode('utf-8')

# ECC digital signatures
def ecc_sign_message(message, private_key):
    logging.info("Signing message with ECC...")
    h = SHA256.new(message.encode('utf-8'))
    signature = private_key.sign(h)
    logging.info("Message signed successfully.")
    return signature

def ecc_verify_signature(message, signature, public_key):
    logging.info("Verifying ECC signature...")
    h = SHA256.new(message.encode('utf-8'))
    try:
        public_key.verify(signature, h)
        logging.info("Signature is valid.")
        return True
    except:
        logging.error("Signature is invalid.")
        return False

# Simulated malware signature checking
def malware_signature_check(file_path):
    logging.info(f"Checking {file_path} for malware signatures...")
    file_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    if file_hash in malware_signatures:
        logging.error(f"Malware detected in {file_path}! Hash: {file_hash}")
        return True
    else:
        logging.info(f"No malware detected in {file_path}.")

# ICMP Ping Sweep for live host discovery
def ping_sweep(subnet):
    logging.info(f"Starting ICMP Ping Sweep for subnet {subnet}")
    for ip in range(1, 255):
        target_ip = f"{subnet}.{ip}"
        response = os.system(f"ping -c 1 {target_ip} > /dev/null 2>&1")
        if response == 0:
            logging.info(f"{target_ip} is live.")
        else:
            logging.debug(f"{target_ip} is not reachable.")

if __name__ == "__main__":
    # IPs to scan
    target_ips = ['127.0.0.1', '192.168.1.1']

    # Advanced port scanner
    start_time = time.time()
    advanced_port_scanner(target_ips, 1, 1024)
    logging.info(f"Port scanning completed in {time.time() - start_time:.2f} seconds.\n")

    # RSA Encryption/Decryption example
    encrypted_message = rsa_encrypt_message("This is a secret message", public_key)
    decrypted_message = rsa_decrypt_message(encrypted_message, private_key)
    logging.info(f"Decrypted message: {decrypted_message}")

    # ECC Signing/Verification example
    signature = ecc_sign_message("This message needs to be signed", ecc_private_key)
    is_valid = ecc_verify_signature("This message needs to be signed", signature, ecc_public_key)
    logging.info(f"ECC signature valid: {is_valid}")
