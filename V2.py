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
from threading import Lock

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

AES_KEY = get_random_bytes(32)

private_key = RSA.generate(2048)
public_key = private_key.publickey()

ecc_private_key = ECC.generate(curve='P-256')
ecc_public_key = ecc_private_key.public_key()

malware_signatures = ["5d41402abc4b2a76b9719d911017c592", "098f6bcd4621d373cade4e832627b4f6"]

file_hashes = {}

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

def vulnerability_scanner(target_ips):
    logging.info("Starting multi-threaded vulnerability scanning...")

    common_vulnerabilities = ["CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708"]

    def scan_for_vulnerabilities(ip):
        for cve in common_vulnerabilities:
            logging.info(f"Checking {ip} for {cve}...")
            time.sleep(0.5)  
            logging.info(f"{ip} is not vulnerable to {cve}.")

    threads = []
    for ip in target_ips:
        t = threading.Thread(target=scan_for_vulnerabilities, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    logging.info("Vulnerability scanning completed.")

def file_integrity_monitor(file_paths):
    logging.info("Starting file integrity monitoring...")

    def check_file_integrity(file_path):
        logging.info(f"Checking integrity of {file_path}...")
        current_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
        if file_path in file_hashes:
            if file_hashes[file_path] != current_hash:
                logging.warning(f"File integrity compromised for {file_path}!")
            else:
                logging.info(f"No changes detected for {file_path}.")
        else:
            logging.info(f"Hashing new file: {file_path}")
        file_hashes[file_path] = current_hash

    threads = []
    for file_path in file_paths:
        t = threading.Thread(target=check_file_integrity, args=(file_path,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    logging.info("File integrity monitoring completed.")

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

def advanced_malware_detection(file_path):
    logging.info(f"Running heuristic analysis on {file_path}...")
    file_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    if file_hash in malware_signatures:
        logging.error(f"Known malware detected in {file_path}! Hash: {file_hash}")
        return True
    else:
        logging.info(f"No known malware found in {file_path}. Running further heuristic analysis...")
        suspicious_patterns = ["exec", "bin/sh"]
        with open(file_path, 'r') as f:
            content = f.read()
            if any(pattern in content for pattern in suspicious_patterns):
                logging.warning(f"Suspicious patterns detected in {file_path}. Potential malware.")
                return True
        logging.info(f"No malware detected in {file_path}.")
        return False

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
    target_ips = ['127.0.0.1', '192.168.1.1']

    start_time = time.time()
    advanced_port_scanner(target_ips, 1, 1024)
    logging.info(f"Port scanning completed in {time.time() - start_time:.2f} seconds.\n")

    vulnerability_scanner(target_ips)

    encrypted_message = rsa_encrypt_message("This is a secret message", public_key)
    decrypted_message = rsa_decrypt_message(encrypted_message, private_key)
    logging.info(f"Decrypted message: {decrypted_message}")

    signature = ecc_sign_message("This message needs to be signed", ecc_private_key)
    is_valid = ecc_verify_signature("This message needs to be signed", signature, ecc_public_key)
    logging.info(f"ECC signature valid: {is_valid}")

    monitored_files = ['file1.txt', 'file2.txt']  
    file_integrity_monitor(monitored_files)

    advanced_malware_detection('suspicious_file.txt')  
