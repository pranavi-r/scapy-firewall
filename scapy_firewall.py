#!/usr/bin/env python3

from scapy.all import *
import argparse
import logging
import sys
import os

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger('scapy-firewall')

BLOCKED_IPS = set()
BLOCKED_PORTS = set()
ALLOWED_IPS = set()
LOG_FILE = "firewall_log.txt"

def setup_logging(log_file):
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    logger.info("Started")

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if src_ip in BLOCKED_IPS:
            logger.warning(f"Blocked: {src_ip}")
            return
        
        if src_ip in ALLOWED_IPS:
            return packet
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        else:
            return packet
        
        if dst_port in BLOCKED_PORTS:
            logger.warning(f"Blocked {protocol} connection from {src_ip}:{src_port} to port {dst_port}")
            return
        
        logger.info(f"Allowed {protocol} connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
    
    return packet

def load_rules(rules_file):
    try:
        with open(rules_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                rule_type, value = parts[0], parts[1]
                
                if rule_type.lower() == 'block-ip':
                    BLOCKED_IPS.add(value)
                    logger.info(f"Added {value} to blocked IPs")
                elif rule_type.lower() == 'block-port':
                    BLOCKED_PORTS.add(int(value))
                    logger.info(f"Added port {value} to blocked ports")
                elif rule_type.lower() == 'allow-ip':
                    ALLOWED_IPS.add(value)
                    logger.info(f"Added {value} to allowed IPs")
    except FileNotFoundError:
        logger.error(f"Rules file {rules_file} not found")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Simple Scapy Firewall')
    parser.add_argument('-i', '--interface', default='en0', help='Network interface to monitor')
    parser.add_argument('-r', '--rules', default='firewall_rules.txt', help='Firewall rules file')
    parser.add_argument('-l', '--log', default=LOG_FILE, help='Log file path')
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("Use sudo.")
        sys.exit(1)
    
    setup_logging(args.log)
    
    load_rules(args.rules)
    
    logger.info(f"Starting: {args.interface}")
    logger.info(f"Blocked IPs: {BLOCKED_IPS}")
    logger.info(f"Blocked Ports: {BLOCKED_PORTS}")
    logger.info(f"Allowed IPs: {ALLOWED_IPS}")
    
    try:
        sniff(iface=args.interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        logger.info("Stopped")
    except Exception as e:
        logger.error(f"Error: {e}")

if __name__ == "__main__":
    main()