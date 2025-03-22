#!/usr/bin/env python3

from scapy.all import *
import argparse
import logging
import sys
import os
import time
import ipaddress
import threading
import json
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import socket
from collections import defaultdict, Counter
import signal

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger('scapy-firewall')

BLOCKED_IPS = set()
BLOCKED_PORTS = set()
ALLOWED_IPS = set()
CIDR_BLOCKS = []
CONN_TRACK = {}
LOG_FILE = "firewall_log.txt"
MAX_LOG_SIZE = 10 * 1024 * 1024
BLACKLIST_URL = "https://blocklist.example.com/list.txt"
STATS = {
    "packets_processed": 0,
    "packets_dropped": 0,
    "packets_allowed": 0,
    "last_update": time.time()
}
RATE_LIMITS = defaultdict(Counter)
RATE_THRESHOLD = 100
RATE_WINDOW = 60
LOCK = threading.Lock()
WEB_PORT = 8080
APP_RUNNING = True

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
                
                elif rule_type.lower() == 'block-port':
                    BLOCKED_PORTS.add(int(value))
                
                elif rule_type.lower() == 'allow-ip':
                    ALLOWED_IPS.add(value)
                
                elif rule_type.lower() == 'block-net':
                    CIDR_BLOCKS.append(ipaddress.ip_network(value))
                
                elif rule_type.lower() == 'rate-limit':
                    parts = value.split(':')
                    if len(parts) == 2:
                        RATE_THRESHOLD = int(parts[0])
                        RATE_WINDOW = int(parts[1])
    except Exception as e:
        logger.error(f"Error loading rules: {e}")
        sys.exit(1)

def setup_logging(log_file):
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    
    def rotate_logs():
        while APP_RUNNING:
            try:
                if os.path.exists(log_file) and os.path.getsize(log_file) > MAX_LOG_SIZE:
                    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                    backup = f"{log_file}.{timestamp}"
                    os.rename(log_file, backup)
                    logger.handlers = [h for h in logger.handlers if not isinstance(h, logging.FileHandler)]
                    file_handler = logging.FileHandler(log_file)
                    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                    logger.addHandler(file_handler)
            except Exception as e:
                print(f"Error rotating logs: {e}")
            time.sleep(60)
    
    log_thread = threading.Thread(target=rotate_logs)
    log_thread.daemon = True
    log_thread.start()

def is_ip_blocked(ip):
    if ip in ALLOWED_IPS:
        return False
    
    if ip in BLOCKED_IPS:
        return True
    
    for net in CIDR_BLOCKS:
        if ipaddress.ip_address(ip) in net:
            return True
    
    return False

def check_rate_limit(ip):
    now = int(time.time())
    with LOCK:
        RATE_LIMITS[ip][now] += 1
        
        total = sum(count for ts, count in RATE_LIMITS[ip].items() if now - ts <= RATE_WINDOW)
        return total > RATE_THRESHOLD

def track_connection(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto = "TCP"
            flags = packet[TCP].flags
            
            conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-TCP"
            
            if flags & 0x02:  # SYN flag
                CONN_TRACK[conn_id] = {"start_time": time.time(), "state": "SYN", "packets": 1}
                return True
            
            if conn_id in CONN_TRACK:
                CONN_TRACK[conn_id]["packets"] += 1
                CONN_TRACK[conn_id]["last_seen"] = time.time()
                
                if flags & 0x01:  # FIN flag
                    CONN_TRACK[conn_id]["state"] = "FIN"
                
                if flags & 0x04:  # RST flag
                    CONN_TRACK[conn_id]["state"] = "RST"
                
                return True
            
            rev_conn_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-TCP"
            if rev_conn_id in CONN_TRACK:
                return True
        
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto = "UDP"
            
            conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-UDP"
            
            if conn_id not in CONN_TRACK:
                CONN_TRACK[conn_id] = {"start_time": time.time(), "state": "ACTIVE", "packets": 1}
            else:
                CONN_TRACK[conn_id]["packets"] += 1
                CONN_TRACK[conn_id]["last_seen"] = time.time()
            
            rev_conn_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-UDP"
            if rev_conn_id in CONN_TRACK:
                return True
    
    return False

def clean_old_connections():
    while APP_RUNNING:
        try:
            now = time.time()
            with LOCK:
                to_delete = []
                
                for conn_id, data in CONN_TRACK.items():
                    if data["state"] in ["FIN", "RST"] and now - data.get("last_seen", data["start_time"]) > 60:
                        to_delete.append(conn_id)
                    elif now - data.get("last_seen", data["start_time"]) > 300:
                        to_delete.append(conn_id)
                
                for conn_id in to_delete:
                    del CONN_TRACK[conn_id]
                
                old_times = []
                for ip in RATE_LIMITS:
                    for ts in list(RATE_LIMITS[ip].keys()):
                        if now - ts > RATE_WINDOW:
                            old_times.append((ip, ts))
                
                for ip, ts in old_times:
                    del RATE_LIMITS[ip][ts]
        except Exception as e:
            print(f"Error cleaning connections: {e}")
        
        time.sleep(10)

def packet_callback(packet):
    try:
        with LOCK:
            STATS["packets_processed"] += 1
        
        if IP not in packet:
            return packet
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if is_ip_blocked(src_ip):
            with LOCK:
                STATS["packets_dropped"] += 1
            logger.warning(f"Blocked packet from {src_ip}")
            return
        
        if track_connection(packet):
            pass
        elif check_rate_limit(src_ip):
            with LOCK:
                STATS["packets_dropped"] += 1
            logger.warning(f"Rate limit exceeded for {src_ip}")
            return
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        else:
            with LOCK:
                STATS["packets_allowed"] += 1
            return packet
        
        if dst_port in BLOCKED_PORTS:
            with LOCK:
                STATS["packets_dropped"] += 1
            logger.warning(f"Blocked {protocol} from {src_ip}:{src_port} to port {dst_port}")
            return
        
        with LOCK:
            STATS["packets_allowed"] += 1
        
        return packet
    except Exception as e:
        logger.error(f"Error processing packet: {e}")
        return packet

class FirewallHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            with LOCK:
                stats_copy = STATS.copy()
                conn_copy = len(CONN_TRACK)
            
            html = f"""
            <html>
            <head><title>Scapy Firewall Dashboard</title>
            <meta http-equiv="refresh" content="5">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .stats {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; }}
                .good {{ color: green; }}
                .bad {{ color: red; }}
            </style>
            </head>
            <body>
                <h1>Scapy Firewall Dashboard</h1>
                <div class="stats">
                    <h2>Statistics</h2>
                    <p>Packets Processed: <strong>{stats_copy['packets_processed']}</strong></p>
                    <p>Packets Allowed: <strong class="good">{stats_copy['packets_allowed']}</strong></p>
                    <p>Packets Dropped: <strong class="bad">{stats_copy['packets_dropped']}</strong></p>
                    <p>Active Connections: <strong>{conn_copy}</strong></p>
                </div>
            </body>
            </html>
            """
            
            self.wfile.write(html.encode())
        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            with LOCK:
                stats_copy = STATS.copy()
                stats_copy['connections'] = len(CONN_TRACK)
            
            self.wfile.write(json.dumps(stats_copy).encode())
        else:
            self.send_response(404)
            self.end_headers()

def start_web_interface(port):
    server = socketserver.ThreadingTCPServer(('localhost', port), FirewallHTTPHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    logger.info(f"Web interface running at http://localhost:{port}")
    return server

def update_blacklist():
    while APP_RUNNING:
        try:
            import requests
            response = requests.get(BLACKLIST_URL, timeout=10)
            if response.status_code == 200:
                ips = response.text.strip().split('\n')
                with LOCK:
                    for ip in ips:
                        ip = ip.strip()
                        if ip and not ip.startswith('#'):
                            BLOCKED_IPS.add(ip)
                logger.info(f"Updated blacklist with {len(ips)} entries")
        except Exception as e:
            logger.error(f"Error updating blacklist: {e}")
        
        time.sleep(3600)  # Update every hour

def cleanup():
    logger.info("Shutting down firewall...")
    global APP_RUNNING
    APP_RUNNING = False

def main():
    global APP_RUNNING
    
    parser = argparse.ArgumentParser(description='Enhanced Scapy Firewall')
    parser.add_argument('-i', '--interface', default='en0', help='Network interface to monitor')
    parser.add_argument('-r', '--rules', default='firewall_rules.txt', help='Firewall rules file')
    parser.add_argument('-l', '--log', default=LOG_FILE, help='Log file path')
    parser.add_argument('-w', '--web', action='store_true', help='Enable web interface')
    parser.add_argument('-p', '--port', type=int, default=WEB_PORT, help='Web interface port')
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This program requires root privileges to run. Please use sudo.")
        sys.exit(1)
    
    setup_logging(args.log)
    logger.info("Starting enhanced Scapy firewall")
    
    load_rules(args.rules)
    
    cleaner_thread = threading.Thread(target=clean_old_connections)
    cleaner_thread.daemon = True
    cleaner_thread.start()
    
    blacklist_thread = threading.Thread(target=update_blacklist)
    blacklist_thread.daemon = True
    blacklist_thread.start()
    
    server = None
    if args.web:
        server = start_web_interface(args.port)
    
    def signal_handler(sig, frame):
        cleanup()
        if server:
            server.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info(f"Monitoring interface {args.interface}")
    
    try:
        sniff(iface=args.interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        logger.error(f"Error: {e}")
        cleanup()

if __name__ == "__main__":
    main()