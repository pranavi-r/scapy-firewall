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
import ssl
import sqlite3
import smtplib
import hashlib
import base64
import email.message
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import socket
from collections import defaultdict, Counter
import signal
import random
import struct
import re
import requests
from functools import lru_cache
try:
    import cython
    USE_CYTHON = True
except ImportError:
    USE_CYTHON = False

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
l = logging.getLogger('fw')

b_ip = set()
b_pt = set()
a_ip = set()
c_bk = []
c_tk = {}
l_fl = "fw.log"
m_sz = 10485760
b_ul = "https://blocklist.example.com/list.txt"
s = {
    "p": 0,
    "d": 0,
    "a": 0,
    "u": time.time()
}
r_lm = defaultdict(Counter)
r_th = 100
r_wn = 60
lk = threading.Lock()
w_pt = 8443
app = True
u_db = "fw.db"
w_u = "admin"
w_p = "changeme"
t_dirs = {}
dns_bk = set()
smtp_h = "smtp.example.com"
smtp_p = 587
smtp_u = "alert@example.com"
smtp_pw = "password"
alert_to = "admin@example.com"
alert_from = "alert@example.com"
w_ip = ["127.0.0.1"]
smp_rt = 100
an_ts = {}
bpf_f = "ip"

def init_db():
    conn = sqlite3.connect(u_db)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS rules
                 (id INTEGER PRIMARY KEY, type TEXT, value TEXT, added TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY, timestamp TEXT, event TEXT, ip TEXT, port INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id TEXT PRIMARY KEY, username TEXT, expires INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS config
                 (key TEXT PRIMARY KEY, value TEXT)''')
    conn.commit()
    
    c.execute("SELECT * FROM users WHERE username=?", (w_u,))
    if not c.fetchone():
        salt = os.urandom(16).hex()
        h = hashlib.sha256((w_p + salt).encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                 (w_u, f"{salt}:{h}", "admin"))
        conn.commit()
    
    conn.close()

def log_db(event, ip=None, port=None):
    try:
        conn = sqlite3.connect(u_db)
        c = conn.cursor()
        c.execute("INSERT INTO logs (timestamp, event, ip, port) VALUES (?, ?, ?, ?)",
                 (datetime.datetime.now().isoformat(), event, ip, port))
        conn.commit()
        conn.close()
    except Exception as e:
        l.error(f"DB:{e}")

def load_r(rules_file):
    try:
        conn = sqlite3.connect(u_db)
        c = conn.cursor()
        c.execute("SELECT type, value FROM rules")
        db_rules = c.fetchall()
        conn.close()
        
        for rule_type, value in db_rules:
            apply_rule(rule_type, value)
        
        if os.path.exists(rules_file):
            with open(rules_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        continue
                    
                    rule_type, value = parts
                    apply_rule(rule_type, value)
                    
    except Exception as e:
        l.error(f"E:{e}")
        sys.exit(1)

def apply_rule(rule_type, value):
    rt = rule_type.lower()
    if rt == 'block-ip':
        b_ip.add(value)
    elif rt == 'block-port':
        b_pt.add(int(value))
    elif rt == 'allow-ip':
        a_ip.add(value)
    elif rt == 'block-net':
        c_bk.append(ipaddress.ip_network(value))
    elif rt == 'rate-limit':
        global r_th, r_wn
        parts = value.split(':')
        if len(parts) == 2:
            r_th = int(parts[0])
            r_wn = int(parts[1])
    elif rt == 'block-domain':
        dns_bk.add(value)

def setup_l(log_file):
    h = logging.FileHandler(log_file)
    h.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    l.addHandler(h)
    
    def rotate():
        while app:
            try:
                if os.path.exists(log_file) and os.path.getsize(log_file) > m_sz:
                    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                    bk = f"{log_file}.{ts}"
                    os.rename(log_file, bk)
                    l.handlers = [h for h in l.handlers if not isinstance(h, logging.FileHandler)]
                    fh = logging.FileHandler(log_file)
                    fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                    l.addHandler(fh)
            except Exception as e:
                pass
            time.sleep(60)
    
    t = threading.Thread(target=rotate)
    t.daemon = True
    t.start()

def is_b(ip):
    if ip in a_ip:
        return False
    
    if ip in b_ip:
        return True
    
    for net in c_bk:
        if ipaddress.ip_address(ip) in net:
            return True
    
    return False

def chk_r(ip):
    now = int(time.time())
    with lk:
        r_lm[ip][now] += 1
        
        total = sum(count for ts, count in r_lm[ip].items() if now - ts <= r_wn)
        return total > r_th

@lru_cache(maxsize=1024)
def is_domain_blocked(domain):
    for blocked in dns_bk:
        if domain == blocked or domain.endswith("." + blocked):
            return True
    return False

def extract_dns(pkt):
    if DNS in pkt and pkt[DNS].qr == 0:
        for i in range(pkt[DNS].qdcount):
            qname = pkt[DNS].qd[i].qname.decode('utf-8')
            if qname.endswith('.'):
                qname = qname[:-1]
            if is_domain_blocked(qname):
                return True
    return False

def deep_inspect(pkt):
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load.lower()
        patterns = [
            rb"(?i)eval\s*\(",
            rb"(?i)exec\s*\(",
            rb"(?i)system\s*\(",
            rb"(?i)<script>",
            rb"(?i)select.+from.+where",
            rb"(?i)union\s+select",
            rb"(?i)drop\s+table"
        ]
        for pattern in patterns:
            if re.search(pattern, payload):
                return True
    return False

def trk_c(pkt):
    if random.randint(1, smp_rt) != 1:
        return False
    
    if IP in pkt and (TCP in pkt or UDP in pkt):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "T"
            flags = pkt[TCP].flags
            
            conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-T"
            
            if flags & 0x02:
                c_tk[conn_id] = {"t": time.time(), "s": "S", "p": 1}
                return True
            
            if conn_id in c_tk:
                c_tk[conn_id]["p"] += 1
                c_tk[conn_id]["l"] = time.time()
                
                if flags & 0x01:
                    c_tk[conn_id]["s"] = "F"
                
                if flags & 0x04:
                    c_tk[conn_id]["s"] = "R"
                
                return True
            
            rev_conn_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-T"
            if rev_conn_id in c_tk:
                return True
        
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "U"
            
            conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-U"
            
            if conn_id not in c_tk:
                c_tk[conn_id] = {"t": time.time(), "s": "A", "p": 1}
            else:
                c_tk[conn_id]["p"] += 1
                c_tk[conn_id]["l"] = time.time()
            
            rev_conn_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-U"
            if rev_conn_id in c_tk:
                return True
    
    return False

def cln_old():
    while app:
        try:
            now = time.time()
            with lk:
                to_delete = []
                
                for conn_id, data in c_tk.items():
                    if data["s"] in ["F", "R"] and now - data.get("l", data["t"]) > 60:
                        to_delete.append(conn_id)
                    elif now - data.get("l", data["t"]) > 300:
                        to_delete.append(conn_id)
                
                for conn_id in to_delete:
                    del c_tk[conn_id]
                
                old_times = []
                for ip in r_lm:
                    for ts in list(r_lm[ip].keys()):
                        if now - ts > r_wn:
                            old_times.append((ip, ts))
                
                for ip, ts in old_times:
                    del r_lm[ip][ts]
                
                detect_anomalies()
        except Exception as e:
            pass
        
        time.sleep(10)

def detect_anomalies():
    global an_ts
    now = time.time()
    anomalies = []
    
    for ip, counters in r_lm.items():
        curr_rate = sum(count for ts, count in counters.items() if now - ts <= 10)
        
        if ip in an_ts:
            last_rate, last_time = an_ts[ip]
            if curr_rate > 0 and last_rate > 0:
                increase = curr_rate / last_rate
                if increase > 5:
                    anomalies.append((ip, curr_rate, increase))
        
        an_ts[ip] = (curr_rate, now)
    
    if anomalies and now - s.get("last_alert", 0) > 300:
        s["last_alert"] = now
        alert_text = "Anomalies:\n"
        for ip, rate, increase in anomalies[:5]:
            alert_text += f"{ip} - {rate}/s\n"
        send_alert("Traffic Anomalies", alert_text)

def send_alert(subj, msg):
    try:
        message = MIMEText(msg)
        message["Subject"] = subj
        message["From"] = alert_from
        message["To"] = alert_to
        
        with smtplib.SMTP(smtp_h, smtp_p) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_u, smtp_pw)
            server.send_message(message)
    except:
        pass

def pkt_cb(pkt):
    try:
        if random.randint(1, smp_rt) != 1:
            return pkt
            
        with lk:
            s["p"] += 1
        
        if IP not in pkt:
            return pkt
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if is_b(src_ip):
            with lk:
                s["d"] += 1
            log_db("block_ip", src_ip)
            return
        
        if extract_dns(pkt):
            with lk:
                s["d"] += 1
            log_db("block_dns", src_ip)
            return
        
        if deep_inspect(pkt):
            with lk:
                s["d"] += 1
            log_db("block_payload", src_ip)
            return
        
        if trk_c(pkt):
            pass
        elif chk_r(src_ip):
            with lk:
                s["d"] += 1
            log_db("rate_limit", src_ip)
            return
        
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "T"
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "U"
        else:
            with lk:
                s["a"] += 1
            return pkt
        
        if dst_port in b_pt:
            with lk:
                s["d"] += 1
            log_db("block_port", src_ip, dst_port)
            return
        
        with lk:
            s["a"] += 1
        
        return pkt
    except Exception as e:
        l.error(f"E:{e}")
        return pkt

class H(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
        
    def auth(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False
            
        try:
            auth_type, auth_data = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return False
                
            username, password = base64.b64decode(auth_data).decode().split(':', 1)
            
            conn = sqlite3.connect(u_db)
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username=?", (username,))
            result = c.fetchone()
            conn.close()
            
            if not result:
                return False
                
            stored_pw = result[0]
            salt, hash_val = stored_pw.split(':', 1)
            
            calc_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return calc_hash == hash_val
        except:
            return False
    
    def check_ip(self):
        client_ip = self.client_address[0]
        return client_ip in w_ip
    
    def send_auth_required(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Firewall Admin"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Auth")
    
    def do_GET(self):
        if not self.check_ip():
            self.send_response(403)
            self.end_headers()
            return
            
        if not self.auth():
            self.send_auth_required()
            return
            
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            with lk:
                st = s.copy()
                ct = len(c_tk)
            
            html = f"""
            <html><head><title>Fw</title>
            <meta http-equiv="refresh" content="5">
            <style>
                body{{font-family:Arial;margin:20px}}
                h1{{color:#333}}
                .s{{background-color:#f5f5f5;padding:10px;border-radius:5px}}
                .g{{color:green}}
                .b{{color:red}}
            </style>
            </head>
            <body>
                <h1>Fw</h1>
                <div class="s">
                    <h2>Stats</h2>
                    <p>P: <strong>{st['p']}</strong></p>
                    <p>A: <strong class="g">{st['a']}</strong></p>
                    <p>D: <strong class="b">{st['d']}</strong></p>
                    <p>C: <strong>{ct}</strong></p>
                </div>
                <div>
                    <h2>Rules</h2>
                    <form method="post" action="/rule">
                        <select name="type">
                            <option value="block-ip">Block IP</option>
                            <option value="block-port">Block Port</option>
                            <option value="allow-ip">Allow IP</option>
                            <option value="block-net">Block Net</option>
                            <option value="block-domain">Block Domain</option>
                        </select>
                        <input type="text" name="value" required>
                        <input type="submit" value="Add">
                    </form>
                </div>
            </body>
            </html>
            """
            
            self.wfile.write(html.encode())
            
        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            with lk:
                st = s.copy()
                st['c'] = len(c_tk)
            
            self.wfile.write(json.dumps(st).encode())
            
        elif self.path == '/logs':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            conn = sqlite3.connect(u_db)
            c = conn.cursor()
            c.execute("SELECT timestamp, event, ip, port FROM logs ORDER BY id DESC LIMIT 100")
            logs = c.fetchall()
            conn.close()
            
            html = """
            <html><head><title>Logs</title>
            <style>
                body{font-family:Arial;margin:20px}
                table{width:100%;border-collapse:collapse}
                th,td{text-align:left;padding:8px;border-bottom:1px solid #ddd}
                tr:nth-child(even){background-color:#f2f2f2}
            </style>
            </head>
            <body>
                <h1>Logs</h1>
                <table>
                    <tr><th>Time</th><th>Event</th><th>IP</th><th>Port</th></tr>
            """
            
            for timestamp, event, ip, port in logs:
                html += f"<tr><td>{timestamp}</td><td>{event}</td><td>{ip or ''}</td><td>{port or ''}</td></tr>"
            
            html += "</table></body></html>"
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if not self.check_ip():
            self.send_response(403)
            self.end_headers()
            return
            
        if not self.auth():
            self.send_auth_required()
            return
            
        if self.path == '/rule':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = {}
            for item in post_data.split('&'):
                key, value = item.split('=')
                params[key] = value
            
            rule_type = params.get('type')
            rule_value = params.get('value')
            
            if rule_type and rule_value:
                conn = sqlite3.connect(u_db)
                c = conn.cursor()
                c.execute("INSERT INTO rules (type, value, added) VALUES (?, ?, ?)", 
                         (rule_type, rule_value, datetime.datetime.now().isoformat()))
                conn.commit()
                conn.close()
                
                apply_rule(rule_type, rule_value)
            
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def start_w(port):
    handler_class = H
    server_class = socketserver.ThreadingTCPServer
    server_class.allow_reuse_address = True
    httpd = server_class(('', port), handler_class)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    except:
        k = os.path.join(os.path.dirname(os.path.abspath(__file__)), "key.pem")
        c = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert.pem")
        if not (os.path.exists(k) and os.path.exists(c)):
            gen_cert(k, c)
        context.load_cert_chain(certfile=c, keyfile=k)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    l.info(f"W:{port}")
    return httpd

def gen_cert(key_file, cert_file):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import datetime
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Firewall"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def upd_bl():
    while app:
        try:
            r = requests.get(b_ul, timeout=10)
            if r.status_code == 200:
                ips = r.text.strip().split('\n')
                with lk:
                    for ip in ips:
                        ip = ip.strip()
                        if ip and not ip.startswith('#'):
                            b_ip.add(ip)
        except:
            pass
        
        time.sleep(3600)

def end():
    l.info("End")
    global app
    app = False

def scheduled_report():
    while app:
        now = datetime.datetime.now()
        if now.hour == 0 and now.minute == 0:
            with lk:
                st = s.copy()
                ct = len(c_tk)
            
            conn = sqlite3.connect(u_db)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM logs WHERE timestamp >= datetime('now', '-1 day')")
            log_count = c.fetchone()[0]
            
            c.execute("SELECT event, COUNT(*) FROM logs WHERE timestamp >= datetime('now', '-1 day') GROUP BY event")
            events = c.fetchall()
            
            c.execute("SELECT ip, COUNT(*) FROM logs WHERE timestamp >= datetime('now', '-1 day') GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 10")
            top_ips = c.fetchall()
            conn.close()
            
            report = f"Daily Report\n\n"
            report += f"Packets: {st['p']}\n"
            report += f"Allowed: {st['a']}\n"
            report += f"Dropped: {st['d']}\n"
            report += f"Connections: {ct}\n\n"
            report += f"Logs: {log_count}\n\n"
            
            report += "Events:\n"
            for event, count in events:
                report += f"{event}: {count}\n"
            
            report += "\nTop IPs:\n"
            for ip, count in top_ips:
                if ip:
                    report += f"{ip}: {count}\n"
            
            send_alert("Fw Report", report)
        
        time.sleep(60)

def optimize():
    if USE_CYTHON:
        try:
            from scapy_functions import fast_packet_check
            global pkt_cb
            pkt_cb = fast_packet_check
            l.info("Opt")
        except:
            pass

def main():
    global app, bpf_f
    
    p = argparse.ArgumentParser(description='Fw')
    p.add_argument('-i', '--interface', default='en0')
    p.add_argument('-r', '--rules', default='fw.txt')
    p.add_argument('-l', '--log', default=l_fl)
    p.add_argument('-w', '--web', action='store_true')
    p.add_argument('-p', '--port', type=int, default=w_pt)
    p.add_argument('-f', '--filter', default=bpf_f)
    args = p.parse_args()
    
    if os.geteuid() != 0:
        print("Root")
        sys.exit(1)
    
    init_db()
    setup_l(args.log)
    l.info("Start")
    
    load_r(args.rules)
    
    optimize()
    
    cl_thread = threading.Thread(target=cln_old)
    cl_thread.daemon = True
    cl_thread.start()
    
    bl_thread = threading.Thread(target=upd_bl)
    bl_thread.daemon = True
    bl_thread.start()
    
    report_thread = threading.Thread(target=scheduled_report)
    report_thread.daemon = True
    report_thread.start()
    
    srv = None
    if args.web:
        srv = start_w(args.port)
    
    def sig_handler(sig, frame):
        end()
        if srv:
            srv.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    
    l.info(f"Mon:{args.interface}")
    bpf_f = args.filter
    
    try:
        sniff(iface=args.interface, filter=bpf_f, prn=pkt_cb, store=0)
    except KeyboardInterrupt:
        end()
    except Exception as e:
        l.error(f"E:{e}")
        end()

if __name__ == "__main__":
    main()