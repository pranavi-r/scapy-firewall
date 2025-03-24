
# Scapy Firewall

"""
 Requirements

- Python 3.x
- Scapy library
- Additional Python packages: requests, cryptography, sqlite3
- Root/administrator privileges

 Installation

1. Clone this repository:

git clone https://github.com/your-username/scapy-firewall.git
cd scapy-firewall


2. Install required dependencies:

pip3 install scapy requests cryptography


 Usage

 Basic Execution

Run the firewall with:

sudo python3 scapy_firewall.py --interface en0


Replace en0 with your network interface name.

 Firewall Rules

Create a text file with rules in the following format:

block-ip 192.168.1.100
block-port 22
allow-ip 192.168.1.5
block-net 10.0.0.0/8
block-domain example.com
rate-limit 100:60


 Web Interface

The firewall comes with a web interface for monitoring and management:

1. Enable it with the --web flag
2. Access it at https://localhost:8443
3. Default login: admin/changeme

 Security Considerations

- Change the default web interface password immediately
- This firewall requires root privileges - use with caution
- Thoroughly test rules before applying them to production environments

 Testing

Test the firewall with:

1. Generate test traffic:

ping google.com
curl example.com


2. Monitor firewall logs to see traffic processing
3. Check the web interface for statistics
"""