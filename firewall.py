from scapy.all import sniff, IP, TCP, UDP
import socket
import time

# Blocked IP addresses and ports
blocked_ips = ["192.168.189.154", "192.168.1.10", "10.0.0.5"]
blocked_ports = [80, 443]

# Logging blocked packets to a file

def log_blocked(message):
    with open("firewall_log.txt", "a") as logfile:
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
        logfile.write(f"{timestamp} {message}\n")

# Handle each packet

def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # adding domain name
            src_domain = resolve_domain(src_ip)
            dst_domain = resolve_domain(dst_ip)
            print(f"Source: {src_ip} ({src_domain}) -> Destination: {dst_ip} ({dst_domain})")

            # checking for blocked ip
            if src_ip in blocked_ips or dst_ip in blocked_ips:
                block_message = f"[BLOCKED IP] {src_ip} --> {dst_ip}"
                print(block_message)
            
            # checking for blocked ports
            elif packet.haslayer(TCP) or packet.haslayer(UDP):
                if packet.haslayer(TCP):
                    layer = packet[TCP]
                else:
                    layer = packet[UDP]
                
                if layer.dport in blocked_ports:
                    block_message = f"[BLOCKED PORT] {src_ip} --> {dst_ip} on port {layer.dport}"
                    print(block_message)
                    log_blocked(block_message)
                else:
                    print(f"[ALLOWED] {src_ip} --> {dst_ip}")
            else:
                print(f"[ALLOWED] {src_ip} --> {dst_ip}")
    except Exception as e:
        print(f"Error processing packet: {e}")

# Start sniffing packet
def start_firewall():
    print("Simple firewall is running....")
    sniff(prn=packet_callback, store=0, filter="ip")

def resolve_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain = "Unknown"
    return domain

if __name__ == "__main__":
    start_firewall()