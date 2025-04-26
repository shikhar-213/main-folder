from scapy.all import sniff, IP, TCP, UDP
import socket
import time
import tkinter as tk
import threading


# Blocked IP addresses and ports

blocked_ips = ["192.168.1.10", "10.0.0.5"]  #sample ip
blocked_ports = [80, 443]   #sample port

# Logging blocked packets to a file

def log_blocked(message):
    with open("firewall_log.txt", "a") as logfile:
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
        logfile.write(f"{timestamp} {message}\n")

# GUI FIREWALL APP
class FirewallApp:
    def __init__(self, master):
        self.master = master
        master.title("Simple Firewall")

        # start button
        self.start_button = tk.Button(master, text="Start Firewall", command=self.start_firewall)
        self.start_button.pack(pady=5)

        # stop button
        self.stop_button = tk.Button(master, text="Stop Firewall", command=self.stop_firewall)
        self.stop_button.pack(pady=5)

        # log area
        self.log = tk.Text(master, height=25, width=100)
        self.log.pack(pady=5)

        self.running = False
    
    def log_packets(self, text):
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
    
    # start sniffing packets
    def start_firewall(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_firewall(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, filter="ip", stop_filter=lambda x: not self.running)

    # Handle each packet
    def packet_callback(self, packet):
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                # adding domain name
                src_domain = resolve_domain(src_ip)
                dst_domain = resolve_domain(dst_ip)

                log_entry = f"Source: {src_ip} ({src_domain}) -> Destination: {dst_ip} ({dst_domain}"

                # checking for blocked ip
                if src_ip in blocked_ips or dst_ip in blocked_ips:
                    block_message = f"[BLOCKED IP] {src_ip} --> {dst_ip}"
                    self.log_packets(block_message)
                
                # checking for blocked ports
                elif packet.haslayer(TCP) or packet.haslayer(UDP):
                    if packet.haslayer(TCP):
                        layer = packet[TCP]
                    else:
                        layer = packet[UDP]
                    
                    if layer.dport in blocked_ports:
                        block_message = f"[BLOCKED PORT] {src_ip} --> {dst_ip} on port {layer.dport}"
                        self.log_packets(block_message)
                        log_blocked(block_message)
                    else:
                        self.log_packets(f"[ALLOWED] {src_ip} --> {dst_ip}")
                else:
                    self.log_packets(f"[ALLOWED] {src_ip} --> {dst_ip}")
                # always show source-destination in the log
                self.log_packets(log_entry)

        except Exception as e:
            self.log_packets(f"Error processing packet: {e}")

# adding domain name as well along with ip
def resolve_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain = "Unknown"
    return domain

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()