# Simple Firewall Project (Python)

![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg)
![Scapy](https://img.shields.io/badge/Scapy-Library-yellowgreen.svg)
![Tkinter](https://img.shields.io/badge/Tkinter-GUI-lightblue.svg)
![Firewall](https://img.shields.io/badge/Firewall-Simulation-red.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-important.svg)

---

## Description
This project is a basic firewall built in Python that monitors incoming and outgoing network packets on a Windows machine. It captures packets in real-time using the Scapy library, checks them against a predefined list of blocked IP addresses and ports, and either allows or blocks the traffic accordingly. Blocked activities are logged into a file for review. It provides a lightweight simulation of how a real firewall operates — making it ideal for learning concepts in network security, packet filtering, and traffic monitoring.

## Features
- Real-time packet monitoring.
- Display of both IP addresses and their resolved domain names.
- Blocking of specific IP addresses and ports based on predefined rules.
- Logging of all blocked activities to a file (`firewall_log.txt`).
- Simple and user-friendly GUI built with Tkinter.
- No administrative (sudo) access required — compatible with standard Windows setups.

## Development Journey
The project evolved through multiple phases:
- Implemented a basic working firewall.
- Enhanced functionality by resolving and displaying domain names along with IP addresses.
- Added a graphical user interface (GUI) for easier interaction and control.

## Challenges & Resolutions
Being relatively new to cybersecurity, I encountered several challenges during the development of this project. Here’s how I addressed them:

| S.No | Issue | Resolution |
|------|-------|------------|
| 1 | `sudo` is not available on Windows | Modified the code to work without requiring `sudo` access. |
| 2 | No `libcap` provider available | Adjusted packet capturing by focusing on Layer 3 (IP/TCP/UDP) instead of Layer 2 (Ethernet frames). |
| 3 | No `libcap` provider available | Installed the `Npcap` packet capture library to ensure proper packet sniffing on Windows. |

**Note:**  
One significant limitation of this project is its dependency on the Windows operating system. Native packet sniffing and blocking behavior may differ on Linux or macOS environments. Future versions may address cross-platform compatibility.

## Output
![sf_op](https://github.com/user-attachments/assets/6971f086-4b05-4782-8f02-a1b795379a29)

## Future Improvements
- Dynamic blocking and unblocking of IPs/ports through the GUI.
- Protocol filtering (TCP, UDP, ICMP) options.
- Real-time traffic charts and statistics.
- Cross-platform support (Linux and macOS compatibility).
- Alert system for suspicious traffic patterns.

## Note
This project is designed for **educational purposes** only and should not be used as a replacement for professional-grade firewall solutions.  
Stay tuned for more feature updates!
