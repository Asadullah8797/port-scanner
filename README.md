# **Advanced Port Scanner 

## **📌 Table of Contents**  
1. [Introduction](#-introduction)  
2. [Features](#-features)  
3. [Installation](#-installation)  
4. [Usage](#-usage)  
   - [Basic Scan](#1-basic-scan-default-ports)  
   - [Custom Port Scan](#2-custom-port-scan)  
   - [Fast Scan (More Threads)](#3-fast-scan-increase-threads)  
   - [Save Results to JSON](#4-save-results-to-json)  
   - [Scan with Custom Timeout](#5-scan-with-custom-timeout)  
5. [Examples](#-examples)  
6. [Troubleshooting](#-troubleshooting)  
7. [Legal & Ethical Use](#-legal--ethical-use)  

---

## **🔍 Introduction**  
This **Advanced Port Scanner** is a Python-based tool designed for:  
✅ **Network security testing**  
✅ **Service discovery**  
✅ **Open port detection**  
✅ **Banner grabbing**  

It supports **multi-threading**, **custom port ranges**, and **JSON reporting** for professional use.  

---

## **✨ Features**  
✔ **Fast & Efficient** – Uses multi-threading for quick scans  
✔ **Service Detection** – Identifies well-known services (HTTP, SSH, FTP, etc.)  
✔ **Banner Grabbing** – Retrieves service banners (e.g., web server info)  
✔ **Custom Port Ranges** – Scan single ports or ranges (e.g., `80,443` or `20-100`)  
✔ **JSON Reports** – Save results for further analysis  
✔ **Adjustable Timeout** – Control scan speed and reliability  

---

## **📥 Installation**  
### **Prerequisites**  
- Python 3.6+  
- `pip` (Python package manager)  

### **Steps**  
1. **Clone the repository (or download the script):**  
   ```bash
   git clone https://github.com/yourusername/advanced-port-scanner.git
   cd advanced-port-scanner
   ```
2. **Run the script directly:**  
   ```bash
   python advanced_port_scanner.py --help
   ```
   *(No additional dependencies required!)*  

---

## **🚀 Usage**  

### **1️⃣ Basic Scan (Default Ports)**  
Scans **1-1024** (common ports).  
```bash
python advanced_port_scanner.py example.com
```
**Output:**  
```
[+] Starting scan on example.com at 2024-05-20 10:00:00  
[+] Scanning 1024 ports with 100 threads  

[+] 22/tcp    OPEN       SSH            SSH-2.0-OpenSSH_8.2  
[+] 80/tcp    OPEN       HTTP           HTTP/1.1 200 OK...  
[-] 443/tcp   CLOSED     HTTPS  
[!] Scan completed in 12.5 seconds  
```

---

### **2️⃣ Custom Port Scan**  
Scan specific ports (comma-separated or ranges).  
```bash
python advanced_port_scanner.py 192.168.1.1 -p 22,80,443,8000-9000
```

---

### **3️⃣ Fast Scan (Increase Threads)**  
Use **200 threads** for faster scanning.  
```bash
python advanced_port_scanner.py example.com -t 200
```

---

### **4️⃣ Save Results to JSON**  
Export scan results for later analysis.  
```bash
python advanced_port_scanner.py example.com -o scan_results.json
```

---

### **5️⃣ Scan with Custom Timeout**  
Increase timeout for slow networks (default: `1.5s`).  
```bash
python advanced_port_scanner.py example.com --timeout 3
```

---

## **📋 Examples**  

| Command | Description |
|---------|-------------|
| `python advanced_port_scanner.py scanme.nmap.org` | Scan default ports (1-1024) |
| `python advanced_port_scanner.py 10.0.0.1 -p 20-80,443,3306` | Scan custom ports |
| `python advanced_port_scanner.py example.com -t 200 -o output.json` | Fast scan + JSON export |
| `sudo python advanced_port_scanner.py localhost -p 1-1024` | Scan privileged ports (Linux) |

---

## **🛠 Troubleshooting**  

| Issue | Solution |
|-------|----------|
| **"Invalid target" error** | Check if the domain/IP is correct and reachable. |
| **Slow scans** | Increase threads (`-t 200`) or timeout (`--timeout 3`). |
| **No open ports found** | Try scanning more ports (`-p 1-65535`). |
| **Permission denied (Linux)** | Use `sudo` for ports below 1024. |

---

## **⚖ Legal & Ethical Use**  
⚠ **This tool is for authorized security testing only.**  
🚫 **Do not scan networks without permission.**  
🔒 **Respect privacy and legal boundaries.**  

---

## **📜 License**  
MIT License - Free for personal and professional use.  

---

**🚀 Happy Scanning!**  
*For questions, open an issue on [GitHub](https://github.com/yourusername/advanced-port-scanner).*
