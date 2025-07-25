import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress
import json
import os
from typing import List, Dict, Tuple, Optional

class AdvancedPortScanner:
    """Advanced port scanner with service detection, banner grabbing, and reporting."""
    
    WELL_KNOWN_PORTS = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
        25: "SMTP", 53: "DNS", 67: "DHCP-SERVER", 68: "DHCP-CLIENT",
        69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
        143: "IMAP", 161: "SNMP", 162: "SNMPTRAP", 179: "BGP",
        389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
        514: "SYSLOG", 587: "SMTP-SUBMISSION", 636: "LDAPS",
        993: "IMAPS", 995: "POP3S", 1433: "MS-SQL", 1521: "ORACLE-DB",
        2049: "NFS", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL",
        5900: "VNC", 6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
        27017: "MONGODB", 11211: "MEMCACHED"
    }

    def __init__(self, timeout: float = 1.5, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = []
        self.scan_stats = {
            'total_ports': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'filtered_ports': 0,
            'start_time': None,
            'end_time': None
        }

    def get_service_name(self, port: int) -> str:
        """Get well-known service name for a port."""
        return self.WELL_KNOWN_PORTS.get(port, "UNKNOWN")

    def grab_banner(self, host: str, port: int) -> str:
        """Attempt to grab banner from open port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                s.send(b"GET / HTTP/1.1\r\n\r\n")
                return s.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            return "No banner received"

    def scan_port(self, host: str, port: int) -> Tuple[int, str, str, str]:
        """Scan a single port with enhanced detection."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((host, port))
                
                if result == 0:
                    service = self.get_service_name(port)
                    banner = self.grab_banner(host, port) if port in [80, 443, 21, 22, 25, 110] else ""
                    return port, service, "OPEN", banner
                else:
                    return port, self.get_service_name(port), "CLOSED", ""
        except socket.timeout:
            return port, self.get_service_name(port), "FILTERED", ""
        except Exception as e:
            return port, self.get_service_name(port), f"ERROR: {str(e)}", ""

    def validate_target(self, target: str) -> bool:
        """Validate target host or IP address."""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                return False

    def scan_ports(self, host: str, ports: List[int]) -> None:
        """Scan multiple ports on a host with progress tracking."""
        if not self.validate_target(host):
            print(f"[-] Invalid target: {host}")
            return

        self.scan_stats['start_time'] = datetime.now()
        self.scan_stats['total_ports'] = len(ports)
        
        print(f"\n[+] Starting scan on {host} at {self.scan_stats['start_time']}")
        print(f"[+] Scanning {len(ports)} ports with {self.max_threads} threads\n")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in ports}
            
            for future in as_completed(futures):
                port, service, status, banner = future.result()
                self.results.append({
                    'port': port,
                    'service': service,
                    'status': status,
                    'banner': banner
                })
                
                # Update stats
                if "OPEN" in status:
                    self.scan_stats['open_ports'] += 1
                elif "CLOSED" in status:
                    self.scan_stats['closed_ports'] += 1
                else:
                    self.scan_stats['filtered_ports'] += 1
                
                # Print live results
                if "OPEN" in status:
                    print(f"[+] {port:5}/tcp {status:8} {service:15} {banner[:50]}...")
                elif "ERROR" not in status:
                    print(f"[-] {port:5}/tcp {status:8} {service:15}")

        self.scan_stats['end_time'] = datetime.now()
        self.print_summary()

    def print_summary(self) -> None:
        """Print scan summary statistics."""
        duration = self.scan_stats['end_time'] - self.scan_stats['start_time']
        print("\n[+] Scan Summary:")
        print(f"    Target scanned: {args.target}")
        print(f"    Scan duration: {duration}")
        print(f"    Total ports scanned: {self.scan_stats['total_ports']}")
        print(f"    Open ports: {self.scan_stats['open_ports']}")
        print(f"    Closed ports: {self.scan_stats['closed_ports']}")
        print(f"    Filtered ports: {self.scan_stats['filtered_ports']}")

    def generate_report(self, format: str = "console", filename: Optional[str] = None) -> None:
        """Generate scan report in various formats."""
        if format == "json":
            report = {
                'target': args.target,
                'scan_time': self.scan_stats['start_time'].isoformat(),
                'duration': str(self.scan_stats['end_time'] - self.scan_stats['start_time']),
                'results': self.results,
                'statistics': {
                    'total_ports': self.scan_stats['total_ports'],
                    'open_ports': self.scan_stats['open_ports'],
                    'closed_ports': self.scan_stats['closed_ports'],
                    'filtered_ports': self.scan_stats['filtered_ports']
                }
            }
            
            if not filename:
                filename = f"portscan_{args.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"\n[+] JSON report saved to {filename}")
        
        elif format == "console":
            print("\n[+] Detailed Results:")
            print("{:<8} {:<15} {:<10} {:<50}".format("PORT", "SERVICE", "STATUS", "BANNER"))
            print("-" * 85)
            for result in sorted(self.results, key=lambda x: x['port']):
                if result['status'] == "OPEN":
                    print("{:<8} {:<15} {:<10} {:<50}".format(
                        result['port'],
                        result['service'],
                        result['status'],
                        result['banner'][:50] + "..." if result['banner'] else ""
                    ))

def parse_ports(port_input: str) -> List[int]:
    """Parse port input string into list of integers."""
    ports = []
    for part in port_input.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(list(set(ports)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with Service Detection")
    parser.add_argument("target", help="Target host (IP or domain)")
    parser.add_argument("-p", "--ports", default="1-1024", 
                       help="Ports to scan (e.g., '80,443' or '20-80')")
    parser.add_argument("-t", "--threads", type=int, default=100,
                       help="Maximum number of threads")
    parser.add_argument("-o", "--output", 
                       help="Output file for JSON report")
    parser.add_argument("--timeout", type=float, default=1.5,
                       help="Connection timeout in seconds")
    
    args = parser.parse_args()
    
    scanner = AdvancedPortScanner(timeout=args.timeout, max_threads=args.threads)
    ports_to_scan = parse_ports(args.ports)
    
    try:
        scanner.scan_ports(args.target, ports_to_scan)
        
        if args.output:
            scanner.generate_report(format="json", filename=args.output)
        else:
            scanner.generate_report(format="console")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.print_summary()
    except Exception as e:
        print(f"\n[!] Error occurred: {str(e)}")
