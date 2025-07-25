import socket
from concurrent.futures import ThreadPoolExecutor

def get_service_name(port):
    """Get well-known service name for a port"""
    services = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP-SERVER",
        68: "DHCP-CLIENT",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        162: "SNMPTRAP",
        179: "BGP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "SYSLOG",
        587: "SMTP-SUBMISSION",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MS-SQL",
        1521: "ORACLE-DB",
        2049: "NFS",
        3306: "MYSQL",
        3389: "RDP",
        5432: "POSTGRESQL",
        5900: "VNC",
        6379: "REDIS",
        8080: "HTTP-ALT",
        8443: "HTTPS-ALT",
        27017: "MONGODB",
    }
    return services.get(port, "UNKNOWN")

def scan_port(host, port, timeout=1):
    """Scan a single port"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = get_service_name(port)
                return port, service, "OPEN"
            else:
                return port, get_service_name(port), "CLOSED"
    except Exception as e:
        return port, get_service_name(port), f"ERROR: {str(e)}"

def port_scanner(host, ports=None, max_threads=100):
    """Scan multiple ports on a host"""
    if ports is None:
        # Default to common ports
        ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 
            443, 445, 587, 993, 995, 1433, 1521,
            3306, 3389, 5432, 5900, 8080, 8443
        ]
    
    print(f"Scanning {host}...\n")
    print("{:<8} {:<15} {:<10}".format("PORT", "SERVICE", "STATUS"))
    print("-" * 35)
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port, host, port) for port in ports]
        for future in futures:
            port, service, status = future.result()
            print("{:<8} {:<15} {:<10}".format(port, service, status))

if __name__ == "__main__":
    target = input("Enter target host (e.g., example.com or 192.168.1.1): ")
    custom_ports = input("Enter ports to scan (comma separated, leave empty for default): ")
    
    if custom_ports:
        ports = [int(p.strip()) for p in custom_ports.split(",")]
        port_scanner(target, ports)
    else:
        port_scanner(target)


