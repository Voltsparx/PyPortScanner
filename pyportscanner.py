import socket
import threading
import argparse
import time
from datetime import datetime
import sys
import ssl
import re

class Color:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class PyPortScanner:
    """
    ╔══════════════════════════════════════════════════════════════╗
    ║                   PyPortScanner by Voltsparx                 ║
    ║                 Contact: voltsparx@gmail.com                 ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    
    # Common protocol ports and their detection methods
    PROTOCOL_PORTS = {
        # Web protocols
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT',
        
        # File transfer
        21: 'FTP',
        22: 'SSH',
        23: 'TELNET',
        
        # Email
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        465: 'SMTPS',
        587: 'SMTP-SUB',
        993: 'IMAPS',
        995: 'POP3S',
        
        # Database
        1433: 'MSSQL',
        1521: 'ORACLE',
        3306: 'MYSQL',
        5432: 'POSTGRES',
        
        # Remote access
        3389: 'RDP',
        5900: 'VNC',
        
        # DNS
        53: 'DNS',
        
        # DHCP
        67: 'DHCP-SERVER',
        68: 'DHCP-CLIENT',
        
        # Network services
        135: 'MSRPC',
        139: 'NETBIOS-SSN',
        445: 'SMB',
        
        # Gaming
        25565: 'MINECRAFT',
        27015: 'STEAM',
        
        # VPN
        1723: 'PPTP',
        1194: 'OPENVPN',
        
        # Other common services
        161: 'SNMP',
        162: 'SNMP-TRAP',
        389: 'LDAP',
        636: 'LDAPS',
    }
    
    # Color mapping for different protocols
    PROTOCOL_COLORS = {
        'HTTP': Color.GREEN,
        'HTTPS': Color.GREEN + Color.BOLD,
        'FTP': Color.YELLOW,
        'SSH': Color.MAGENTA,
        'SMTP': Color.CYAN,
        'DNS': Color.BLUE,
        'RDP': Color.RED,
        'VNC': Color.RED,
        'MYSQL': Color.MAGENTA,
        'POSTGRES': Color.MAGENTA,
        'UNKNOWN': Color.WHITE
    }
    
    def __init__(self, target, timeout=2.0, max_threads=100):
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.protocol_details = {}
        self.lock = threading.Lock()
        self.scanned_ports = 0
        self.total_ports = 0
        
    def print_banner(self):
        """Display colorful banner"""
        print(f"{Color.CYAN}{'═' * 70}{Color.END}")
        print(f"{Color.BOLD} {Color.MAGENTA}____        ____            _   ____                         {Color.END}")
        print(f"{Color.BOLD}{Color.MAGENTA}|  _ \ _   _|  _ \ ___  _ __| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __{Color.END}")
        print(f"{Color.BOLD}{Color.MAGENTA}| |_) | | | | |_) / _ \| '__| __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|{Color.END}")
        print(f"{Color.BOLD}{Color.MAGENTA}|  __/| |_| |  __/ (_) | |  | |_ ___) | (_| (_| | | | | | | |  __/ |{Color.END}")
        print(f"{Color.BOLD}{Color.MAGENTA}|_|    \__, |_|   \___/|_|   \__|____/ \___\__,_|_| |_|_| |_|\___|_| {Color.END}")
        print(f"{Color.BOLD}{Color.MAGENTA}       |___/                                                           {Color.END}")
        print(f"{Color.CYAN}{'═' * 70}{Color.END}")
        print(f"{Color.YELLOW}    Advanced Protocol Port Scanner{Color.END}")
        print(f"{Color.WHITE}    Author: {Color.GREEN}Voltsparx{Color.END}")
        print(f"{Color.WHITE}    Contact: {Color.CYAN}voltsparx@gmail.com{Color.END}")
        print(f"{Color.CYAN}{'═' * 70}{Color.END}")
        print()
        
    def resolve_target(self):
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"{Color.BLUE}[INFO]{Color.END} Resolved {Color.CYAN}{self.target}{Color.END} to {Color.GREEN}{ip}{Color.END}")
            return ip
        except socket.gaierror:
            print(f"{Color.RED}[ERROR]{Color.END} Could not resolve {Color.CYAN}{self.target}{Color.END}")
            sys.exit(1)
    
    def get_protocol_name(self, port):
        """Get protocol name for port"""
        return self.PROTOCOL_PORTS.get(port, "UNKNOWN")
    
    def get_protocol_color(self, protocol):
        """Get color for protocol type"""
        for key, color in self.PROTOCOL_COLORS.items():
            if key in protocol:
                return color
        return Color.WHITE
    
    def detect_http_protocol(self, port):
        """Detect HTTP/HTTPS and get server info"""
        try:
            if port == 443 or port == 8443:
                # HTTPS detection
                context = ssl.create_default_context()
                with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        ssock.send(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % self.target.encode())
                        response = ssock.recv(1024).decode()
                        return self._parse_http_response(response, "HTTPS")
            else:
                # HTTP detection
                with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % self.target.encode())
                    response = sock.recv(1024).decode()
                    return self._parse_http_response(response, "HTTP")
        except:
            return "HTTP/HTTPS (No banner)"
    
    def _parse_http_response(self, response, protocol):
        """Parse HTTP response for server information"""
        server_info = protocol
        lines = response.split('\n')
        for line in lines:
            if line.lower().startswith('server:'):
                server_info = f"{protocol} - {line.strip()}"
                break
            elif 'http' in line.lower() and '200' in line:
                server_info = f"{protocol} - Active"
                break
        return server_info
    
    def detect_ftp_banner(self, port):
        """Detect FTP banner"""
        try:
            with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                banner = sock.recv(1024).decode().strip()
                return f"FTP - {banner[:100]}"
        except:
            return "FTP - Active"
    
    def detect_ssh_banner(self, port):
        """Detect SSH banner"""
        try:
            with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                banner = sock.recv(1024).decode().strip()
                return f"SSH - {banner[:100]}"
        except:
            return "SSH - Active"
    
    def detect_smtp_banner(self, port):
        """Detect SMTP banner"""
        try:
            with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                banner = sock.recv(1024).decode().strip()
                return f"SMTP - {banner[:100]}"
        except:
            return "SMTP - Active"
    
    def detect_generic_banner(self, port, protocol):
        """Generic banner grabbing"""
        try:
            with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                try:
                    banner = sock.recv(1024).decode().strip()
                    if banner:
                        return f"{protocol} - {banner[:100]}"
                except:
                    pass
                return f"{protocol} - Active"
        except:
            return f"{protocol} - Active"
    
    def get_protocol_details(self, port):
        """Get detailed protocol information"""
        protocol = self.get_protocol_name(port)
        
        if protocol in ['HTTP', 'HTTPS', 'HTTP-ALT', 'HTTPS-ALT']:
            return self.detect_http_protocol(port)
        elif protocol == 'FTP':
            return self.detect_ftp_banner(port)
        elif protocol == 'SSH':
            return self.detect_ssh_banner(port)
        elif protocol in ['SMTP', 'SMTPS', 'SMTP-SUB']:
            return self.detect_smtp_banner(port)
        elif protocol != 'UNKNOWN':
            return self.detect_generic_banner(port, protocol)
        else:
            # Try to detect unknown protocols
            try:
                with socket.create_connection((self.target_ip, port), timeout=1.0) as sock:
                    sock.send(b'\n')
                    banner = sock.recv(1024).decode().strip()
                    if banner:
                        return f"UNKNOWN - Banner: {banner[:100]}"
            except:
                pass
            return "UNKNOWN - No banner"
    
    def scan_port(self, port, semaphore):
        """Scan a single port with protocol detection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                
                with self.lock:
                    self.scanned_ports += 1
                    if result == 0:
                        protocol_info = self.get_protocol_details(port)
                        self.open_ports.append(port)
                        self.protocol_details[port] = protocol_info
                        
                        # Display progress and results
                        if self.scanned_ports % 20 == 0:
                            progress = (self.scanned_ports / self.total_ports) * 100
                            print(f"{Color.BLUE}[PROGRESS]{Color.END} {progress:.1f}% ({self.scanned_ports}/{self.total_ports} ports)")
                        
                        # Colorful output for open ports
                        protocol_color = self.get_protocol_color(protocol_info)
                        print(f"{Color.GREEN}✅ [OPEN]{Color.END} Port {Color.YELLOW}{port:5}{Color.END} - {protocol_color}{protocol_info}{Color.END}")
                        
        except Exception as e:
            pass
        finally:
            semaphore.release()
    
    def scan_range(self, start_port=1, end_port=1024):
        """Scan a range of ports"""
        self.print_banner()
        self.target_ip = self.resolve_target()
        self.total_ports = end_port - start_port + 1
        
        print(f"{Color.BLUE}[TARGET]{Color.END}    {Color.CYAN}{self.target_ip}{Color.END} ({self.target})")
        print(f"{Color.BLUE}[PORTS]{Color.END}     {Color.YELLOW}{start_port}-{end_port}{Color.END}")
        print(f"{Color.BLUE}[THREADS]{Color.END}   {Color.MAGENTA}{self.max_threads}{Color.END}")
        print(f"{Color.BLUE}[TIMEOUT]{Color.END}   {Color.CYAN}{self.timeout}s{Color.END}")
        print(f"{Color.BLUE}[START]{Color.END}     {Color.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.END}")
        print(f"{Color.CYAN}{'─' * 70}{Color.END}")
        print(f"{Color.BOLD}{Color.GREEN}🚀 Scanning ports and detecting protocols...{Color.END}")
        print()
        
        start_time = time.time()
        
        # Create thread pool with semaphore
        threads = []
        semaphore = threading.Semaphore(self.max_threads)
        
        for port in range(start_port, end_port + 1):
            semaphore.acquire()
            thread = threading.Thread(target=self.scan_port, args=(port, semaphore))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        self._print_results(scan_duration)
    
    def _print_results(self, duration):
        """Print detailed scan results with colors"""
        print()
        print(f"{Color.CYAN}{'═' * 70}{Color.END}")
        print(f"{Color.BOLD}{Color.MAGENTA}           SCAN RESULTS SUMMARY{Color.END}")
        print(f"{Color.CYAN}{'═' * 70}{Color.END}")
        
        print(f"{Color.BLUE}⏱️  Duration:{Color.END}    {Color.YELLOW}{duration:.2f} seconds{Color.END}")
        print(f"{Color.BLUE}📊 Ports Scanned:{Color.END} {Color.CYAN}{self.scanned_ports}{Color.END}")
        print(f"{Color.BLUE}✅ Open Ports:{Color.END}    {Color.GREEN if self.open_ports else Color.RED}{len(self.open_ports)}{Color.END}")
        
        if self.open_ports:
            print(f"\n{Color.BOLD}{Color.GREEN}🎯 OPEN PORTS DETECTED:{Color.END}")
            print(f"{Color.CYAN}{'─' * 70}{Color.END}")
            
            for port in sorted(self.open_ports):
                protocol_info = self.protocol_details.get(port, "UNKNOWN")
                protocol_color = self.get_protocol_color(protocol_info)
                print(f"   Port {Color.YELLOW}{port:5}{Color.END} → {protocol_color}{protocol_info}{Color.END}")
            
            # Group by protocol type with colors
            print(f"\n{Color.BOLD}{Color.MAGENTA}📋 PROTOCOL SUMMARY:{Color.END}")
            print(f"{Color.CYAN}{'─' * 30}{Color.END}")
            protocol_count = {}
            for port in self.open_ports:
                protocol = self.get_protocol_name(port)
                protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
            
            for protocol, count in sorted(protocol_count.items()):
                protocol_color = self.get_protocol_color(protocol)
                print(f"   {protocol_color}{protocol:15}{Color.END}: {Color.GREEN}{count} port(s){Color.END}")
        else:
            print(f"\n{Color.RED}❌ No open ports found.{Color.END}")
        
        print(f"\n{Color.BLUE}⏰ End Time:{Color.END} {Color.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.END}")
        print(f"{Color.CYAN}{'═' * 70}{Color.END}")

def parse_ports(port_str):
    """Parse port range string"""
    if '-' in port_str:
        start, end = map(int, port_str.split('-'))
        return start, end
    elif ',' in port_str:
        ports = list(map(int, port_str.split(',')))
        return min(ports), max(ports)
    else:
        port = int(port_str)
        return port, port

def main():
    parser = argparse.ArgumentParser(
        description=f"{Color.GREEN}PyPortScanner - Advanced Protocol Port Scanner{Color.END}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{Color.CYAN}
Examples:
  python pyportscanner.py example.com --common
  python pyportscanner.py 192.168.1.1 -p 1-10000 -t 150
  python pyportscanner.py target.com -p 21,22,80,443,8080,8443
  python pyportscanner.py example.com -T 0.5 -t 200{Color.END}"""
    )
    
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1000, 80,443,8080)", default="1-1024")
    parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=100)
    parser.add_argument("-T", "--timeout", help="Timeout in seconds", type=float, default=2.0)
    parser.add_argument("--common", help="Scan only common service ports", action="store_true")
    
    args = parser.parse_args()
    
    try:
        if args.common:
            common_ports = sorted(PyPortScanner.PROTOCOL_PORTS.keys())
            start_port, end_port = min(common_ports), max(common_ports)
            print(f"{Color.BLUE}[INFO]{Color.END} Scanning {Color.YELLOW}{len(common_ports)}{Color.END} common service ports")
        else:
            start_port, end_port = parse_ports(args.ports)
        
        scanner = PyPortScanner(args.target, args.timeout, args.threads)
        scanner.scan_range(start_port, end_port)
        
    except ValueError:
        print(f"{Color.RED}[ERROR]{Color.END} Invalid port format. Use '1-1000' or '80,443,8080'")
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}[INFO]{Color.END} Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"{Color.RED}[ERROR]{Color.END} {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()