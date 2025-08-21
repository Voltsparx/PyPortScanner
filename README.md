Python Port Scanner by Voltsparx
Contact: voltsparx@gmail.com

Description

PyPortScanner is an advanced, multi-threaded port scanner with protocol detection capabilities. Built with Python, it provides colorful terminal output and comprehensive network reconnaissance features.

Features

Colorful Terminal Interface - Beautiful ANSI-colored output
Multi-threaded Scanning - Fast parallel port scanning
Protocol Detection - Automatic service identification (HTTP, HTTPS, FTP, SSH, SMTP, etc.)
Banner Grabbing - Service banner collection for detailed information
Common Port Scanning - Pre-defined common service ports
Customizable Timeouts - Adjustable connection timeouts
Progress Reporting - Real-time scan progress updates
Safe Scanning - Proper error handling and timeout management
Installation

Prerequisites:

Python 3.6 or higher
pip package manager
Installation:

bash
git clone https://github.com/Voltsparx/PyPortScanner.git
cd PyPortScanner
Usage

Basic Scanning:

bash
python pyportscanner.py example.com --common
python pyportscanner.py 192.168.1.1 -p 1-1000
python pyportscanner.py target.com -p 80,443,22,21
Advanced Options:

bash
python pyportscanner.py target.com -t 200
python pyportscanner.py target.com -T 1.5
python pyportscanner.py example.com -p 1-5000 -t 150 -T 0.8
Command Line Arguments:

text
target                Target IP address or hostname
-p PORTS, --ports     Port range (e.g., 1-1000, 80,443,8080)
-t THREADS, --threads Number of threads (default: 100)
-T TIMEOUT, --timeout Timeout in seconds (default: 2.0)
--common              Scan only common service ports
Supported Protocols

PyPortScanner automatically detects and identifies over 30 different protocols including:

Web Protocols: HTTP (80), HTTPS (443), HTTP-ALT (8080), HTTPS-ALT (8443)
File Transfer: FTP (21), SSH (22), TELNET (23)
Email: SMTP (25), POP3 (110), IMAP (143), SMTPS (465), SMTP-SUB (587), IMAPS (993), POP3S (995)
Database: MSSQL (1433), ORACLE (1521), MYSQL (3306), POSTGRES (5432)
Remote Access: RDP (3389), VNC (5900)
Network Services: DNS (53), DHCP (67-68), MSRPC (135), NETBIOS-SSN (139), SMB (445)
Other Services: SNMP (161-162), LDAP (389), LDAPS (636)
Screenshot

text
╔══════════════════════════════════════════════════════════════╗
║                   PyPortScanner by Voltsparx                 ║
║                 Contact: voltsparx@gmail.com                 ║
╚══════════════════════════════════════════════════════════════╝

[INFO] Resolved example.com to 93.184.216.34
[TARGET]    93.184.216.34 (example.com)
[PORTS]     1-1024
[THREADS]   100
[TIMEOUT]   2.0s
[START]     2024-01-15 14:30:22
──────────────────────────────────────────────────────────────────────
🚀 Scanning ports and detecting protocols...

✅ [OPEN] Port    80 - HTTP - Active
✅ [OPEN] Port   443 - HTTPS - Active
✅ [OPEN] Port    53 - DNS - Active

══════════════════════════════════════════════════════════════
           SCAN RESULTS SUMMARY
══════════════════════════════════════════════════════════════
⏱️  Duration:    12.45 seconds
📊 Ports Scanned: 1024
✅ Open Ports:    3

🎯 OPEN PORTS DETECTED:
──────────────────────────────────────────────────────────────────────
   Port    80 → HTTP - Active
   Port   443 → HTTPS - Active
   Port    53 → DNS - Active

📋 PROTOCOL SUMMARY:
──────────────────────────────
   HTTP           : 1 port(s)
   HTTPS          : 1 port(s)
   DNS            : 1 port(s)

⏰ End Time: 2024-01-15 14:30:34
══════════════════════════════════════════════════════════════
Legal Disclaimer

This tool is designed for educational purposes and authorized security testing only. Always obtain proper permission before scanning any network or system. The author is not responsible for any misuse or damage caused by this program.

License

MIT License - feel free to modify and distribute this tool.

Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

Support

For support, questions, or suggestions, please contact:

Email: voltsparx@gmail.com
GitHub Issues: Create an issue
Note: This tool should only be used on networks you own or have explicit permission to scan. Unauthorized port scanning may be illegal in your jurisdiction.