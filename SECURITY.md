# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of PyPortScanner seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**voltsparx@gmail.com**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### Information to Include

When reporting a vulnerability, please include:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag, branch, or commit hash)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Best Practices for Users

### Legal Compliance
- **Always obtain proper authorization** before scanning any network or system
- Ensure compliance with local laws and regulations in your jurisdiction
- Use only on networks you own or have explicit permission to test

### Safe Usage
- Use appropriate timeout values to avoid network congestion
- Limit thread count to prevent overwhelming target systems
- Avoid scanning critical infrastructure without explicit authorization
- Use the `--common` flag for less intrusive scanning when appropriate

### Data Handling
- Scan results may contain sensitive information - handle with care
- Securely store and transmit scan results
- Anonymize data when sharing for educational purposes

## Security Considerations

### For Penetration Testers
- This tool is designed for authorized security assessments only
- Ensure you have written permission before conducting scans
- Document all scanning activities for compliance purposes

### For Developers
- The tool uses only Python standard library modules
- No external dependencies that could introduce supply chain vulnerabilities
- Regular code reviews are conducted for security best practices

## Security Updates

Security updates will be released as needed. Please ensure you are using the latest version of PyPortScanner for the most secure experience.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The developers are not responsible for any misuse or damage caused by this program. Users are solely responsible for ensuring they have proper authorization before using this tool.

## Security History

All security updates and vulnerability fixes will be documented in the [CHANGELOG.md](CHANGELOG.md) file.

---

*Last updated: August 21, 2025*