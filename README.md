# MESH by Viscount Vulnerability Scanner MCP Server

**Version 0.2.0** - Enhanced with prompts, resources, and comprehensive security assessment tools

A comprehensive MCP server for scanning and analyzing MESH by Viscount systems for default credential vulnerabilities. This tool is designed for security research and educational purposes only.

## 🚨 Important Notice

**This tool is for educational and security research purposes only.** Unauthorized access to systems is illegal. Always obtain proper authorization before scanning any systems.

## Features

### 🔍 Scanning Capabilities
- **Single IP Scanning**: Scan individual IP addresses for MESH systems
- **IP Range Scanning**: Scan entire IP ranges with configurable concurrency
- **Default Credential Testing**: Test for the default credentials (freedom:viscount)
- **System Discovery**: Identify MESH by Viscount systems on networks

### 📊 Security Assessment
- **Comprehensive Reports**: Generate detailed security assessment reports
- **Vulnerability Summaries**: Track vulnerabilities across timeframes
- **Compliance Reports**: Generate reports for NIST, ISO27001, SOC2, and PCI-DSS
- **Risk Analysis**: Automatic risk level assessment (LOW, MEDIUM, HIGH, CRITICAL)

### 📋 Data Export
- **Multiple Formats**: Export results as JSON, CSV, or XML
- **Filtered Export**: Export only vulnerable systems or specific scans
- **Historical Data**: Maintain scan history and statistics

### 🎯 Advanced Features
- **System Information**: Extract building details, user lists, and event logs
- **Entrance Control**: Demonstrate entrance unlocking (educational only)
- **Real-time Monitoring**: Track scanning progress and results
- **Rate Limiting**: Configurable rate limiting for responsible scanning

## Installation

```bash
# Install dependencies
npm install

# Build the server
npm run build

# Run the server
npm start
```

## MCP Configuration

Add to your MCP configuration file:

```json
{
  "mcpServers": {
    "mesh-scanner": {
      "command": "node",
      "args": ["path/to/mesh-scanner/build/index.js"]
    }
  }
}
```

## Usage

### Basic Scanning

#### Scan a Single IP
```json
{
  "tool": "scan_ip",
  "arguments": {
    "ipAddress": "192.168.1.100"
  }
}
```

#### Scan an IP Range
```json
{
  "tool": "scan_ip_range",
  "arguments": {
    "startIp": "192.168.1.1",
    "endIp": "192.168.1.254",
    "concurrency": 5,
    "timeout": 5000
  }
}
```

### Security Assessment

#### Generate Security Report
```json
{
  "prompt": "security_assessment",
  "arguments": {
    "format": "detailed",
    "scan_id": "scan_123456789"
  }
}
```

#### Vulnerability Summary
```json
{
  "prompt": "vulnerability_summary",
  "arguments": {
    "timeframe": "7d"
  }
}
```

#### Compliance Report
```json
{
  "prompt": "compliance_report",
  "arguments": {
    "standard": "NIST"
  }
}
```

#### Remediation Guide
```json
{
  "prompt": "remediation_guide",
  "arguments": {
    "system_ip": "192.168.1.100",
    "severity": "high"
  }
}
```

### Data Export

#### Export All Results
```json
{
  "tool": "export_scan_results",
  "arguments": {
    "format": "json"
  }
}
```

#### Export Vulnerable Systems Only
```json
{
  "tool": "export_scan_results",
  "arguments": {
    "format": "csv",
    "includeVulnerableOnly": true
  }
}
```

### System Information

#### Get System Details
```json
{
  "tool": "get_system_info",
  "arguments": {
    "url": "http://192.168.1.100"
  }
}
```

### Resources

Access real-time data through MCP resources:

- `mesh://scan-results` - Latest scan results
- `mesh://vulnerable-systems` - List of vulnerable systems
- `mesh://scan-history` - Historical scan data
- `mesh://vulnerability-stats` - Statistics and trends
- `mesh://system-details` - Detailed system information
- `mesh://security-assessments` - Generated assessments

## Prompts

The server provides several prompts for comprehensive security analysis:

### 1. Security Assessment
Generates detailed security reports with risk analysis and recommendations.

**Arguments:**
- `scan_id` (optional): Specific scan to analyze
- `format`: "detailed", "summary", or "executive"

### 2. Vulnerability Summary
Creates summaries of vulnerabilities found across different timeframes.

**Arguments:**
- `timeframe`: "24h", "7d", "30d", or "all"

### 3. Remediation Guide
Provides specific remediation steps for vulnerable systems.

**Arguments:**
- `system_ip`: IP address of vulnerable system
- `severity`: "low", "medium", "high", or "critical"

### 4. Compliance Report
Generates compliance reports for various security standards.

**Arguments:**
- `standard`: "NIST", "ISO27001", "SOC2", or "PCI-DSS"

## Tools

### scan_ip
Scan a single IP address for MESH system and test default credentials.

**Parameters:**
- `ipAddress` (string): IP address to scan
- `timeout` (number, optional): Timeout in milliseconds
- `config` (object, optional): Additional configuration

### scan_ip_range
Scan a range of IP addresses for MESH systems.

**Parameters:**
- `startIp` (string): Starting IP address
- `endIp` (string): Ending IP address
- `concurrency` (number, optional): Concurrent scans (max: 20)
- `timeout` (number, optional): Timeout in milliseconds
- `config` (object, optional): Additional configuration

### test_default_credentials
Test if a MESH system is vulnerable to default credentials.

**Parameters:**
- `url` (string): URL of the MESH system
- `config` (object, optional): Additional configuration

### get_system_info
Get detailed information about a vulnerable MESH system.

**Parameters:**
- `url` (string): URL of the vulnerable system
- `config` (object, optional): Additional configuration

### unlock_entrance
Unlock an entrance (educational purposes only).

**Parameters:**
- `url` (string): URL of the vulnerable system
- `entranceId` (string): ID of the entrance to unlock
- `config` (object, optional): Additional configuration

### export_scan_results
Export scan results to various formats.

**Parameters:**
- `format` (string): "json", "csv", or "xml"
- `includeVulnerableOnly` (boolean, optional): Export only vulnerable systems
- `scanId` (string, optional): Specific scan ID to export

## Configuration

### Scan Configuration
```typescript
interface ScanConfig {
  timeout: number;        // Request timeout in ms (default: 5000)
  concurrency: number;    // Concurrent scans (default: 5, max: 20)
  rateLimit: number;      // Rate limit between requests (default: 100)
  userAgent: string;      // Custom User-Agent string
}
```

### Default Credentials
- **Username**: freedom
- **Password**: viscount

## Security Considerations

### Risk Levels
- **CRITICAL**: >50% of systems vulnerable
- **HIGH**: >20% of systems vulnerable
- **MEDIUM**: >10% of systems vulnerable
- **LOW**: ≤10% of systems vulnerable

### Recommendations
1. **Immediate**: Change default credentials on all vulnerable systems
2. **Short-term**: Implement network segmentation and monitoring
3. **Long-term**: Establish regular security assessments and training

## Legal and Ethical Use

This tool is provided for:
- Security research and education
- Authorized penetration testing
- Vulnerability assessment with proper authorization
- Security awareness training

**Users are responsible for ensuring they have proper authorization before scanning any systems.**

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is provided for educational purposes. Use responsibly and in accordance with applicable laws and regulations.

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.
