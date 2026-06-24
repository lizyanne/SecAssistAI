import express from "express";
import path from "path";
import fs from "fs";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";
import { DatabaseService } from "./src/db/database.ts";
import { MITRE_ATTACK_MATRIX } from "./src/data/mitreData.ts";

dotenv.config();

const app = express();
const PORT = 3000;
const DB_FILE = path.join(process.cwd(), "db.json");

// Initialize Gemini client with proper user agent header
let ai: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  try {
    ai = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
    console.log("Gemini API client initialized successfully.");
  } catch (err) {
    console.error("Failed to initialize Gemini API Client:", err);
  }
} else {
  console.log("No GEMINI_API_KEY environment variable found. Falling back to rules-based local engine.");
}

app.use(express.json({ limit: "50mb" }));

// Pre-seeded high fidelity mock database
const initialDatabase = {
  users: [
    { id: "u-1", name: "Sarah Connor", email: "admin@secassist.ai", role: "Admin", tenantId: "tenant-alpha" },
    { id: "u-2", name: "John Doe", email: "analyst@secassist.ai", role: "Analyst", tenantId: "tenant-alpha" },
    { id: "u-3", name: "Marcus Wright", email: "viewer@secassist.ai", role: "Viewer", tenantId: "tenant-alpha" },
    { id: "u-4", name: "Elena Rostova", email: "external@secassist.ai", role: "Analyst", tenantId: "tenant-beta" }
  ],
  alerts: [
    {
      id: "alt-101",
      title: "Ransomware C2 Beaconing Detected",
      severity: "Critical",
      category: "Malware",
      timestamp: new Date(Date.now() - 3600000 * 2).toISOString(), // 2 hrs ago
      sourceIp: "10.100.12.45",
      destIp: "185.112.144.12",
      status: "Active",
      description: "Repeated outbound HTTPS connections to known LockBit C2 infrastructure. Pattern matches periodic 30-second beacon jitter.",
      mitreAttack: {
        tactic: "Command and Control",
        technique: "Application Layer Protocol: Web Protocols",
        id: "T1071.001"
      },
      assignedTo: "analyst@secassist.ai",
      tenantId: "tenant-alpha"
    },
    {
      id: "alt-102",
      title: "Active Directory Domain Controller Brute-Force",
      severity: "High",
      category: "Credential Access",
      timestamp: new Date(Date.now() - 3600000 * 5).toISOString(), // 5 hrs ago
      sourceIp: "192.168.1.112",
      destIp: "10.100.1.4",
      status: "Investigating",
      description: "Over 450 failed authentication attempts for 'Administrator' account within 3 minutes followed by a successful login event from external IP range.",
      mitreAttack: {
        tactic: "Credential Access",
        technique: "Brute Force: Password Guessing",
        id: "T1110.001"
      },
      assignedTo: "analyst@secassist.ai",
      tenantId: "tenant-alpha"
    },
    {
      id: "alt-103",
      title: "SQL Injection on Public Web Server",
      severity: "Medium",
      category: "Initial Access",
      timestamp: new Date(Date.now() - 3600000 * 12).toISOString(), // 12 hrs ago
      sourceIp: "198.51.100.73",
      destIp: "10.100.5.10",
      status: "Resolved",
      description: "WAF block event triggered by payload containing 'UNION SELECT' and '--' comments targeting product catalog API parameter 'id'.",
      mitreAttack: {
        tactic: "Initial Access",
        technique: "Exploit Public-Facing Application",
        id: "T1190"
      },
      assignedTo: "admin@secassist.ai",
      tenantId: "tenant-alpha"
    },
    {
      id: "alt-104",
      title: "Suspicious AWS IAM Privilege Escalation",
      severity: "Critical",
      category: "Privilege Escalation",
      timestamp: new Date(Date.now() - 3600000 * 24).toISOString(), // 1 day ago
      sourceIp: "203.0.113.88",
      destIp: "AWS-IAM-Service",
      status: "Active",
      description: "IAM user 'Dev-Admin-Temp' successfully updated policy to include AdministratorAccess using a previously unused session token from TOR exit node.",
      mitreAttack: {
        tactic: "Privilege Escalation",
        technique: "Abuse Access Token / Role Assumption",
        id: "T1548"
      },
      assignedTo: "admin@secassist.ai",
      tenantId: "tenant-alpha"
    },
    {
      id: "alt-105",
      title: "Anomalous Bulk Data Exfiltration",
      severity: "High",
      category: "Exfiltration",
      timestamp: new Date(Date.now() - 3600000 * 36).toISOString(), // 1.5 days ago
      sourceIp: "10.100.12.89",
      destIp: "91.189.91.157",
      status: "Resolved",
      description: "Upload of 14.2 GB of compressed archives (.tar.gz) from backup repository to public object storage endpoints over port 443.",
      mitreAttack: {
        tactic: "Exfiltration",
        technique: "Exfiltration Over Web Service",
        id: "T1567.002"
      },
      assignedTo: "analyst@secassist.ai",
      tenantId: "tenant-alpha"
    }
  ],
  logs: [
    {
      id: "log-201",
      filename: "auth_failures_ssh.log",
      uploadedBy: "analyst@secassist.ai",
      timestamp: new Date(Date.now() - 3600000 * 3).toISOString(),
      parsedCount: 42,
      status: "Analyzed",
      rawContent: "Jun 24 02:15:33 core-ssh-server sshd[12495]: Failed password for root from 185.220.101.44 port 43224 ssh2\nJun 24 02:15:35 core-ssh-server sshd[12497]: Failed password for root from 185.220.101.44 port 43228 ssh2\nJun 24 02:15:37 core-ssh-server sshd[12499]: Failed password for root from 185.220.101.44 port 43232 ssh2\nJun 24 02:15:40 core-ssh-server sshd[12501]: Accepted publickey for admin from 10.100.12.4 port 38222 ssh2",
      analysis: {
        threatLevel: "High",
        threatName: "SSH Brute-Force Attack with Tor Exit Node Connection",
        explanation: "An external IP (185.220.101.44) known to be associated with Tor exit networks repeatedly attempted to brute force the root user via SSH. Immediately following these attempts, a legitimate user 'admin' authenticated successfully from an internal IP (10.100.12.4). While the root attempts were blocked, the correlation with internal activity requires monitoring.",
        remediationSteps: [
          "Disable root SSH logins on core-ssh-server in /etc/ssh/sshd_config (PermitRootLogin no).",
          "Add IP 185.220.101.44 to the corporate perimeter firewall blocklist.",
          "Enable rate-limiting or install fail2ban on core-ssh-server.",
          "Verify the owner of internal IP 10.100.12.4 was active and authorised at 02:15."
        ],
        mitreMapping: {
          tactic: "Credential Access",
          technique: "Brute Force: Password Guessing",
          id: "T1110.001"
        },
        suspiciousIndicators: [
          "185.220.101.44",
          "Failed password for root",
          "Multiple login attempts in a short timeframe (2 second intervals)"
        ]
      }
    }
  ] as any[],
  threats: [
    {
      id: "th-301",
      name: "LockBit 3.0 Ransomware Campaign",
      severity: "Critical",
      mitreMapping: { tactic: "Impact", technique: "Data Encrypted for Impact", id: "T1486" },
      explanation: "Active ransomware strain targeting Windows/Linux directories via customized GPO scripting. Beacons out on encrypted HTTPS channels.",
      remediation: "Ensure offsite immutable backups are validated. Disable lateral administrative shares (C$) where possible.",
      detectionSignature: "Outbound DNS requests resolving to *.lockbit.onion or related command and control web proxy IP addresses.",
      affectedAssets: ["Internal Domain Controllers", "Active Directory Servers", "User Workstations"]
    },
    {
      id: "th-302",
      name: "Kerberoasting Exploit",
      severity: "High",
      mitreMapping: { tactic: "Credential Access", technique: "Steal or Forge Kerberos Tickets", id: "T1558" },
      explanation: "Attacker queries Active Directory SPNs and requests ticket-granting service (TGS) tickets offline to crack passwords.",
      remediation: "Enforce long passwords for service accounts (minimum 25 characters) or migrate to Group Managed Service Accounts (gMSA).",
      detectionSignature: "Event ID 4769 with RC4 encryption type (0x17) indicating vulnerable password cracking exposure.",
      affectedAssets: ["Active Directory Services", "Database Service Accounts"]
    }
  ],
  reports: [
    {
      id: "rep-401",
      title: "Incident Report: Lockheed C2 Outbound Beaconing Activity",
      alertId: "alt-101",
      threatName: "LockBit C2 Beaconing Activity",
      severity: "Critical",
      mitreMapping: { tactic: "Command and Control", technique: "Application Layer Protocol: Web Protocols", id: "T1071.001" },
      executiveSummary: "On June 24, SecAssistAI detected a high-volume, highly persistent HTTP-beaconing threat emanating from the internal system 10.100.12.45. Analysis indicates LockBit ransomware payload beacon execution. Immediate isolation and host forensics are required.",
      technicalDetails: "The endpoint was found transferring periodic HTTP GET requests with structured base64 headers. Jitter matches the telemetry for LockBit proxy hosts. Network analysis confirmed connections to 185.112.144.12 on port 443.",
      remediationPlan: "1. Network-isolate endpoint 10.100.12.45 via EDR controller.\n2. Revoke active Active Directory credentials for compromised endpoints.\n3. Run a threat hunt on surrounding systems for lateral traversal artifacts.\n4. Re-image the target operating system.",
      generatedBy: "admin@secassist.ai",
      timestamp: new Date(Date.now() - 3600000 * 2).toISOString()
    }
  ],
  assets: [
    { id: "ast-1", name: "AD-Domain-Controller", type: "Server", ipAddress: "10.100.1.4", os: "Windows Server 2022", criticality: "Critical", status: "Online", owner: "admin@secassist.ai", activeAlertsCount: 1, lastSeen: new Date().toISOString() },
    { id: "ast-2", name: "WAF-Public-Web", type: "Server", ipAddress: "10.100.5.10", os: "Ubuntu Linux 22.04 LTS", criticality: "High", status: "Online", owner: "admin@secassist.ai", activeAlertsCount: 0, lastSeen: new Date().toISOString() },
    { id: "ast-3", name: "Finance-WS-45", type: "Endpoint", ipAddress: "10.100.12.45", os: "Windows 11 Enterprise", criticality: "High", status: "Investigating", owner: "analyst@secassist.ai", activeAlertsCount: 1, lastSeen: new Date().toISOString() },
    { id: "ast-4", name: "Dev-WS-89", type: "Endpoint", ipAddress: "10.100.12.89", os: "macOS Sequoia", criticality: "Medium", status: "Online", owner: "analyst@secassist.ai", activeAlertsCount: 0, lastSeen: new Date().toISOString() },
    { id: "ast-5", name: "AWS-Prod-Kubernetes", type: "Cloud", ipAddress: "172.31.44.10", os: "Linux CoreOS", criticality: "Critical", status: "Online", owner: "admin@secassist.ai", cloudProvider: "AWS", activeAlertsCount: 1, lastSeen: new Date().toISOString() }
  ],
  vulnerabilities: [
    {
      id: "CVE-2024-3094",
      title: "XZ Utils Backdoor Vulnerability",
      score: 10.0,
      severity: "Critical",
      affectedAssetId: "ast-2",
      affectedAssetName: "WAF-Public-Web",
      status: "Open",
      patchRecommendation: "Downgrade or upgrade xz-utils package to unbackdoored version (e.g. 5.6.1+ or 5.4.6) immediately.",
      publishedDate: "2024-03-29",
      description: "Malicious code was discovered in upstream xz-utils tarballs starting with version 5.6.0, allowing unauthorized SSH execution bypass."
    },
    {
      id: "CVE-2023-38606",
      title: "Apple WebKit Remote Code Execution",
      score: 8.8,
      severity: "High",
      affectedAssetId: "ast-4",
      affectedAssetName: "Dev-WS-89",
      status: "In Progress",
      patchRecommendation: "Apply the latest macOS Ventura 13.5 or macOS Sonoma security patches.",
      publishedDate: "2023-07-24",
      description: "A stateful validation vulnerability in WebKit allowed remote attackers to execute arbitrary code via specially crafted web content."
    },
    {
      id: "CVE-2022-22965",
      title: "Spring4Shell Remote Code Execution",
      score: 9.8,
      severity: "Critical",
      affectedAssetId: "ast-2",
      affectedAssetName: "WAF-Public-Web",
      status: "Patched",
      patchRecommendation: "Upgrade Spring Framework dependency to 5.3.18+ or 5.2.20+.",
      publishedDate: "2022-03-31",
      description: "A Spring MVC or Spring WebFlux application running on JDK 9+ was vulnerable to remote code execution via data binding."
    },
    {
      id: "CVE-2023-22515",
      title: "Confluence Privilege Escalation Vulnerability",
      score: 10.0,
      severity: "Critical",
      affectedAssetId: "ast-1",
      affectedAssetName: "AD-Domain-Controller",
      status: "Open",
      patchRecommendation: "Upgrade Atlassian Confluence Server to versions 8.3.3+, 8.4.3+ or 8.5.2+ immediately.",
      publishedDate: "2023-10-04",
      description: "A privilege escalation vulnerability in Confluence Data Center and Server allowed unauthenticated attackers to create administrator accounts."
    }
  ],
  aiInvestigations: [] as any[]
};

// Database read/write utility helper
function readDb(): typeof initialDatabase {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(initialDatabase, null, 2));
    return initialDatabase;
  }
  try {
    const data = fs.readFileSync(DB_FILE, "utf-8");
    return JSON.parse(data);
  } catch (err) {
    console.error("Failed to parse db.json. Reverting to initial DB.", err);
    return initialDatabase;
  }
}

function writeDb(data: typeof initialDatabase) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error("Failed to write to db.json", err);
  }
}

// Ensure db exists
readDb();

// In-memory store for AI investigations when running in PG/fallback mode
const aiInvestigations: any[] = [];

// Authentication middleware to extract user context
async function getAuthUser(req: express.Request): Promise<any> {
  let token = req.headers.authorization;
  if (!token && req.query.token) {
    token = String(req.query.token);
  }
  if (!token) return null;

  const cleanToken = token.replace("Bearer ", "");
  if (!cleanToken) return null;

  // Simple base64 decode for token emulation (enterprise grade mock authentication)
  try {
    const decoded = Buffer.from(cleanToken, "base64").toString("utf-8");
    const parsed = JSON.parse(decoded);
    const matchedUser = await DatabaseService.getUserByEmail(parsed.email);
    return matchedUser || null;
  } catch (err) {
    return null;
  }
}

// Rules-based local security scanner (used when Gemini API key is missing, or for fallback)
function fallbackAnalyzeLog(filename: string, content: string): any {
  const lowerContent = content.toLowerCase();
  let threatLevel: "Critical" | "High" | "Medium" | "Low" = "Low";
  let threatName = "Anomalous Log Event";
  let tactic = "Execution";
  let technique = "Command and Scripting Interpreter";
  let code = "T1059";
  let explanation = "SecAssistAI completed a deep heuristics scan. No critical signatures match common ransomware patterns, but general system event tracking is logged.";
  const remediationSteps = [
    "Verify the event origin and ensure standard host configurations.",
    "Monitor continuous security performance alerts of the host."
  ];
  const suspiciousIndicators: string[] = [];

  if (lowerContent.includes("union select") || lowerContent.includes("select ") && lowerContent.includes("--")) {
    threatLevel = "High";
    threatName = "SQL Injection Vulnerability Attempt";
    tactic = "Initial Access";
    technique = "Exploit Public-Facing Application";
    code = "T1190";
    explanation = "An attacker attempted to manipulate a database query argument using high-risk SQL payload structures such as SELECT and comment flags.";
    remediationSteps.unshift("Validate web application input sanitization and integrate parameterized SQL queries.", "Ensure the Web Application Firewall (WAF) blocks SQL signature payloads.");
    suspiciousIndicators.push("UNION SELECT", "Comment markers '--'");
  } else if (lowerContent.includes("failed password") || lowerContent.includes("authentication failure")) {
    threatLevel = "High";
    threatName = "Potential Brute Force Credential Harvest";
    tactic = "Credential Access";
    technique = "Brute Force: Password Guessing";
    code = "T1110.001";
    explanation = "Repeated failed login instances originating from an identical daemon port. Matches credential stuffing or automated password guessing activity.";
    remediationSteps.unshift("Implement brute-force shielding (fail2ban or firewall rate-limits).", "Enforce Multi-Factor Authentication (MFA) across all ssh endpoints.");
    suspiciousIndicators.push("Failed password", "Failed authentication attempts");
  } else if (lowerContent.includes("lockbit") || lowerContent.includes("c2") || lowerContent.includes("beacon")) {
    threatLevel = "Critical";
    threatName = "Active Command and Control Beaconing";
    tactic = "Command and Control";
    technique = "Application Layer Protocol: Web Protocols";
    code = "T1071.001";
    explanation = "Critical host was matched interacting with identified LockBit commands. Jitter parameters indicate persistent malicious agent beacon script execution.";
    remediationSteps.unshift("Perform EDR client isolation on the host immediately.", "Quarantine surrounding hosts linked to active sessions.");
    suspiciousIndicators.push("Beacon signature matching LockBit telemetry");
  }

  return {
    threatLevel,
    threatName,
    explanation,
    remediationSteps,
    mitreMapping: { tactic, technique, id: code },
    suspiciousIndicators: suspiciousIndicators.length > 0 ? suspiciousIndicators : ["Unrecognized event pattern log line"]
  };
}

// --- API ROUTES ---

// Authenticate and return JWT token replica
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email) {
    return res.status(400).json({ error: "Email is required." });
  }

  const matchedUser = await DatabaseService.getUserByEmail(email);

  if (!matchedUser) {
    return res.status(401).json({ error: "Invalid security email credentials." });
  }

  // Create a base64 simulation token representing jwt authentication
  const tokenPayload = { email: matchedUser.email, role: matchedUser.role, tenantId: matchedUser.tenantId };
  const mockToken = Buffer.from(JSON.stringify(tokenPayload)).toString("base64");

  return res.json({
    token: mockToken,
    user: matchedUser
  });
});

// Fetch current user details
app.get("/api/auth/me", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) {
    return res.status(401).json({ error: "Unauthorized access token." });
  }
  return res.json({ user });
});

// Dynamic statistics compiler for custom dashboard widgets
app.get("/api/dashboard/stats", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });

  const alertsList = await DatabaseService.getAlerts();
  // Multi-tenant check
  const alerts = alertsList.filter(a => user.role === "Admin" || a.tenantId === user.tenantId);

  const total = alerts.length;
  const critical = alerts.filter(a => a.severity === "Critical").length;
  const high = alerts.filter(a => a.severity === "High").length;
  const medium = alerts.filter(a => a.severity === "Medium").length;
  const low = alerts.filter(a => a.severity === "Low").length;

  const active = alerts.filter(a => a.status !== "Resolved").length;
  const resolved = alerts.filter(a => a.status === "Resolved").length;

  // Real-time calculated Security Risk Score: 100 max, weighted heavily by Critical & High active threats
  let baseScore = 20; // baseline standard risk
  const activeCritical = alerts.filter(a => a.severity === "Critical" && a.status !== "Resolved").length;
  const activeHigh = alerts.filter(a => a.severity === "High" && a.status !== "Resolved").length;
  const activeMed = alerts.filter(a => a.severity === "Medium" && a.status !== "Resolved").length;

  baseScore += (activeCritical * 25) + (activeHigh * 15) + (activeMed * 5);
  const riskScore = Math.min(Math.max(baseScore, 10), 99);

  // Staggered incident timeline distribution (past 5 days)
  const timelineData = Array.from({ length: 5 }).map((_, idx) => {
    const day = new Date(Date.now() - 86400000 * (4 - idx)).toLocaleDateString("en-US", { month: "short", day: "numeric" });
    // Distribute sample variations
    return {
      time: day,
      Critical: idx === 4 ? activeCritical : Math.max(0, critical - (4 - idx)),
      High: idx === 4 ? activeHigh : Math.max(0, high - Math.abs(2 - idx)),
      Medium: idx === 3 ? 2 : Math.max(1, medium - Math.abs(1 - idx)),
      Low: Math.max(1, low - idx)
    };
  });

  // MITRE attack heatmap aggregation
  const tacticMap: Record<string, number> = {};
  alerts.forEach(a => {
    if (a.mitreAttack) {
      tacticMap[a.mitreAttack.tactic] = (tacticMap[a.mitreAttack.tactic] || 0) + 1;
    }
  });

  const allTactics = ["Initial Access", "Execution", "Privilege Escalation", "Credential Access", "Command and Control", "Exfiltration"];
  const mitreHeatmap = allTactics.map(t => {
    const count = tacticMap[t] || 0;
    let color = "rgba(30, 41, 59, 0.4)"; // dark low-risk slate
    if (count > 2) color = "rgba(239, 68, 68, 0.8)"; // bright red
    else if (count > 1) color = "rgba(249, 115, 22, 0.8)"; // bright orange
    else if (count > 0) color = "rgba(234, 179, 8, 0.8)"; // bright yellow
    return { tactic: t, count, color };
  });

  // Category distribution for pie rendering
  const categories: Record<string, number> = {};
  alerts.forEach(a => {
    categories[a.category] = (categories[a.category] || 0) + 1;
  });
  const categoryDistribution = Object.entries(categories).map(([name, value]) => ({ name, value }));

  return res.json({
    riskScore,
    totalAlerts: total,
    criticalCount: critical,
    highCount: high,
    mediumCount: medium,
    lowCount: low,
    activeIncidents: active,
    resolvedIncidents: resolved,
    timelineData,
    mitreHeatmap,
    categoryDistribution
  });
});

// Security alerts retrieval with searching, sorting and multi-tenant isolation
app.get("/api/alerts", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });

  const { severity, status, search } = req.query;
  let alerts = await DatabaseService.getAlerts();

  alerts = alerts.filter(a => user.role === "Admin" || a.tenantId === user.tenantId);

  if (severity && severity !== "All") {
    alerts = alerts.filter(a => a.severity === severity);
  }
  if (status && status !== "All") {
    alerts = alerts.filter(a => a.status === status);
  }
  if (search) {
    const term = String(search).toLowerCase();
    alerts = alerts.filter(a => 
      a.title.toLowerCase().includes(term) ||
      (a.description && a.description.toLowerCase().includes(term)) ||
      a.category.toLowerCase().includes(term) ||
      (a.sourceIp && a.sourceIp.toLowerCase().includes(term)) ||
      (a.destIp && a.destIp.toLowerCase().includes(term))
    );
  }

  // Sort alerts chronological descending (newest first)
  alerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return res.json(alerts);
});

// Update Alert Status, Assignee, Severity
app.patch("/api/alerts/:id", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  if (user.role === "Viewer") return res.status(403).json({ error: "Forbidden: Viewer permission insufficient." });

  const { id } = req.params;
  const { status, assignedTo, severity } = req.body;

  const alerts = await DatabaseService.getAlerts();
  const alertItem = alerts.find(a => a.id === id);

  if (!alertItem) {
    return res.status(404).json({ error: "Alert not found." });
  }

  // Tenant security boundary
  if (user.role !== "Admin" && alertItem.tenantId !== user.tenantId) {
    return res.status(403).json({ error: "Unauthorized access to tenant alert data." });
  }

  const updatedAlert = await DatabaseService.updateAlert(id, { status, assignedTo, severity });
  return res.json(updatedAlert);
});

// Automatic simulated alert injector (Alert trigger event emulation)
app.post("/api/alerts", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  if (user.role === "Viewer") return res.status(403).json({ error: "Forbidden: Viewer permission insufficient." });

  const { title, severity, category, sourceIp, destIp, description, mitreTactic, mitreTechnique, mitreId } = req.body;

  if (!title || !severity || !category || !sourceIp || !destIp) {
    return res.status(400).json({ error: "Missing required security event attributes." });
  }

  const newAlert = await DatabaseService.createAlert({
    title,
    severity,
    category,
    sourceIp,
    destIp,
    description: description || "Manually raised security incident report.",
    mitreAttack: mitreTactic ? {
      tactic: mitreTactic,
      technique: mitreTechnique || "Exploit Activity",
      id: mitreId || "T1000"
    } : undefined,
    assignedTo: user.email,
    tenantId: user.tenantId,
    timestamp: new Date().toISOString()
  });

  return res.status(201).json(newAlert);
});

// Logs listing endpoint
app.get("/api/logs", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });

  const logs = await DatabaseService.getAuditLogs();
  return res.json(logs);
});

// Log File Upload and Deep AI Analysis using Google GenAI SDK (with fallback parsing)
app.post("/api/logs/upload", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  if (user.role === "Viewer") return res.status(403).json({ error: "Forbidden: Viewer role cannot upload logs." });

  const { filename, content } = req.body;
  if (!filename || !content) {
    return res.status(400).json({ error: "Filename and log content are required." });
  }

  const logId = `log-${Math.floor(200 + Math.random() * 800)}`;
  const parsedLines = content.split("\n").filter((l: string) => l.trim().length > 0).length;

  const newLog = await DatabaseService.createAuditLog({
    id: logId,
    filename,
    uploadedBy: user.email,
    timestamp: new Date().toISOString(),
    parsedCount: parsedLines,
    status: "Pending",
    rawContent: content
  });

  // Return the immediate status and handle deep analysis asynchronously or synchronously
  // Let's do it inline to ensure 100% real-time responsive analytics
  try {
    let analysisResult: any = null;

    if (ai) {
      console.log(`Analyzing security logs using Gemini Model ('gemini-3.5-flash')`);
      const prompt = `You are an expert Security Operations Center (SOC) analysis agent. Analyze the following raw security log file named "${filename}" for malicious behavior, anomalies, exfiltration, or breach attempts.
      
      Log Content:
      """
      ${content.substring(0, 5000)}
      """

      Return a JSON object containing the threat Level (Critical, High, Medium, Low), the specific threat name, plain English explanation, actionable remediation steps, a MITRE ATT&CK mapping of the tactic, technique and technique ID, and suspicious lines/indicators triggering this warning.`;

      const geminiRes = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              threatLevel: { type: Type.STRING, description: "Must be exactly one of: Critical, High, Medium, Low" },
              threatName: { type: Type.STRING },
              explanation: { type: Type.STRING },
              remediationSteps: {
                type: Type.ARRAY,
                items: { type: Type.STRING }
              },
              mitreMapping: {
                type: Type.OBJECT,
                properties: {
                  tactic: { type: Type.STRING },
                  technique: { type: Type.STRING },
                  id: { type: Type.STRING }
                },
                required: ["tactic", "technique", "id"]
              },
              suspiciousIndicators: {
                type: Type.ARRAY,
                items: { type: Type.STRING }
              }
            },
            required: ["threatLevel", "threatName", "explanation", "remediationSteps", "mitreMapping", "suspiciousIndicators"]
          }
        }
      });

      if (geminiRes.text) {
        analysisResult = JSON.parse(geminiRes.text.trim());
      }
    }

    // Fallback to rules-based processing if Gemini client is unavailable or failed
    if (!analysisResult) {
      analysisResult = fallbackAnalyzeLog(filename, content);
    }

    // Save analysis result
    await DatabaseService.updateAuditLog(logId, {
      status: "Analyzed",
      analysis: analysisResult
    });

    // Automatically raise a Security Alert if the threat is Critical or High
    if (analysisResult.threatLevel === "Critical" || analysisResult.threatLevel === "High") {
      await DatabaseService.createAlert({
        title: `AI Flagged: ${analysisResult.threatName}`,
        severity: analysisResult.threatLevel,
        category: "AI Detection Analytics",
        timestamp: new Date().toISOString(),
        sourceIp: "Dynamic Capture",
        destIp: "Internal Network Range",
        status: "Active",
        description: `Automatically raised alert based on uploaded log file analysis. Originating Log: ${filename}.\nAI Explanation: ${analysisResult.explanation}`,
        mitreAttack: analysisResult.mitreMapping,
        assignedTo: user.email,
        tenantId: user.tenantId
      });
    }

    return res.json({ success: true, logId, analysis: analysisResult });

  } catch (err) {
    console.error("AI deep log analysis failed:", err);
    // Graceful recovery
    await DatabaseService.updateAuditLog(logId, { status: "Failed" });
    return res.status(500).json({ error: "Log registered but AI Deep analysis failed.", logId });
  }
});

// Threat Intelligence library
app.get("/api/threats", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });

  const threats = await DatabaseService.getThreatIntelligence();
  return res.json(threats);
});

// Add threat definition (Threat intelligence portal)
app.post("/api/threats", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  if (user.role === "Viewer") return res.status(403).json({ error: "Forbidden." });

  const { name, severity, tactic, technique, id, explanation, remediation, detectionSignature, affectedAssets } = req.body;

  if (!name || !severity || !tactic || !technique || !id) {
    return res.status(400).json({ error: "Missing required threat characteristics." });
  }

  const newThreat = await DatabaseService.createThreatIntel({
    name,
    severity,
    mitreMapping: { tactic, technique, id },
    explanation: explanation || "A threat intel bulletin posted by administration.",
    remediation: remediation || "Monitor active network endpoints.",
    detectionSignature: detectionSignature || "N/A",
    affectedAssets: affectedAssets || ["Corporate Assets"]
  });

  return res.status(201).json(newThreat);
});

// Reports endpoints
app.get("/api/reports", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });

  const reports = await DatabaseService.getReports();
  return res.json(reports);
});

// Generate Incident Report dynamically using Gemini API
app.post("/api/reports/generate", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  if (user.role === "Viewer") return res.status(403).json({ error: "Forbidden: Viewer role cannot generate reports." });

  const { alertId } = req.body;
  if (!alertId) {
    return res.status(400).json({ error: "alertId is required to map and generate the comprehensive report." });
  }

  const alerts = await DatabaseService.getAlerts();
  const matchedAlert = alerts.find(a => a.id === alertId);

  if (!matchedAlert) {
    return res.status(404).json({ error: "Alert context not found." });
  }

  try {
    // 1. Gather related incidents
    const allIncidents = await DatabaseService.getIncidents();
    const relatedIncidents = allIncidents.filter(inc => {
      if (inc.tenantId && matchedAlert.tenantId && inc.tenantId === matchedAlert.tenantId) {
        const alertKeywords = matchedAlert.title.toLowerCase().split(/\s+/).filter(w => w.length > 3);
        const sharesKeywords = alertKeywords.some(keyword => 
          inc.title.toLowerCase().includes(keyword) || inc.description.toLowerCase().includes(keyword)
        );
        const sameSeverity = inc.severity === matchedAlert.severity;
        return sharesKeywords || sameSeverity;
      }
      return false;
    });

    // 2. Gather related assets
    const allAssets = await DatabaseService.getAssets();
    const relatedAssets = allAssets.filter(asset => {
      const matchesIp = asset.ipAddress && (asset.ipAddress === matchedAlert.sourceIp || asset.ipAddress === matchedAlert.destIp);
      const matchesName = asset.name && (
        matchedAlert.title.toLowerCase().includes(asset.name.toLowerCase()) || 
        matchedAlert.description.toLowerCase().includes(asset.name.toLowerCase())
      );
      return matchesIp || matchesName;
    });

    // 3. Gather related vulnerabilities
    const allVulnerabilities = await DatabaseService.getVulnerabilities();
    const relatedVulnerabilities = allVulnerabilities.filter(vuln => {
      return relatedAssets.some(asset => asset.id === vuln.affectedAssetId || asset.name === vuln.affectedAssetName);
    });

    // 4. Gather related MITRE mappings
    const allMitreMappings = await DatabaseService.getMitreMappings();
    const relatedMitreMappings = allMitreMappings.filter(m => m.entity_id === matchedAlert.id || (m.entity_type === 'alert' && m.entity_id === matchedAlert.id));

    // Establish a high-fidelity local fallback structure
    let reportData = {
      executiveSummary: `On ${new Date(matchedAlert.timestamp).toLocaleString()}, a security event classified as ${matchedAlert.severity} was identified: ${matchedAlert.title}. Immediate action was flagged across the tenant environment.`,
      technicalAnalysis: `Forensic analysis of telemetry details: ${matchedAlert.description}.\nSource IP: ${matchedAlert.sourceIp} • Destination IP: ${matchedAlert.destIp}.\nRelated Assets: ${relatedAssets.length > 0 ? relatedAssets.map(a => `${a.name} (${a.ipAddress})`).join(", ") : "None directly matched in inventory"}.\nVulnerabilities: ${relatedVulnerabilities.length > 0 ? relatedVulnerabilities.map(v => `[${v.id}] ${v.title} (Severity: ${v.severity})`).join(", ") : "No CVEs correlated"}.`,
      rootCauseAssessment: relatedVulnerabilities.length > 0 
        ? `The incident root cause is highly correlated to known unpatched vulnerability ${relatedVulnerabilities[0].id} (${relatedVulnerabilities[0].title}) affecting the compromised asset ${relatedVulnerabilities[0].affectedAssetName}.`
        : `Potential lateral ingress, credential abuse, or untrusted execution of external scripts on target assets matching network endpoints ${matchedAlert.sourceIp} and ${matchedAlert.destIp}.`,
      remediationPlan: `1. Network-isolate all correlated assets: ${relatedAssets.length > 0 ? relatedAssets.map(a => a.name).join(", ") : "network endpoints"} immediately.\n2. Apply immediate patches or workarounds for unpatched vulnerabilities: ${relatedVulnerabilities.length > 0 ? relatedVulnerabilities.map(v => v.id).join(", ") : "system libraries"}.\n3. Revoke any active session credentials, session tokens, and Active Directory linkages for associated endpoints.\n4. Run a comprehensive malware scan and packet capture trace on target subnet ranges.`,
      riskRating: matchedAlert.severity
    };

    if (ai) {
      console.log(`Generating AI security incident report for alert: ${matchedAlert.title}`);
      const prompt = `You are a certified Lead Incident Handler (GCIH) at an enterprise SOC. Draft an official Security Incident Report for this active alert based on gathered security context:
      
      [ALERT DETAILS]
      Alert ID: ${matchedAlert.id}
      Alert Title: ${matchedAlert.title}
      Severity: ${matchedAlert.severity}
      Category: ${matchedAlert.category}
      Source IP: ${matchedAlert.sourceIp}
      Destination IP: ${matchedAlert.destIp}
      Alert Telemetry: ${matchedAlert.description}
      MITRE ATT&CK: ${matchedAlert.mitreAttack ? JSON.stringify(matchedAlert.mitreAttack) : "N/A"}

      [GATHERED CONTEXT - RELATED INCIDENTS]
      ${relatedIncidents.length > 0 
        ? JSON.stringify(relatedIncidents.map(i => ({ id: i.id, title: i.title, severity: i.severity, status: i.status, description: i.description })))
        : "No related incidents found."}

      [GATHERED CONTEXT - RELATED ASSETS]
      ${relatedAssets.length > 0 
        ? JSON.stringify(relatedAssets.map(a => ({ id: a.id, name: a.name, type: a.type, ipAddress: a.ipAddress, os: a.os, criticality: a.criticality })))
        : "No directly related assets found in inventory."}

      [GATHERED CONTEXT - RELATED VULNERABILITIES]
      ${relatedVulnerabilities.length > 0 
        ? JSON.stringify(relatedVulnerabilities.map(v => ({ id: v.id, title: v.title, score: v.score, severity: v.severity, affectedAsset: v.affectedAssetName, patchRecommendation: v.patchRecommendation, description: v.description })))
        : "No active vulnerabilities identified on related assets."}

      [GATHERED CONTEXT - MITRE ATT&CK MAPPINGS]
      ${relatedMitreMappings.length > 0 
        ? JSON.stringify(relatedMitreMappings.map(m => ({ tactic: m.tactic, technique: m.technique, id: m.technique_id })))
        : "No external mapping records."}
 
      Draft a highly detailed and structured response containing:
      1. executiveSummary: A high-level, stakeholders-facing overview.
      2. technicalAnalysis: Deep forensic threat mechanics analysis, firewall recommendations, payload context, and correlation with the gathered asset/vulnerability information.
      3. rootCauseAssessment: A rigorous assessment of the underlying root cause that enabled this threat.
      4. remediationPlan: Clear, numbered instructions and recommended actions to isolate, mitigate, and patch.
      5. riskRating: A precise evaluation of the threat's risk level (e.g. Critical, High, Medium, Low) based on asset criticality and vulnerability severity.

      Return the results in JSON format matching the schema exactly.`;

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              executiveSummary: { type: Type.STRING },
              technicalAnalysis: { type: Type.STRING },
              rootCauseAssessment: { type: Type.STRING },
              remediationPlan: { type: Type.STRING },
              riskRating: { type: Type.STRING }
            },
            required: ["executiveSummary", "technicalAnalysis", "rootCauseAssessment", "remediationPlan", "riskRating"]
          }
        }
      });

      if (response.text) {
        const parsed = JSON.parse(response.text.trim());
        if (parsed.executiveSummary) reportData.executiveSummary = parsed.executiveSummary;
        if (parsed.technicalAnalysis) reportData.technicalAnalysis = parsed.technicalAnalysis;
        if (parsed.rootCauseAssessment) reportData.rootCauseAssessment = parsed.rootCauseAssessment;
        if (parsed.remediationPlan) reportData.remediationPlan = parsed.remediationPlan;
        if (parsed.riskRating) reportData.riskRating = parsed.riskRating;
      }
    }

    const reportId = `rep-${Math.floor(400 + Math.random() * 600)}`;
    const newReport = await DatabaseService.createReport({
      id: reportId,
      title: `Incident Response Report: ${matchedAlert.title}`,
      alertId: matchedAlert.id,
      threatName: matchedAlert.title,
      severity: matchedAlert.severity,
      mitreMapping: matchedAlert.mitreAttack || (relatedMitreMappings.length > 0 ? { tactic: relatedMitreMappings[0].tactic, technique: relatedMitreMappings[0].technique, id: relatedMitreMappings[0].technique_id } : { tactic: "Defense Evasion", technique: "Obfuscated Files", id: "T1027" }),
      executiveSummary: reportData.executiveSummary,
      technicalDetails: reportData.technicalAnalysis,
      remediationPlan: reportData.remediationPlan,
      rootCauseAssessment: reportData.rootCauseAssessment,
      riskRating: reportData.riskRating,
      generatedBy: user.email,
      timestamp: new Date().toISOString()
    });

    return res.status(201).json(newReport);

  } catch (err) {
    console.error("Failed to generate report via Gemini:", err);
    return res.status(500).json({ error: "Failed to generate AI incident report successfully." });
  }
});

// CSV/JSON Export endpoint for alerts/reports
app.get("/api/export", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });

  // Enforce RBAC rules: Ensure authenticated Admin and Analyst users can export reports successfully.
  if (user.role !== "Admin" && user.role !== "Analyst") {
    return res.status(403).json({ error: "Forbidden: Export permission is restricted to Admin and Analyst roles." });
  }

  const { type, format } = req.query;

  if (type === "alerts") {
    const alertsList = await DatabaseService.getAlerts();
    const alerts = alertsList.filter(a => user.role === "Admin" || a.tenantId === user.tenantId);
    if (format === "csv") {
      let csv = "ID,Title,Severity,Category,Timestamp,Source IP,Dest IP,Status,MITRE Tactic\n";
      alerts.forEach(a => {
        const cleanTitle = (a.title || "").replace(/"/g, '""');
        csv += `"${a.id}","${cleanTitle}","${a.severity || ""}","${a.category || ""}","${a.timestamp || ""}","${a.sourceIp || ""}","${a.destIp || ""}","${a.status || ""}","${a.mitreAttack?.tactic || "N/A"}"\n`;
      });
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=secassist_alerts.csv");
      return res.send(csv);
    }
    return res.json(alerts);
  } else if (type === "reports") {
    const reports = await DatabaseService.getReports();
    if (format === "csv") {
      let csv = "ID,Title,Threat Name,Severity,Tactic,Technique,ID,Generated By,Timestamp,Root Cause Assessment,Risk Rating\n";
      reports.forEach(r => {
        const cleanTitle = (r.title || "").replace(/"/g, '""');
        const cleanThreatName = (r.threatName || "").replace(/"/g, '""');
        const cleanRootCause = (r.rootCauseAssessment || "").replace(/"/g, '""');
        const cleanRiskRating = (r.riskRating || "").replace(/"/g, '""');
        csv += `"${r.id}","${cleanTitle}","${cleanThreatName}","${r.severity || ""}","${r.mitreMapping?.tactic || ""}","${r.mitreMapping?.technique || ""}","${r.mitreMapping?.id || ""}","${r.generatedBy || ""}","${r.timestamp || ""}","${cleanRootCause}","${cleanRiskRating}"\n`;
      });
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=secassist_reports.csv");
      return res.send(csv);
    }
    return res.json(reports);
  }

  return res.status(400).json({ error: "Invalid export target." });
});

// MITRE ATT&CK Enterprise Matrix Data Endpoint
app.get("/api/mitre/matrix", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  return res.json(MITRE_ATTACK_MATRIX);
});

// --- NEW EXTENDED SOC PLATFORM API ENDPOINTS ---

// 1. Asset Inventory
app.get("/api/assets", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  const assets = await DatabaseService.getAssets();
  return res.json(assets);
});

app.post("/api/assets", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  if (user.role === "Viewer") return res.status(403).json({ error: "Forbidden: Viewer permission insufficient." });

  const { name, type, ipAddress, os, criticality, owner, cloudProvider } = req.body;
  if (!name || !type || !ipAddress || !os || !criticality) {
    return res.status(400).json({ error: "Missing required asset parameters." });
  }

  const newAsset = await DatabaseService.createAsset({
    name,
    type,
    ipAddress,
    os,
    criticality,
    status: "Online",
    owner: owner || user.email,
    cloudProvider,
    activeAlertsCount: 0,
    lastSeen: new Date().toISOString()
  });

  return res.status(201).json(newAsset);
});

app.patch("/api/assets/:id", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  if (user.role === "Viewer") return res.status(403).json({ error: "Forbidden." });

  const { id } = req.params;
  const { status, criticality } = req.body;

  const updatedAsset = await DatabaseService.updateAsset(id, { status, criticality });
  if (!updatedAsset) return res.status(404).json({ error: "Asset not found." });

  return res.json(updatedAsset);
});

// 2. Vulnerability Management
app.get("/api/vulnerabilities", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  const vulnerabilities = await DatabaseService.getVulnerabilities();
  return res.json(vulnerabilities);
});

app.patch("/api/vulnerabilities/:id", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  if (user.role === "Viewer") return res.status(403).json({ error: "Forbidden." });

  const { id } = req.params;
  const { status } = req.body;

  const updatedVuln = await DatabaseService.updateVulnerability(id, { status });
  if (!updatedVuln) return res.status(404).json({ error: "Vulnerability not found." });

  return res.json(updatedVuln);
});

// 3. Security Knowledge Graph (Dynamic Node-Link Builder)
app.get("/api/knowledge-graph", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });

  const [users, assets, alerts, reports, threats] = await Promise.all([
    DatabaseService.getUsers(),
    DatabaseService.getAssets(),
    DatabaseService.getAlerts(),
    DatabaseService.getReports(),
    DatabaseService.getThreatIntelligence()
  ]);
  
  const nodes: any[] = [];
  const links: any[] = [];
  const addedNodeIds = new Set<string>();

  const addNode = (id: string, label: string, type: string, severity?: string, details?: any) => {
    if (!addedNodeIds.has(id)) {
      nodes.push({ id, label, type, severity, details });
      addedNodeIds.add(id);
    }
  };

  const addLink = (source: string, target: string, label: string) => {
    // Only link if both endpoints exist (or will exist)
    links.push({ source, target, label });
  };

  // 1. Users
  users.forEach(u => {
    addNode(`user-${u.email}`, u.name, "user", undefined, { role: u.role, email: u.email });
  });

  // 2. Assets (Devices)
  assets.forEach(a => {
    addNode(`device-${a.id}`, a.name, "device", a.criticality, { ip: a.ipAddress, os: a.os, type: a.type });
  });

  // 3. Alerts
  const activeAlerts = alerts.filter(a => user.role === "Admin" || a.tenantId === user.tenantId);
  activeAlerts.forEach(al => {
    addNode(`alert-${al.id}`, al.title, "alert", al.severity, { category: al.category, status: al.status });

    // Link alerts to assets based on matching IP or exact name
    const targetAsset = assets.find(a => 
      a.ipAddress === al.sourceIp || 
      a.ipAddress === al.destIp || 
      (al.destIp && a.name.toLowerCase() === al.destIp.toLowerCase())
    );
    if (targetAsset) {
      addLink(`alert-${al.id}`, `device-${targetAsset.id}`, "targets");
    }

    // Link alerts to assigned user
    if (al.assignedTo) {
      addLink(`alert-${al.id}`, `user-${al.assignedTo}`, "assigned_to");
    }
  });

  // 4. Incident Reports
  reports.forEach(rep => {
    addNode(`incident-${rep.id}`, rep.title, "incident", rep.severity, { generatedBy: rep.generatedBy, date: rep.timestamp });
    
    if (rep.alertId) {
      addLink(`incident-${rep.id}`, `alert-${rep.alertId}`, "consolidates");
    }
    addLink(`incident-${rep.id}`, `user-${rep.generatedBy}`, "authored_by");
  });

  // 5. Threat Intel
  threats.forEach(t => {
    addNode(`threat-${t.id}`, t.name, "threat", t.severity, { code: t.mitreMapping?.id });

    // Link threats to affected assets
    assets.forEach(a => {
      const isAffected = t.affectedAssets && t.affectedAssets.some(aa => 
        aa.toLowerCase().includes(a.type.toLowerCase()) || 
        a.name.toLowerCase().includes(aa.toLowerCase())
      );
      if (isAffected) {
        addLink(`threat-${t.id}`, `device-${a.id}`, "vulnerable_asset_class");
      }
    });

    // Link alerts to threat intel if matching MITRE ID or severity / category details
    activeAlerts.forEach(al => {
      if (al.mitreAttack && al.mitreAttack.id === t.mitreMapping?.id) {
        addLink(`alert-${al.id}`, `threat-${t.id}`, "classified_by");
      }
    });
  });

  return res.json({ nodes, links });
});

// 4. Threat Hunting Query Workbench
app.get("/api/threat-hunting/search", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });

  const query = String(req.query.query || "").trim().toLowerCase();

  const [assets, users, alerts, logs] = await Promise.all([
    DatabaseService.getAssets(),
    DatabaseService.getUsers(),
    DatabaseService.getAlerts(),
    DatabaseService.getAuditLogs()
  ]);

  if (!query) {
    return res.json({
      hosts: [],
      users: [],
      alerts: [],
      timeline: [],
      correlation: { score: "Low", description: "Empty hunt criteria." }
    });
  }

  // Find matching assets (hosts)
  const matchedAssets = assets.filter(a => 
    a.name.toLowerCase().includes(query) || 
    a.ipAddress.toLowerCase().includes(query) ||
    a.os.toLowerCase().includes(query)
  );

  // Find matching users
  const matchedUsers = users.filter(u => 
    u.name.toLowerCase().includes(query) || 
    u.email.toLowerCase().includes(query)
  );

  // Find matching alerts
  const matchedAlerts = alerts.filter(a => 
    (user.role === "Admin" || a.tenantId === user.tenantId) && (
      a.title.toLowerCase().includes(query) ||
      (a.description && a.description.toLowerCase().includes(query)) ||
      (a.sourceIp && a.sourceIp.toLowerCase().includes(query)) ||
      (a.destIp && a.destIp.toLowerCase().includes(query)) ||
      (a.mitreAttack?.id && a.mitreAttack.id.toLowerCase().includes(query))
    )
  );

  // Reconstruct unified timeline of events
  const timeline: any[] = [];

  // Add parsed SSH failed logins matching term if queried
  logs.forEach(log => {
    if ((log.rawContent && log.rawContent.toLowerCase().includes(query)) || log.filename.toLowerCase().includes(query)) {
      timeline.push({
        timestamp: log.timestamp,
        type: "log_event",
        title: `Syslog Flagged: ${log.filename}`,
        description: `Deep forensic indicators matched raw search pattern: "${query}" in uploaded SOC logs.`,
        severity: (log.analysis as any)?.threatLevel || "Medium"
      });
    }
  });

  // Add alerts related timeline events
  matchedAlerts.forEach(al => {
    timeline.push({
      timestamp: al.timestamp,
      type: "security_alert",
      title: al.title,
      description: `${al.severity} risk security alert detected from ${al.sourceIp} targeting ${al.destIp}. Status: ${al.status}.`,
      severity: al.severity
    });
  });

  // Sort timeline chronologically descending
  timeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  // Dynamic threat correlation engine analysis logic
  let correlationScore = "Low";
  let correlationDescription = `Threat hunt search query processed. No multi-stage correlation indicators matched the signature baseline.`;

  const hasTorExitMatch = query.includes("185.220") || query.includes("185.112") || query.includes("tor") || matchedAlerts.some(a => (a.description && a.description.toLowerCase().includes("tor")) || a.title.toLowerCase().includes("beacon"));
  const hasCredentialMatch = query.includes("admin") || query.includes("brute") || query.includes("password") || matchedAlerts.some(a => a.category === "Credential Access");
  const hasMalwareMatch = query.includes("lockbit") || query.includes("ransomware") || query.includes("beaconing") || matchedAlerts.some(a => a.category === "Malware");

  if (hasTorExitMatch && hasCredentialMatch && hasMalwareMatch) {
    correlationScore = "Critical";
    correlationDescription = "CORRELATION TRIGGERED: Outbound Tor-exit beaconing detected in close temporal sequence with Active Directory Administrator brute-force and local ransomware payload detonation commands. Immediate enterprise lockout advised.";
  } else if ((hasTorExitMatch && hasCredentialMatch) || (hasTorExitMatch && hasMalwareMatch)) {
    correlationScore = "High";
    correlationDescription = "HIGH RISK CORRELATION: Perimeter Tor network relays correlated with repeated unauthorized authentication failures and anomalous payload execution behaviors on critical finance assets.";
  } else if (matchedAlerts.length > 1) {
    correlationScore = "Medium";
    correlationDescription = `Multiple matching alert indicators detected on host assets. Lateral progression and credential scraping suspected.`;
  }

  return res.json({
    hosts: matchedAssets,
    users: matchedUsers,
    alerts: matchedAlerts,
    timeline,
    correlation: {
      score: correlationScore,
      description: correlationDescription
    }
  });
});

// 5. AI Threat Investigation Agent
app.post("/api/ai-agent/investigate", async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized." });
  if (user.role === "Viewer") return res.status(403).json({ error: "Forbidden." });

  const { alertId } = req.body;
  if (!alertId) {
    return res.status(400).json({ error: "alertId is required to invoke the threat agent." });
  }

  const alerts = await DatabaseService.getAlerts();
  const alert = alerts.find(a => a.id === alertId);
  if (!alert) {
    return res.status(404).json({ error: "Alert context not found." });
  }

  try {
    // 100% Real-time dynamic response generation
    let investigationData: any = null;

    if (ai) {
      console.log(`AI Investigation Agent invoking Gemini Model 'gemini-3.5-flash' for Alert: ${alert.title}`);
      const prompt = `You are a Tier-3 Senior Threat Hunter AI Agent at an enterprise SOC. Investigate the following active security alert:
      
      Alert ID: ${alert.id}
      Alert Title: ${alert.title}
      Severity: ${alert.severity}
      Category: ${alert.category}
      Source Host/IP: ${alert.sourceIp}
      Destination Host/IP: ${alert.destIp}
      Alert Telemetry Description: ${alert.description}
      MITRE ATT&CK Info: ${alert.mitreAttack ? JSON.stringify(alert.mitreAttack) : "N/A"}

      Perform a logical timeline forensic reconstruction and compile the following:
      1. Dynamic logs (Simulated agent thinking steps illustrating investigation progression, e.g. "Querying IP reputation...", "Verifying parent processes...", minimum 4 logs).
      2. Collected evidence (At least 3 evidence objects detailing specific suspicious findings. Each evidence must have: type ['process', 'network', 'user', 'file'], name, description, and severity ['Suspicious', 'Malicious', 'Benign']).
      3. Cyber Findings (At least 3 analytical bullet points explaining the root cause, exfiltration traces, and lateral traversals).
      4. Targeted Remediation actions.

      Return the result in JSON format matching the specified schema.`;

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              logs: {
                type: Type.ARRAY,
                items: { type: Type.STRING }
              },
              evidence: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: { type: Type.STRING, description: "Must be: process, network, user, or file" },
                    name: { type: Type.STRING },
                    description: { type: Type.STRING },
                    severity: { type: Type.STRING, description: "Must be: Suspicious, Malicious, or Benign" }
                  },
                  required: ["type", "name", "description", "severity"]
                }
              },
              findings: {
                type: Type.ARRAY,
                items: { type: Type.STRING }
              },
              remediationSteps: {
                type: Type.ARRAY,
                items: { type: Type.STRING }
              }
            },
            required: ["logs", "evidence", "findings", "remediationSteps"]
          }
        }
      });

      if (response.text) {
        investigationData = JSON.parse(response.text.trim());
      }
    }

    // Rules-based local engine fallback for offline demonstration or failed requests
    if (!investigationData) {
      console.log("No Gemini connection or API failed. Executing local threat agent rules engine.");
      
      const isRansomware = alert.category.toLowerCase().includes("malware") || alert.title.toLowerCase().includes("ransomware") || alert.title.toLowerCase().includes("beaconing");
      const isCredBrute = alert.category.toLowerCase().includes("credential") || alert.title.toLowerCase().includes("brute") || alert.title.toLowerCase().includes("login");

      if (isRansomware) {
        investigationData = {
          logs: [
            "AI Agent initialized. Pulling active network state for remote IP " + alert.destIp,
            "Scanning running processes on host endpoint matching " + alert.sourceIp,
            "Detected anomalous process 'svchost_backup.exe' spawned by system cmd.exe",
            "Checking local file systems for encrypted metadata and ransomware file markers",
            "Querying threat intelligence database for C2 IP reputation history. MATCH FOUND: LockBit 3.0 C2 Proxy"
          ],
          evidence: [
            { type: "process", name: "svchost_backup.exe", description: "Unsigned binary running with high administrative privileges. Spawned from unauthorized temporary temp folder.", severity: "Malicious" },
            { type: "network", name: "Outbound HTTPS Connection to " + alert.destIp, description: "Repeated packets transferred with fixed intervals (30s jitter), matching C2 beacon command telemetry.", severity: "Malicious" },
            { type: "file", name: "C:\\Users\\Administrator\\Desktop\\README.txt", description: "Ransomware encryption notice found in desktop root path.", severity: "Suspicious" }
          ],
          findings: [
            "Root Cause identified: Detonation of an unsigned lateral ransomware payload (svchost_backup.exe) on the target server system.",
            "Network analysis confirms continuous command and control handshakes. Data leakage of active folder directory assets is highly suspected.",
            "Active Directory administrator credentials have been compromised through initial domain controller credential scrapings."
          ],
          remediationSteps: [
            "Initiate isolation of endpoint " + alert.sourceIp + " from the enterprise internal network.",
            "Revoke all active Active Directory administrator password hashes and API login keys.",
            "Block IP address " + alert.destIp + " at the corporate perimeter firewall level.",
            "Restore server directory configuration from offsite immutable backup servers."
          ]
        };
      } else if (isCredBrute) {
        investigationData = {
          logs: [
            "AI Agent initialized. Scanning auth.log files for brute-force signatures",
            "Correlating login timestamps with normal corporate shifts. Atypical hourly logins flagged",
            "Querying Active Directory account status for user 'Administrator'. Account locked out due to password failure limits",
            "Querying IP geolocation database for source IP " + alert.sourceIp + ". Geolocation: TOR exit node proxy server"
          ],
          evidence: [
            { type: "user", name: "Administrator", description: "Admin credentials targeted by automated dictionary login attempt on Domain Controller.", severity: "Suspicious" },
            { type: "network", name: "Perimeter Brute-Force from " + alert.sourceIp, description: "Transfer of 450+ rapid failed password requests within 180 seconds followed by a single successful authentication event.", severity: "Malicious" },
            { type: "process", name: "cmd.exe (spawned by sshd)", description: "Administrative command shell opened directly from external proxy SSH connection.", severity: "Malicious" }
          ],
          findings: [
            "Credential Spraying targeted local system service managers to guess default root parameters.",
            "Authentication bypass succeeded on SSH listener. External agent successfully authenticated as Administrator.",
            "Local AD credentials harvested and cached offline for lateral propagation audits."
          ],
          remediationSteps: [
            "Revoke Active Directory session tokens for Administrator account immediately.",
            "Block attacker IP " + alert.sourceIp + " at perimeter firewalls.",
            "Disable SSH password-based login; enforce strong public-key cryptographic authentication."
          ]
        };
      } else {
        // General fallback
        investigationData = {
          logs: [
            "AI Agent initialized. Correlating security alert: " + alert.title,
            "Scanning local network sockets for anomalous connection threads",
            "Verifying user credentials and active policy rules",
            "Analysis complete. Compiling response findings."
          ],
          evidence: [
            { type: "network", name: "Port activity alert", description: "Unusual connection packets identified targeting critical resources.", severity: "Suspicious" }
          ],
          findings: [
            "Anomalous trigger events matched standard defensive scan baselines.",
            "No active lateral traversals or file system encryption signs detected on nearby subnets.",
            "Asset configurations are verified and firewall filtering acts normally."
          ],
          remediationSteps: [
            "Monitor server system log files for repetitive occurrences.",
            "Validate firewall rule settings and patch target systems with latest security advisory."
          ]
        };
      }
    }

    const investigationId = `inv-${Math.floor(500 + Math.random() * 500)}`;
    const newInvestigation = {
      id: investigationId,
      alertId: alert.id,
      alertTitle: alert.title,
      status: "Completed" as const,
      evidence: investigationData.evidence,
      findings: investigationData.findings,
      remediationSteps: investigationData.remediationSteps,
      timestamp: new Date().toISOString(),
      logs: investigationData.logs
    };

    aiInvestigations.unshift(newInvestigation);

    // Automatically transition the alert's status to 'Investigating' since AI is actively reviewing it
    await DatabaseService.updateAlert(alertId, { status: "Investigating" });

    return res.status(201).json(newInvestigation);

  } catch (err) {
    console.error("AI Investigation Agent failure:", err);
    return res.status(500).json({ error: "Threat Agent was unable to complete automated alert forensics." });
  }
});

// --- CLIENT SERVER CONFIG & STARTER BOOTSTRAP ---

async function startServer() {
  // Initialize the persistent database (or fallback database)
  await DatabaseService.initialize();

  // Vite integration
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`SecAssistAI full-stack enterprise platform running on http://localhost:${PORT}`);
  });
}

startServer();
