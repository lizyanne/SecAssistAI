import { MITRE_ATTACK_MATRIX } from "./data/mitreData";

// Initial seed data matching db.json
const DEFAULT_USERS = [
  { id: "u-1", name: "Sarah Connor", email: "admin@secassist.ai", role: "Admin", tenantId: "tenant-alpha" },
  { id: "u-2", name: "John Doe", email: "analyst@secassist.ai", role: "Analyst", tenantId: "tenant-alpha" },
  { id: "u-3", name: "Marcus Wright", email: "viewer@secassist.ai", role: "Viewer", tenantId: "tenant-alpha" },
  { id: "u-4", name: "Elena Rostova", email: "external@secassist.ai", role: "Analyst", tenantId: "tenant-beta" }
];

const DEFAULT_ALERTS = [
  {
    id: "alt-101",
    title: "Ransomware C2 Beaconing Detected",
    severity: "Critical",
    category: "Malware",
    timestamp: "2026-06-25T19:11:32.794Z",
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
    timestamp: "2026-06-25T16:11:32.794Z",
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
    timestamp: "2026-06-25T09:11:32.794Z",
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
    timestamp: "2026-06-24T21:11:32.794Z",
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
    timestamp: "2026-06-24T09:11:32.794Z",
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
];

const DEFAULT_LOGS = [
  {
    id: "log-201",
    filename: "auth_failures_ssh.log",
    uploadedBy: "analyst@secassist.ai",
    timestamp: "2026-06-25T18:11:32.794Z",
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
];

const DEFAULT_THREATS = [
  {
    id: "th-301",
    name: "LockBit 3.0 Ransomware Campaign",
    severity: "Critical",
    mitreMapping: {
      tactic: "Impact",
      technique: "Data Encrypted for Impact",
      id: "T1486"
    },
    explanation: "Active ransomware strain targeting Windows/Linux directories via customized GPO scripting. Beacons out on encrypted HTTPS channels.",
    remediation: "Ensure offsite immutable backups are validated. Disable lateral administrative shares (C$) where possible.",
    detectionSignature: "Outbound DNS requests resolving to *.lockbit.onion or related command and control web proxy IP addresses.",
    affectedAssets: [
      "Internal Domain Controllers",
      "Active Directory Servers",
      "User Workstations"
    ]
  },
  {
    id: "th-302",
    name: "Kerberoasting Exploit",
    severity: "High",
    mitreMapping: {
      tactic: "Credential Access",
      technique: "Steal or Forge Kerberos Tickets",
      id: "T1558"
    },
    explanation: "Attacker queries Active Directory SPNs and requests ticket-granting service (TGS) tickets offline to crack passwords.",
    remediation: "Enforce long passwords for service accounts (minimum 25 characters) or migrate to Group Managed Service Accounts (gMSA).",
    detectionSignature: "Event ID 4769 with RC4 encryption type (0x17) indicating vulnerable password cracking exposure.",
    affectedAssets: [
      "Active Directory Services",
      "Database Service Accounts"
    ]
  }
];

const DEFAULT_REPORTS = [
  {
    id: "rep-401",
    title: "Incident Report: Lockheed C2 Outbound Beaconing Activity",
    alertId: "alt-101",
    threatName: "LockBit C2 Beaconing Activity",
    severity: "Critical",
    mitreMapping: {
      tactic: "Command and Control",
      technique: "Application Layer Protocol: Web Protocols",
      id: "T1071.001"
    },
    executiveSummary: "On June 24, SecAssistAI detected a high-volume, highly persistent HTTP-beaconing threat emanating from the internal system 10.100.12.45. Analysis indicates LockBit ransomware payload beacon execution. Immediate isolation and host forensics are required.",
    technicalDetails: "The endpoint was found transferring periodic HTTP GET requests with structured base64 headers. Jitter matches the telemetry for LockBit proxy hosts. Network analysis confirmed connections to 185.112.144.12 on port 443.",
    remediationPlan: "1. Network-isolate endpoint 10.100.12.45 via EDR controller.\n2. Revoke active Active Directory credentials for compromised endpoints.\n3. Run a threat hunt on surrounding systems for lateral traversal artifacts.\n4. Re-image the target operating system.",
    rootCauseAssessment: "Lateral ingress or credential exploitation enabling Command and Control execution.",
    riskRating: "Critical",
    generatedBy: "admin@secassist.ai",
    timestamp: "2026-06-25T19:11:32.794Z"
  }
];

const DEFAULT_ASSETS = [
  {
    id: "ast-1",
    name: "AD-Domain-Controller",
    type: "Server",
    ipAddress: "10.100.1.4",
    os: "Windows Server 2022",
    criticality: "Critical",
    status: "Online",
    owner: "admin@secassist.ai",
    activeAlertsCount: 1,
    lastSeen: "2026-06-25T21:11:32.794Z"
  },
  {
    id: "ast-2",
    name: "WAF-Public-Web",
    type: "Server",
    ipAddress: "10.100.5.10",
    os: "Ubuntu Linux 22.04 LTS",
    criticality: "High",
    status: "Online",
    owner: "admin@secassist.ai",
    activeAlertsCount: 0,
    lastSeen: "2026-06-25T21:11:32.794Z"
  },
  {
    id: "ast-3",
    name: "Finance-WS-45",
    type: "Endpoint",
    ipAddress: "10.100.12.45",
    os: "Windows 11 Enterprise",
    criticality: "High",
    status: "Investigating",
    owner: "analyst@secassist.ai",
    activeAlertsCount: 1,
    lastSeen: "2026-06-25T21:11:32.794Z"
  },
  {
    id: "ast-4",
    name: "Dev-WS-89",
    type: "Endpoint",
    ipAddress: "10.100.12.89",
    os: "macOS Sequoia",
    criticality: "Medium",
    status: "Online",
    owner: "analyst@secassist.ai",
    activeAlertsCount: 0,
    lastSeen: "2026-06-25T21:11:32.794Z"
  },
  {
    id: "ast-5",
    name: "AWS-Prod-Kubernetes",
    type: "Cloud",
    ipAddress: "172.31.44.10",
    os: "Linux CoreOS",
    criticality: "Critical",
    status: "Online",
    owner: "admin@secassist.ai",
    cloudProvider: "AWS",
    activeAlertsCount: 1,
    lastSeen: "2026-06-25T21:11:32.794Z"
  }
];

const DEFAULT_VULNERABILITIES = [
  {
    id: "CVE-2024-3094",
    title: "XZ Utils Backdoor Vulnerability",
    score: 10,
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
    score: 10,
    severity: "Critical",
    affectedAssetId: "ast-1",
    affectedAssetName: "AD-Domain-Controller",
    status: "Open",
    patchRecommendation: "Upgrade Atlassian Confluence Server to versions 8.3.3+, 8.4.3+ or 8.5.2+ immediately.",
    publishedDate: "2023-10-04",
    description: "A privilege escalation vulnerability in Confluence Data Center and Server allowed unauthenticated attackers to create administrator accounts."
  }
];

// Helper to interact with LocalStorage
const getStored = (key: string, defaults: any) => {
  const item = localStorage.getItem(`sec_${key}`);
  if (!item) {
    localStorage.setItem(`sec_${key}`, JSON.stringify(defaults));
    return defaults;
  }
  return JSON.parse(item);
};

const setStored = (key: string, data: any) => {
  localStorage.setItem(`sec_${key}`, JSON.stringify(data));
};

// Check if we should activate the mock API interceptor
export function setupMockApi() {
  const isStaticHost = 
    window.location.hostname.endsWith("github.io") || 
    window.location.hostname.includes("pages.dev") ||
    window.location.hostname.includes("netlify") ||
    window.location.hostname.includes("vercel") ||
    window.location.search.includes("mock=true");

  if (!isStaticHost) {
    // Probe normal server to see if it responds. If it doesn't, activate mock as auto-recovery fallback.
    fetch("/api/auth/me")
      .catch((err) => {
        console.warn("Express backend seems unreachable. Auto-activating offline mock sandbox engine.", err);
        activateMockInterceptor();
      });
    return;
  }

  console.log("GitHub Pages/Static host detected. Injecting high-fidelity SOC mock API database interceptor.");
  activateMockInterceptor();
}

function activateMockInterceptor() {
  const originalFetch = window.fetch;

  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const urlString = typeof input === "string" ? input : (input instanceof URL ? input.toString() : input.url);
    
    // Only intercept requests directed to our back-end "/api/*"
    if (!urlString.includes("/api/")) {
      return originalFetch.apply(this, arguments as any);
    }

    // Add a small mock delay to make operations feel natural (simulating network roundtrip)
    await new Promise((resolve) => setTimeout(resolve, 150 + Math.random() * 150));

    try {
      // Decode Token / User Session Context from Header
      const authHeader = init?.headers ? (init.headers as any)["Authorization"] || "" : "";
      const currentToken = authHeader.replace("Bearer ", "").trim() || localStorage.getItem("secassist_token") || "";
      
      let currentUser: any = null;
      if (currentToken && currentToken.startsWith("mock-token-")) {
        const email = currentToken.replace("mock-token-", "");
        const users = getStored("users", DEFAULT_USERS);
        currentUser = users.find((u: any) => u.email === email) || null;
      }

      const parsedUrl = new URL(urlString, window.location.origin);
      const path = parsedUrl.pathname;
      const method = init?.method?.toUpperCase() || "GET";

      // Decode JSON body safely
      let body: any = {};
      if (init?.body && typeof init.body === "string") {
        try {
          body = JSON.parse(init.body);
        } catch (_) {}
      }

      // ==========================================
      // ROUTING SIMULATION
      // ==========================================

      // 1. POST /api/auth/login
      if (path === "/api/auth/login" && method === "POST") {
        const { email } = body;
        const users = getStored("users", DEFAULT_USERS);
        const user = users.find((u: any) => u.email === email);
        if (user) {
          return new Response(JSON.stringify({
            token: `mock-token-${user.email}`,
            user
          }), { status: 200, headers: { "Content-Type": "application/json" } });
        } else {
          return new Response(JSON.stringify({ error: "Access key/identity not found." }), { status: 401 });
        }
      }

      // POST /api/auth/register
      if (path === "/api/auth/register" && method === "POST") {
        const { name, email, role, tenantId } = body;
        if (!email || !name) {
          return new Response(JSON.stringify({ error: "Name and email are required." }), { status: 400 });
        }
        const users = getStored("users", DEFAULT_USERS);
        const existingUser = users.find((u: any) => u.email.toLowerCase() === email.toLowerCase());
        if (existingUser) {
          return new Response(JSON.stringify({ error: "Identity ID already registered." }), { status: 400 });
        }
        const newUser = {
          id: `u-${Math.floor(100 + Math.random() * 900)}`,
          name,
          email,
          role: role || "Analyst",
          tenantId: tenantId || "tenant-alpha"
        };
        users.push(newUser);
        setStored("users", users);
        return new Response(JSON.stringify({
          token: `mock-token-${newUser.email}`,
          user: newUser
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 2. GET /api/auth/me
      if (path === "/api/auth/me" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        return new Response(JSON.stringify({ user: currentUser }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 3. GET /api/dashboard/stats
      if (path === "/api/dashboard/stats" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });

        const alerts = getStored("alerts", DEFAULT_ALERTS).filter(
          (a: any) => currentUser.role === "Admin" || a.tenantId === currentUser.tenantId
        );

        const total = alerts.length;
        const critical = alerts.filter((a: any) => a.severity === "Critical").length;
        const high = alerts.filter((a: any) => a.severity === "High").length;
        const medium = alerts.filter((a: any) => a.severity === "Medium").length;
        const low = alerts.filter((a: any) => a.severity === "Low").length;

        const active = alerts.filter((a: any) => a.status !== "Resolved").length;
        const resolved = alerts.filter((a: any) => a.status === "Resolved").length;

        let baseScore = 25;
        const activeCritical = alerts.filter((a: any) => a.severity === "Critical" && a.status !== "Resolved").length;
        const activeHigh = alerts.filter((a: any) => a.severity === "High" && a.status !== "Resolved").length;
        const activeMed = alerts.filter((a: any) => a.severity === "Medium" && a.status !== "Resolved").length;

        baseScore += (activeCritical * 25) + (activeHigh * 15) + (activeMed * 5);
        const riskScore = Math.min(Math.max(baseScore, 10), 99);

        const timelineData = Array.from({ length: 5 }).map((_, idx) => {
          const day = new Date(Date.now() - 86400000 * (4 - idx)).toLocaleDateString("en-US", { month: "short", day: "numeric" });
          return {
            time: day,
            Critical: idx === 4 ? activeCritical : Math.max(0, critical - (4 - idx)),
            High: idx === 4 ? activeHigh : Math.max(0, high - Math.abs(2 - idx)),
            Medium: idx === 3 ? 2 : Math.max(1, medium - Math.abs(1 - idx)),
            Low: Math.max(1, low - idx)
          };
        });

        const tacticMap: Record<string, number> = {};
        alerts.forEach((a: any) => {
          if (a.mitreAttack) {
            tacticMap[a.mitreAttack.tactic] = (tacticMap[a.mitreAttack.tactic] || 0) + 1;
          }
        });

        const allTactics = ["Initial Access", "Execution", "Privilege Escalation", "Credential Access", "Command and Control", "Exfiltration"];
        const mitreHeatmap = allTactics.map(t => {
          const count = tacticMap[t] || 0;
          let color = "rgba(30, 41, 59, 0.4)";
          if (count > 2) color = "rgba(239, 68, 68, 0.8)";
          else if (count > 1) color = "rgba(249, 115, 22, 0.8)";
          else if (count > 0) color = "rgba(234, 179, 8, 0.8)";
          return { tactic: t, count, color };
        });

        const categories: Record<string, number> = {};
        alerts.forEach((a: any) => {
          categories[a.category] = (categories[a.category] || 0) + 1;
        });
        const categoryDistribution = Object.entries(categories).map(([name, value]) => ({ name, value }));

        return new Response(JSON.stringify({
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
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 4. GET /api/alerts
      if (path === "/api/alerts" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        
        let alerts = getStored("alerts", DEFAULT_ALERTS);
        alerts = alerts.filter((a: any) => currentUser.role === "Admin" || a.tenantId === currentUser.tenantId);

        const severity = parsedUrl.searchParams.get("severity");
        const status = parsedUrl.searchParams.get("status");
        const search = parsedUrl.searchParams.get("search");

        if (severity && severity !== "All") {
          alerts = alerts.filter((a: any) => a.severity === severity);
        }
        if (status && status !== "All") {
          alerts = alerts.filter((a: any) => a.status === status);
        }
        if (search) {
          const s = search.toLowerCase();
          alerts = alerts.filter((a: any) => 
            a.title.toLowerCase().includes(s) || 
            a.description.toLowerCase().includes(s) ||
            a.sourceIp.toLowerCase().includes(s) ||
            a.destIp.toLowerCase().includes(s)
          );
        }

        // Sort: newest first
        alerts.sort((a: any, b: any) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

        return new Response(JSON.stringify(alerts), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 5. POST /api/alerts (Live Attack Simulation injector)
      if (path === "/api/alerts" && method === "POST") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        
        const newAlert = {
          id: `alt-${Math.floor(200 + Math.random() * 800)}`,
          title: body.title || "Simulated Security Incident Triggered",
          severity: body.severity || "High",
          category: body.category || "Defense Evasion",
          timestamp: new Date().toISOString(),
          sourceIp: body.sourceIp || "10.100.12.91",
          destIp: body.destIp || "10.100.1.4",
          status: "Active",
          description: body.description || "Simulated breach payload query execution.",
          mitreAttack: {
            tactic: body.mitreTactic || "Execution",
            technique: body.mitreTechnique || "Command and Scripting Interpreter",
            id: body.mitreId || "T1059"
          },
          assignedTo: currentUser.email,
          tenantId: currentUser.tenantId
        };

        const alerts = getStored("alerts", DEFAULT_ALERTS);
        alerts.unshift(newAlert);
        setStored("alerts", alerts);

        return new Response(JSON.stringify(newAlert), { status: 201, headers: { "Content-Type": "application/json" } });
      }

      // 6. PATCH /api/alerts/:id (Update triage status / analyst assignment)
      if (path.startsWith("/api/alerts/") && method === "PATCH") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const parts = path.split("/");
        const alertId = parts[parts.length - 1];

        const alerts = getStored("alerts", DEFAULT_ALERTS);
        const idx = alerts.findIndex((a: any) => a.id === alertId);

        if (idx !== -1) {
          if (body.status) alerts[idx].status = body.status;
          if (body.assignedTo !== undefined) alerts[idx].assignedTo = body.assignedTo;
          setStored("alerts", alerts);
          return new Response(JSON.stringify(alerts[idx]), { status: 200, headers: { "Content-Type": "application/json" } });
        } else {
          return new Response(JSON.stringify({ error: "Alert not found" }), { status: 404 });
        }
      }

      // 7. GET /api/logs
      if (path === "/api/logs" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const logs = getStored("logs", DEFAULT_LOGS);
        return new Response(JSON.stringify(logs), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 8. POST /api/logs/upload (Log upload analyzer simulation)
      if (path === "/api/logs/upload" && method === "POST") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        if (currentUser.role === "Viewer") return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 });

        const { filename, content } = body;
        const parsedLines = content.split("\n").filter((l: string) => l.trim().length > 0).length;
        const logId = `log-${Math.floor(202 + Math.random() * 800)}`;

        // Analyze content locally and generate a smart heuristic security report
        let threatLevel = "Low";
        let threatName = "Standard Server Auditing Report";
        let explanation = "Our heuristic engine scanned the logs and found typical user activity with no significant threat indicators.";
        let remediationSteps = ["Continue regular audit reviews.", "Ensure log shipping retention parameters match standards."];
        let mitreMapping = { tactic: "Defense Evasion", technique: "Indicator Removal", id: "T1070" };
        let suspiciousIndicators: string[] = [];

        const lowerContent = content.toLowerCase();
        if (lowerContent.includes("failed password") || lowerContent.includes("invalid user") || lowerContent.includes("sshd")) {
          threatLevel = "High";
          threatName = "Brute-Force SSH Auth Guessing Surge";
          explanation = "Detected multiple failed SSH login entries with sequential execution windows from a single client segment attempting root access.";
          remediationSteps = [
            "Deactivate remote password-based access in sshd_config.",
            "Integrate rate-limiting or security groups to isolate SSH ports.",
            "Verify SSH keys for active admins."
          ];
          mitreMapping = { tactic: "Credential Access", technique: "Brute Force: Password Guessing", id: "T1110.001" };
          suspiciousIndicators = ["Failed password for root", "sshd[invalid]", "Sequential failed attempts"];
        } else if (lowerContent.includes("union select") || lowerContent.includes("select") || lowerContent.includes("sqlmap") || lowerContent.includes("--")) {
          threatLevel = "Critical";
          threatName = "Web SQL Injection Database Exfiltration Attempt";
          explanation = "Database query command operators ('UNION SELECT') were detected inside request parameters matching common SQL Injection scanners.";
          remediationSteps = [
            "Deploy Web Application Firewall query regex matching blocks.",
            "Sanitize incoming API variables using parameterized statements.",
            "Restrict database user privileges to reading minimum tables."
          ];
          mitreMapping = { tactic: "Initial Access", technique: "Exploit Public-Facing Application", id: "T1190" };
          suspiciousIndicators = ["UNION SELECT", "sqlmap", "api/products?id="];
        } else if (lowerContent.includes("lockbit") || lowerContent.includes("beacon") || lowerContent.includes(".onion")) {
          threatLevel = "Critical";
          threatName = "LockBit ransomware network proxy beaconing";
          explanation = "EDR telemetry matched outbound recurring patterns to domain resolving servers linked with LockBit ransomware campaign mirrors.";
          remediationSteps = [
            "Isolate the machine immediately using the EDR dashboard.",
            "Clear DNS caches and isolate related segment IPs.",
            "Validate offline backup copies for safe system restore."
          ];
          mitreMapping = { tactic: "Command and Control", technique: "Application Layer Protocol: DNS Request Encoding", id: "T1071.004" };
          suspiciousIndicators = ["domain=lockbit-update-mirror.onion", "Resolved IP outbound"];
        }

        const newLog = {
          id: logId,
          filename,
          uploadedBy: currentUser.email,
          timestamp: new Date().toISOString(),
          parsedCount: parsedLines,
          status: "Analyzed",
          rawContent: content,
          analysis: {
            threatLevel,
            threatName,
            explanation,
            remediationSteps,
            mitreMapping,
            suspiciousIndicators
          }
        };

        const logs = getStored("logs", DEFAULT_LOGS);
        logs.unshift(newLog);
        setStored("logs", logs);

        // Also push a simulated matching alert in response
        const newAlert = {
          id: `alt-${Math.floor(200 + Math.random() * 800)}`,
          title: `Log-detected: ${threatName}`,
          severity: threatLevel as any,
          category: mitreMapping.tactic,
          timestamp: new Date().toISOString(),
          sourceIp: "10.100.12.45",
          destIp: "185.112.144.12",
          status: "Active",
          description: explanation,
          mitreAttack: mitreMapping,
          assignedTo: currentUser.email,
          tenantId: currentUser.tenantId
        };
        const alerts = getStored("alerts", DEFAULT_ALERTS);
        alerts.unshift(newAlert);
        setStored("alerts", alerts);

        return new Response(JSON.stringify({ log: newLog, analysis: newLog.analysis }), { status: 201, headers: { "Content-Type": "application/json" } });
      }

      // 9. GET /api/threats
      if (path === "/api/threats" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const threats = getStored("threats", DEFAULT_THREATS);
        return new Response(JSON.stringify(threats), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 10. POST /api/threats (Manual bulletin posting)
      if (path === "/api/threats" && method === "POST") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        
        const newThreat = {
          id: `th-${Math.floor(300 + Math.random() * 700)}`,
          name: body.name || "Custom Threat Advisory",
          severity: body.severity || "High",
          mitreMapping: {
            tactic: body.tactic || "Credential Access",
            technique: body.technique || "Custom Technical Activity",
            id: body.id || "T1000"
          },
          explanation: body.explanation || "Advisory reported by regional network ops center.",
          remediation: body.remediation || "Apply latest patch sets and review endpoint credentials.",
          detectionSignature: "Continuous lateral admin sweeps on critical infrastructure.",
          affectedAssets: ["Internal Domain Controllers", "Windows Endpoints"]
        };

        const threats = getStored("threats", DEFAULT_THREATS);
        threats.unshift(newThreat);
        setStored("threats", threats);

        return new Response(JSON.stringify(newThreat), { status: 201, headers: { "Content-Type": "application/json" } });
      }

      // 11. GET /api/reports
      if (path === "/api/reports" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const reports = getStored("reports", DEFAULT_REPORTS);
        return new Response(JSON.stringify(reports), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 12. POST /api/reports/generate (Generate formal response report)
      if (path === "/api/reports/generate" && method === "POST") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        if (currentUser.role === "Viewer") return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 });

        const { alertId } = body;
        const alerts = getStored("alerts", DEFAULT_ALERTS);
        const matchedAlert = alerts.find((a: any) => a.id === alertId);

        if (!matchedAlert) {
          return new Response(JSON.stringify({ error: "Alert context not found." }), { status: 404 });
        }

        const reportId = `rep-${Math.floor(400 + Math.random() * 600)}`;
        const newReport = {
          id: reportId,
          title: `Incident Response Report: ${matchedAlert.title}`,
          alertId: matchedAlert.id,
          threatName: matchedAlert.title,
          severity: matchedAlert.severity,
          mitreMapping: matchedAlert.mitreAttack || { tactic: "Defense Evasion", technique: "Obfuscated Files", id: "T1027" },
          executiveSummary: `On ${new Date(matchedAlert.timestamp).toLocaleString()}, a security threat classified as ${matchedAlert.severity} was identified: ${matchedAlert.title}. Our automated agent isolated the anomalous egress.`,
          technicalDetails: `A complete forensic analysis revealed ${matchedAlert.description}. The connection originated from host ${matchedAlert.sourceIp} and linked directly to exfiltration vector ${matchedAlert.destIp}. We confirmed lateral credential-stuffing sweeps.`,
          remediationPlan: `1. Isolate associate system groups linked to source address ${matchedAlert.sourceIp} immediately.\n2. Force change of all enterprise AD user account passwords.\n3. Verify integrity of endpoint firewall systems.`,
          rootCauseAssessment: `Weak authentication on network ingress ports or compromise of admin credentials enabling lateral exfiltration.`,
          riskRating: matchedAlert.severity,
          generatedBy: currentUser.email,
          timestamp: new Date().toISOString()
        };

        const reports = getStored("reports", DEFAULT_REPORTS);
        reports.unshift(newReport);
        setStored("reports", reports);

        return new Response(JSON.stringify(newReport), { status: 201, headers: { "Content-Type": "application/json" } });
      }

      // 13. GET /api/export
      if (path === "/api/export" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const type = parsedUrl.searchParams.get("type") || "alerts";
        
        let csv = "";
        if (type === "alerts") {
          const alerts = getStored("alerts", DEFAULT_ALERTS);
          csv = "id,title,severity,status,timestamp,sourceIp,destIp\n" + 
            alerts.map((a: any) => `${a.id},"${a.title}",${a.severity},${a.status},${a.timestamp},${a.sourceIp},${a.destIp}`).join("\n");
        } else {
          const reports = getStored("reports", DEFAULT_REPORTS);
          csv = "id,title,severity,threatName,generatedBy,timestamp\n" + 
            reports.map((r: any) => `${r.id},"${r.title}",${r.severity},"${r.threatName}",${r.generatedBy},${r.timestamp}`).join("\n");
        }

        const blob = new Blob([csv], { type: "text/csv" });
        return new Response(blob, {
          status: 200,
          headers: {
            "Content-Type": "text/csv",
            "Content-Disposition": `attachment; filename="secassist_${type}.csv"`
          }
        });
      }

      // 14. GET /api/mitre/matrix
      if (path === "/api/mitre/matrix" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        
        // Build dynamic counts in tactics based on active alerts
        const alerts = getStored("alerts", DEFAULT_ALERTS).filter(
          (a: any) => currentUser.role === "Admin" || a.tenantId === currentUser.tenantId
        );
        
        const matrixCopy = JSON.parse(JSON.stringify(MITRE_ATTACK_MATRIX));
        matrixCopy.forEach((tactic: any) => {
          tactic.techniques.forEach((tech: any) => {
            const count = alerts.filter((a: any) => a.mitreAttack?.id === tech.id).length;
            tech.alertCount = count;
            tech.active = count > 0;
          });
        });

        return new Response(JSON.stringify(matrixCopy), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 15. GET /api/assets
      if (path === "/api/assets" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const assets = getStored("assets", DEFAULT_ASSETS);
        return new Response(JSON.stringify(assets), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 16. POST /api/assets
      if (path === "/api/assets" && method === "POST") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const newAsset = {
          id: `ast-${Math.floor(10 + Math.random() * 90)}`,
          name: body.name || "Unnamed Asset",
          type: body.type || "Endpoint",
          ipAddress: body.ipAddress || "10.100.12.10",
          os: body.os || "Linux Ubuntu",
          criticality: body.criticality || "Medium",
          status: "Online",
          owner: currentUser.email,
          activeAlertsCount: 0,
          lastSeen: new Date().toISOString()
        };
        const assets = getStored("assets", DEFAULT_ASSETS);
        assets.push(newAsset);
        setStored("assets", assets);
        return new Response(JSON.stringify(newAsset), { status: 201, headers: { "Content-Type": "application/json" } });
      }

      // 17. PATCH /api/assets/:id
      if (path.startsWith("/api/assets/") && method === "PATCH") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const parts = path.split("/");
        const assetId = parts[parts.length - 1];
        const assets = getStored("assets", DEFAULT_ASSETS);
        const idx = assets.findIndex((a: any) => a.id === assetId);
        if (idx !== -1) {
          if (body.status) assets[idx].status = body.status;
          if (body.criticality) assets[idx].criticality = body.criticality;
          setStored("assets", assets);
          return new Response(JSON.stringify(assets[idx]), { status: 200, headers: { "Content-Type": "application/json" } });
        }
        return new Response(JSON.stringify({ error: "Asset not found" }), { status: 404 });
      }

      // 18. GET /api/vulnerabilities
      if (path === "/api/vulnerabilities" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const vulnerabilities = getStored("vulnerabilities", DEFAULT_VULNERABILITIES);
        return new Response(JSON.stringify(vulnerabilities), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 19. PATCH /api/vulnerabilities/:id
      if (path.startsWith("/api/vulnerabilities/") && method === "PATCH") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const parts = path.split("/");
        const vulnId = parts[parts.length - 1];
        const vulnerabilities = getStored("vulnerabilities", DEFAULT_VULNERABILITIES);
        const idx = vulnerabilities.findIndex((v: any) => v.id === vulnId);
        if (idx !== -1) {
          if (body.status) vulnerabilities[idx].status = body.status;
          setStored("vulnerabilities", vulnerabilities);
          return new Response(JSON.stringify(vulnerabilities[idx]), { status: 200, headers: { "Content-Type": "application/json" } });
        }
        return new Response(JSON.stringify({ error: "Vulnerability not found" }), { status: 404 });
      }

      // GET /api/db-status (mock)
      if (path === "/api/db-status" && method === "GET") {
        return new Response(JSON.stringify({
          isPostgres: false,
          host: "GitHub Pages CDN / Local Storage Sandbox",
          database: "sec_local_cache"
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // POST /api/settings/reset-database (mock)
      if (path === "/api/settings/reset-database" && method === "POST") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        setStored("alerts", []);
        setStored("assets", []);
        setStored("vulnerabilities", []);
        setStored("logs", []);
        setStored("reports", []);
        setStored("threats", []);
        setStored("compliance", []);
        return new Response(JSON.stringify({ status: "success" }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // POST /api/settings/restore-defaults (mock)
      if (path === "/api/settings/restore-defaults" && method === "POST") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        localStorage.removeItem("sec_alerts");
        localStorage.removeItem("sec_assets");
        localStorage.removeItem("sec_vulnerabilities");
        localStorage.removeItem("sec_logs");
        localStorage.removeItem("sec_reports");
        localStorage.removeItem("sec_threats");
        localStorage.removeItem("sec_compliance");
        localStorage.removeItem("sec_users");
        return new Response(JSON.stringify({ status: "success" }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 20. GET /api/knowledge-graph
      if (path === "/api/knowledge-graph" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });

        const users = getStored("users", DEFAULT_USERS);
        const assets = getStored("assets", DEFAULT_ASSETS);
        const alerts = getStored("alerts", DEFAULT_ALERTS).filter(
          (a: any) => currentUser.role === "Admin" || a.tenantId === currentUser.tenantId
        );
        const reports = getStored("reports", DEFAULT_REPORTS);

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
          links.push({ source, target, label });
        };

        // Users
        users.forEach((u: any) => {
          addNode(`user-${u.email}`, u.name, "user", undefined, { role: u.role, email: u.email });
        });

        // Assets
        assets.forEach((a: any) => {
          addNode(`device-${a.id}`, a.name, "device", a.criticality, { ip: a.ipAddress, os: a.os, type: a.type });
        });

        // Alerts
        alerts.forEach((al: any) => {
          addNode(`alert-${al.id}`, al.title, "alert", al.severity, { category: al.category, status: al.status });

          const targetAsset = assets.find((a: any) => 
            a.ipAddress === al.sourceIp || 
            a.ipAddress === al.destIp || 
            (al.destIp && a.name.toLowerCase() === al.destIp.toLowerCase())
          );
          if (targetAsset) {
            addLink(`alert-${al.id}`, `device-${targetAsset.id}`, "targets");
          }

          if (al.assignedTo) {
            addLink(`alert-${al.id}`, `user-${al.assignedTo}`, "assigned_to");
          }
        });

        // Incident Reports
        reports.forEach((rep: any) => {
          addNode(`incident-${rep.id}`, rep.title, "incident", rep.severity, { generatedBy: rep.generatedBy, date: rep.timestamp });
          if (rep.alertId) {
            addLink(`incident-${rep.id}`, `alert-${rep.alertId}`, "consolidates");
          }
          addLink(`incident-${rep.id}`, `user-${rep.generatedBy}`, "authored_by");
        });

        return new Response(JSON.stringify({ nodes, links }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 21. GET /api/threat-hunting/search
      if (path === "/api/threat-hunting/search" && method === "GET") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });

        const query = String(parsedUrl.searchParams.get("query") || "").trim().toLowerCase();
        
        const assets = getStored("assets", DEFAULT_ASSETS);
        const users = getStored("users", DEFAULT_USERS);
        let alerts = getStored("alerts", DEFAULT_ALERTS);
        const logs = getStored("logs", DEFAULT_LOGS);

        alerts = alerts.filter((a: any) => currentUser.role === "Admin" || a.tenantId === currentUser.tenantId);

        if (!query) {
          return new Response(JSON.stringify({
            hosts: [],
            users: [],
            alerts: [],
            timeline: [],
            correlation: { score: "Low", description: "Empty hunt criteria." }
          }), { status: 200, headers: { "Content-Type": "application/json" } });
        }

        const matchedAssets = assets.filter((a: any) => 
          a.name.toLowerCase().includes(query) || 
          a.ipAddress.toLowerCase().includes(query) ||
          a.os.toLowerCase().includes(query)
        );

        const matchedUsers = users.filter((u: any) => 
          u.name.toLowerCase().includes(query) || 
          u.email.toLowerCase().includes(query)
        );

        const matchedAlerts = alerts.filter((a: any) => 
          a.title.toLowerCase().includes(query) ||
          (a.description && a.description.toLowerCase().includes(query)) ||
          (a.sourceIp && a.sourceIp.toLowerCase().includes(query)) ||
          (a.destIp && a.destIp.toLowerCase().includes(query)) ||
          (a.mitreAttack?.id && a.mitreAttack.id.toLowerCase().includes(query))
        );

        const timeline: any[] = [];

        logs.forEach((log: any) => {
          if ((log.rawContent && log.rawContent.toLowerCase().includes(query)) || log.filename.toLowerCase().includes(query)) {
            timeline.push({
              timestamp: log.timestamp,
              type: "log_event",
              title: `Syslog Flagged: ${log.filename}`,
              description: `Deep forensic indicators matched raw search pattern: "${query}" in uploaded SOC logs.`,
              severity: log.analysis?.threatLevel || "Medium"
            });
          }
        });

        matchedAlerts.forEach((al: any) => {
          timeline.push({
            timestamp: al.timestamp,
            type: "security_alert",
            title: al.title,
            description: `${al.severity} risk security alert detected from ${al.sourceIp} targeting ${al.destIp}. Status: ${al.status}.`,
            severity: al.severity
          });
        });

        timeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

        let correlationScore = "Low";
        let correlationDescription = `Threat hunt search query processed. No multi-stage correlation indicators matched the signature baseline.`;

        const hasTorExitMatch = query.includes("185.220") || query.includes("185.112") || query.includes("tor") || matchedAlerts.some((a: any) => (a.description && a.description.toLowerCase().includes("tor")) || a.title.toLowerCase().includes("beacon"));
        const hasCredentialMatch = query.includes("admin") || query.includes("brute") || query.includes("password") || matchedAlerts.some((a: any) => a.category === "Credential Access");
        const hasMalwareMatch = query.includes("lockbit") || query.includes("ransomware") || query.includes("beaconing") || matchedAlerts.some((a: any) => a.category === "Malware");

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

        return new Response(JSON.stringify({
          hosts: matchedAssets,
          users: matchedUsers,
          alerts: matchedAlerts,
          timeline,
          correlation: {
            score: correlationScore,
            description: correlationDescription
          }
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // 22. POST /api/ai-agent/investigate
      if (path === "/api/ai-agent/investigate" && method === "POST") {
        if (!currentUser) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        if (currentUser.role === "Viewer") return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 });

        const { alertId } = body;
        const alerts = getStored("alerts", DEFAULT_ALERTS);
        const alert = alerts.find((a: any) => a.id === alertId);

        if (!alert) {
          return new Response(JSON.stringify({ error: "Alert context not found." }), { status: 404 });
        }

        // Simulate expert Tier-3 hunt logs, findings, and remediation
        const logs = [
          `Querying reputation databases for external IP: ${alert.destIp || "remote_host"}...`,
          `Scanning active host processes on source IP segment ${alert.sourceIp}...`,
          `Verifying security token access anomalies on Active Directory Domain Controllers...`,
          `Aggregating correlation vectors. Matching MITRE technique ${alert.mitreAttack?.id || "N/A"}.`
        ];

        const evidence = [
          {
            type: "network",
            name: "Suspicious DNS Tunnel Packet Group",
            description: `Unusual base32-encoded outbound query payloads to server matching ${alert.destIp || "external C2 endpoint"}.`,
            severity: "Malicious"
          },
          {
            type: "process",
            name: "Anomalous PowerShell Script Launch",
            description: "Encrypted system-level payload triggered directly under user session boundaries, evading standard heuristics.",
            severity: "Suspicious"
          },
          {
            type: "user",
            name: "Privileged Access Overwrite",
            description: "System administrative roles reassigned from an anomalous external host origin with zero previous access logging.",
            severity: "Suspicious"
          }
        ];

        const findings = [
          "The compromised host system initiated high-frequency beacon communication patterns typical of Cobalt Strike/LockBit proxy servers.",
          "Prior to outbound tunneling, a credential brute-force event targeted corporate Active Directory servers from the same segment.",
          "Malicious lateral movement was traced across internal segments using obfuscated scripts designed to delete system logs."
        ];

        const remediationSteps = [
          `Network-isolate host ${alert.sourceIp} immediately using endpoint security client.`,
          `Add IP ${alert.destIp || "external relay"} to firewall perimeter ingress and egress blocks.`,
          "Revoke all active active-directory and cloud IAM security roles for compromised administrator logins.",
          "Run a cold system file system backup review and restore pristine OS images."
        ];

        return new Response(JSON.stringify({
          logs,
          evidence,
          findings,
          remediationSteps
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      // Catch-all 404
      return new Response(JSON.stringify({ error: `Not Found: ${path}` }), { status: 404 });
    } catch (err: any) {
      console.error("Mock API internal error:", err);
      return new Response(JSON.stringify({ error: err.message || "Mock API Server Error" }), { status: 500 });
    }
  };
}
