import { Pool } from "pg";
import fs from "fs";
import path from "path";

const DB_FILE = path.join(process.cwd(), "db.json");

// Define TypeScript interfaces for our 11 entities to ensure total type-safety
export interface Organization {
  id: string;
  name: string;
  domain?: string;
  created_at?: string | Date;
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  tenantId?: string;
  created_at?: string | Date;
}

export interface MitreMapping {
  tactic: string;
  technique: string;
  id: string; // T-code e.g. T1071.001
}

export interface Alert {
  id: string;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  category: string;
  timestamp: string;
  sourceIp: string;
  destIp: string;
  status: "Active" | "Investigating" | "Resolved";
  description: string;
  mitreAttack?: MitreMapping;
  assignedTo?: string;
  tenantId?: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  status: "Open" | "Investigating" | "Resolved";
  description: string;
  assignedTo?: string;
  tenantId?: string;
  createdAt?: string;
}

export interface Asset {
  id: string;
  name: string;
  type: string;
  ipAddress: string;
  os: string;
  criticality: "Critical" | "High" | "Medium" | "Low";
  status: "Online" | "Offline" | "Investigating";
  owner?: string;
  activeAlertsCount: number;
  lastSeen: string;
  cloudProvider?: string;
}

export interface Vulnerability {
  id: string;
  title: string;
  score: number;
  severity: "Critical" | "High" | "Medium" | "Low";
  affectedAssetId: string;
  affectedAssetName: string;
  status: "Open" | "In Progress" | "Patched";
  patchRecommendation: string;
  publishedDate: string;
  description: string;
}

export interface ThreatIntelligence {
  id: string;
  name: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  mitreMapping?: MitreMapping;
  explanation: string;
  remediation: string;
  detectionSignature: string;
  affectedAssets: string[];
}

export interface Report {
  id: string;
  title: string;
  alertId?: string;
  threatName?: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  mitreMapping?: MitreMapping;
  executiveSummary: string;
  technicalDetails: string;
  remediationPlan: string;
  generatedBy: string;
  timestamp: string;
  rootCauseAssessment?: string;
  riskRating?: string;
}

export interface AuditLog {
  id: string;
  filename: string;
  uploadedBy: string;
  timestamp: string;
  parsedCount: number;
  status: "Pending" | "Analyzed" | "Failed";
  rawContent: string;
  analysis?: {
    threatLevel: "Critical" | "High" | "Medium" | "Low";
    threatName: string;
    explanation: string;
    remediationSteps: string[];
    mitreMapping?: MitreMapping;
    suspiciousIndicators: string[];
  };
}

export interface ComplianceRecord {
  id: string;
  framework: string;
  controlId: string;
  controlName: string;
  status: "Compliant" | "Non-Compliant" | "In Progress";
  maturityScore: number;
  evidence: string;
  lastAudited: string;
}

export interface MitreMappingEntity {
  id: string;
  tactic: string;
  technique: string;
  technique_id: string;
  entity_type: string;
  entity_id: string;
}

// Initial realistic database fallback structure
const initialFallbackDatabase = {
  organizations: [
    { id: "tenant-alpha", name: "SecAssistAI HQ", domain: "secassist.ai" }
  ] as Organization[],
  users: [
    { id: "u-1", name: "Sarah Connor", email: "admin@secassist.ai", role: "Admin", tenantId: "tenant-alpha" },
    { id: "u-2", name: "John Doe", email: "analyst@secassist.ai", role: "Analyst", tenantId: "tenant-alpha" },
    { id: "u-3", name: "Marcus Wright", email: "viewer@secassist.ai", role: "Viewer", tenantId: "tenant-alpha" }
  ] as User[],
  alerts: [
    {
      id: "alt-101",
      title: "Ransomware C2 Beaconing Detected",
      severity: "Critical",
      category: "Malware",
      timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
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
      timestamp: new Date(Date.now() - 3600000 * 5).toISOString(),
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
      timestamp: new Date(Date.now() - 3600000 * 12).toISOString(),
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
      timestamp: new Date(Date.now() - 3600000 * 24).toISOString(),
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
      timestamp: new Date(Date.now() - 3600000 * 36).toISOString(),
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
  ] as Alert[],
  incidents: [
    {
      id: "inc-501",
      title: "Critical Production Outpost LockBit Exposure",
      severity: "Critical",
      status: "Investigating",
      description: "A critical LockBit ransomware beacon was traced to endpoint ast-3 (Finance-WS-45). Immediate EDR containment pending.",
      assignedTo: "analyst@secassist.ai",
      tenantId: "tenant-alpha",
      createdAt: new Date(Date.now() - 3600000).toISOString()
    },
    {
      id: "inc-502",
      title: "AD Account Lockout Avalanche",
      severity: "High",
      status: "Open",
      description: "Multiple domain controllers reporting lockouts for key service accounts.",
      assignedTo: "admin@secassist.ai",
      tenantId: "tenant-alpha",
      createdAt: new Date(Date.now() - 3600000 * 4).toISOString()
    }
  ] as Incident[],
  assets: [
    { id: "ast-1", name: "AD-Domain-Controller", type: "Server", ipAddress: "10.100.1.4", os: "Windows Server 2022", criticality: "Critical", status: "Online", owner: "admin@secassist.ai", activeAlertsCount: 1, lastSeen: new Date().toISOString() },
    { id: "ast-2", name: "WAF-Public-Web", type: "Server", ipAddress: "10.100.5.10", os: "Ubuntu Linux 22.04 LTS", criticality: "High", status: "Online", owner: "admin@secassist.ai", activeAlertsCount: 0, lastSeen: new Date().toISOString() },
    { id: "ast-3", name: "Finance-WS-45", type: "Endpoint", ipAddress: "10.100.12.45", os: "Windows 11 Enterprise", criticality: "High", status: "Investigating", owner: "analyst@secassist.ai", activeAlertsCount: 1, lastSeen: new Date().toISOString() },
    { id: "ast-4", name: "Dev-WS-89", type: "Endpoint", ipAddress: "10.100.12.89", os: "macOS Sequoia", criticality: "Medium", status: "Online", owner: "analyst@secassist.ai", activeAlertsCount: 0, lastSeen: new Date().toISOString() },
    { id: "ast-5", name: "AWS-Prod-Kubernetes", type: "Cloud", ipAddress: "172.31.44.10", os: "Linux CoreOS", criticality: "Critical", status: "Online", owner: "admin@secassist.ai", cloudProvider: "AWS", activeAlertsCount: 1, lastSeen: new Date().toISOString() }
  ] as Asset[],
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
  ] as Vulnerability[],
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
  ] as ThreatIntelligence[],
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
  ] as Report[],
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
  ] as AuditLog[],
  compliance: [
    { id: "cr-601", framework: "SOC2", controlId: "CC6.1", controlName: "Access Control and User Authentication", status: "Compliant", maturityScore: 90, evidence: "Configured enterprise SSO, password length requirements of 16+ chars, and mandatory MFA. Automated monitoring reviews occur every 12 hours.", lastAudited: new Date(Date.now() - 86400000).toISOString() },
    { id: "cr-602", framework: "SOC2", controlId: "CC7.1", controlName: "Vulnerability Management", status: "In Progress", maturityScore: 75, evidence: "Daily automated container scans via SecAssistAI configured. Open CVE tracking dashboard updated live.", lastAudited: new Date(Date.now() - 86400000 * 2).toISOString() },
    { id: "cr-603", framework: "ISO27001", controlId: "A.12.6.1", controlName: "Management of Technical Vulnerabilities", status: "Compliant", maturityScore: 85, evidence: "Asset patch policies published. Active monitoring for critical zero-days like XZ utils is automated.", lastAudited: new Date(Date.now() - 86400000 * 4).toISOString() },
    { id: "cr-604", framework: "NIST", controlId: "PR.AC-1", controlName: "Access Control Policies and Procedures", status: "Compliant", maturityScore: 95, evidence: "Multi-tenant boundaries secured at the API controller layer. Tenant separation confirmed by annual compliance review.", lastAudited: new Date(Date.now() - 86400000 * 10).toISOString() },
    { id: "cr-605", framework: "HIPAA", controlId: "164.312(a)(1)", controlName: "Access Controls (Unique User Identification)", status: "Compliant", maturityScore: 80, evidence: "Every system asset and user audit session is logged with unique base64 session authorization tokens.", lastAudited: new Date(Date.now() - 86400000 * 5).toISOString() },
    { id: "cr-606", framework: "GDPR", controlId: "Article 32", controlName: "Security of Processing", status: "In Progress", maturityScore: 65, evidence: "Database connection proxy layer encrypted. Data exports restricted to standard CSV file format.", lastAudited: new Date(Date.now() - 86400000 * 6).toISOString() }
  ] as ComplianceRecord[],
  mitre_mappings: [
    { id: "mm-101", tactic: "Command and Control", technique: "Application Layer Protocol: Web Protocols", technique_id: "T1071.001", entity_type: "alert", entity_id: "alt-101" },
    { id: "mm-102", tactic: "Credential Access", technique: "Brute Force: Password Guessing", technique_id: "T1110.001", entity_type: "alert", entity_id: "alt-102" },
    { id: "mm-103", tactic: "Initial Access", technique: "Exploit Public-Facing Application", technique_id: "T1190", entity_type: "alert", entity_id: "alt-103" },
    { id: "mm-104", tactic: "Privilege Escalation", technique: "Abuse Access Token / Role Assumption", technique_id: "T1548", entity_type: "alert", entity_id: "alt-104" },
    { id: "mm-105", tactic: "Exfiltration", technique: "Exfiltration Over Web Service", technique_id: "T1567.002", entity_type: "alert", entity_id: "alt-105" }
  ] as MitreMappingEntity[]
};

export class DatabaseService {
  private static pool: Pool | null = null;
  private static isPostgres = false;

  public static async initialize(): Promise<void> {
    const hasPostgresVars = !!(
      process.env.DATABASE_URL ||
      process.env.PGHOST ||
      process.env.SQL_HOST
    );

    if (!hasPostgresVars) {
      console.log("ℹ️ No PostgreSQL credentials detected. Utilizing secure, persistent, file-backed JSON engine fallback.");
      this.ensureJsonDbExists();
      return;
    }

    try {
      console.log("🔋 Initializing PostgreSQL Connection Pool...");
      
      const config: any = {
        connectionTimeoutMillis: 5000,
      };

      if (process.env.DATABASE_URL) {
        config.connectionString = process.env.DATABASE_URL;
        // Supabase, Neon, Render, and other cloud databases require SSL
        const lowerUrl = process.env.DATABASE_URL.toLowerCase();
        if (
          lowerUrl.includes("supabase") ||
          lowerUrl.includes("neon") ||
          lowerUrl.includes("render") ||
          lowerUrl.includes("sslmode=require") ||
          lowerUrl.includes("pooler")
        ) {
          config.ssl = { rejectUnauthorized: false };
        }
      } else {
        config.host = process.env.SQL_HOST || process.env.PGHOST || "127.0.0.1";
        config.user = process.env.SQL_USER || process.env.PGUSER || "postgres";
        config.password = process.env.SQL_PASSWORD || process.env.PGPASSWORD || "";
        config.database = process.env.SQL_DB_NAME || process.env.PGDATABASE || "secassist";
        config.port = parseInt(process.env.PGPORT || "5432", 10);
      }

      this.pool = new Pool(config);

      // Verify connection
      const client = await this.pool.connect();
      client.release();
      this.isPostgres = true;
      console.log("✅ Successfully connected to PostgreSQL instance.");

      // Run schemas and migrations dynamically
      await this.runMigrations();

    } catch (err: any) {
      console.error("⚠️ PostgreSQL Connection failed! Falling back to secure file-backed JSON database engine.", err.message);
      this.isPostgres = false;
      this.pool = null;
      this.ensureJsonDbExists();
    }
  }

  private static ensureJsonDbExists() {
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, JSON.stringify(initialFallbackDatabase, null, 2));
      console.log("📁 Generated initial local file database seed.");
    }
  }

  private static async runMigrations(): Promise<void> {
    if (!this.pool) return;
    try {
      console.log("⚡ Executing database schemas & seeding...");
      const migrationFile = path.join(process.cwd(), "src", "db", "migrations.sql");
      if (fs.existsSync(migrationFile)) {
        const sql = fs.readFileSync(migrationFile, "utf-8");
        await this.pool.query(sql);
        console.log("🌟 Schemas established & seeded successfully.");
      }
    } catch (err: any) {
      console.error("❌ Failed executing migrations.sql:", err.message);
    }
  }

  private static readJsonDb(): typeof initialFallbackDatabase {
    this.ensureJsonDbExists();
    try {
      return JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
    } catch (err) {
      return initialFallbackDatabase;
    }
  }

  private static writeJsonDb(data: typeof initialFallbackDatabase) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  }

  // =========================================================================
  // ENTITY CRUD - USERS
  // =========================================================================
  public static async getUsers(): Promise<User[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("SELECT id, name, email, role, tenant_id as \"tenantId\", created_at FROM users ORDER BY created_at DESC");
      return res.rows;
    }
    return this.readJsonDb().users;
  }

  public static async getUserById(id: string): Promise<User | null> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("SELECT id, name, email, role, tenant_id as \"tenantId\", created_at FROM users WHERE id = $1", [id]);
      return res.rows[0] || null;
    }
    return this.readJsonDb().users.find((u) => u.id === id) || null;
  }

  public static async getUserByEmail(email: string): Promise<User | null> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("SELECT id, name, email, role, tenant_id as \"tenantId\", created_at FROM users WHERE LOWER(email) = LOWER($1)", [email]);
      return res.rows[0] || null;
    }
    return this.readJsonDb().users.find((u) => u.email.toLowerCase() === email.toLowerCase()) || null;
  }

  public static async createUser(user: Partial<User>): Promise<User> {
    const id = user.id || `u-${Math.floor(100 + Math.random() * 900)}`;
    const name = user.name || "New Security Analyst";
    const email = user.email || `analyst-${id}@secassist.ai`;
    const role = user.role || "Analyst";
    const tenantId = user.tenantId || "tenant-alpha";

    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(
        "INSERT INTO users (id, name, email, role, tenant_id) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, role, tenant_id as \"tenantId\"",
        [id, name, email, role, tenantId]
      );
      return res.rows[0];
    }

    const db = this.readJsonDb();
    const newUser: User = { id, name, email, role, tenantId, created_at: new Date().toISOString() };
    db.users.push(newUser);
    this.writeJsonDb(db);
    return newUser;
  }

  public static async updateUser(id: string, updates: Partial<User>): Promise<User | null> {
    if (this.isPostgres && this.pool) {
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (updates.name !== undefined) { fields.push(`name = $${idx++}`); values.push(updates.name); }
      if (updates.email !== undefined) { fields.push(`email = $${idx++}`); values.push(updates.email); }
      if (updates.role !== undefined) { fields.push(`role = $${idx++}`); values.push(updates.role); }
      if (updates.tenantId !== undefined) { fields.push(`tenant_id = $${idx++}`); values.push(updates.tenantId); }

      if (fields.length === 0) return this.getUserById(id);

      values.push(id);
      const query = `UPDATE users SET ${fields.join(", ")} WHERE id = $${idx} RETURNING id, name, email, role, tenant_id as "tenantId"`;
      const res = await this.pool.query(query, values);
      return res.rows[0] || null;
    }

    const db = this.readJsonDb();
    const userIdx = db.users.findIndex((u) => u.id === id);
    if (userIdx === -1) return null;

    db.users[userIdx] = { ...db.users[userIdx], ...updates };
    this.writeJsonDb(db);
    return db.users[userIdx];
  }

  public static async deleteUser(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("DELETE FROM users WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.users.length;
    db.users = db.users.filter((u) => u.id !== id);
    this.writeJsonDb(db);
    return db.users.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - ORGANIZATIONS
  // =========================================================================
  public static async getOrganizations(): Promise<Organization[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("SELECT id, name, domain, created_at FROM organizations ORDER BY created_at DESC");
      return res.rows;
    }
    return this.readJsonDb().organizations;
  }

  public static async createOrganization(org: Partial<Organization>): Promise<Organization> {
    const id = org.id || `tenant-${Math.floor(100 + Math.random() * 900)}`;
    const name = org.name || "New Corporation Branch";
    const domain = org.domain || `${id}.com`;

    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(
        "INSERT INTO organizations (id, name, domain) VALUES ($1, $2, $3) RETURNING id, name, domain, created_at",
        [id, name, domain]
      );
      return res.rows[0];
    }

    const db = this.readJsonDb();
    const newOrg: Organization = { id, name, domain, created_at: new Date().toISOString() };
    db.organizations.push(newOrg);
    this.writeJsonDb(db);
    return newOrg;
  }

  public static async updateOrganization(id: string, updates: Partial<Organization>): Promise<Organization | null> {
    if (this.isPostgres && this.pool) {
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (updates.name !== undefined) { fields.push(`name = $${idx++}`); values.push(updates.name); }
      if (updates.domain !== undefined) { fields.push(`domain = $${idx++}`); values.push(updates.domain); }

      if (fields.length === 0) {
        const res = await this.pool.query("SELECT id, name, domain, created_at FROM organizations WHERE id = $1", [id]);
        return res.rows[0] || null;
      }

      values.push(id);
      const query = `UPDATE organizations SET ${fields.join(", ")} WHERE id = $${idx} RETURNING id, name, domain, created_at`;
      const res = await this.pool.query(query, values);
      return res.rows[0] || null;
    }

    const db = this.readJsonDb();
    const idx = db.organizations.findIndex((o) => o.id === id);
    if (idx === -1) return null;
    db.organizations[idx] = { ...db.organizations[idx], ...updates };
    this.writeJsonDb(db);
    return db.organizations[idx];
  }

  public static async deleteOrganization(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("DELETE FROM organizations WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.organizations.length;
    db.organizations = db.organizations.filter((o) => o.id !== id);
    this.writeJsonDb(db);
    return db.organizations.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - ALERTS
  // =========================================================================
  public static async getAlerts(): Promise<Alert[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(`
        SELECT a.id, a.title, a.severity, a.category, a.timestamp, 
               a.source_ip as "sourceIp", a.dest_ip as "destIp", a.status, 
               a.description, a.assigned_to as "assignedTo", a.tenant_id as "tenantId",
               m.tactic as "mitreTactic", m.technique as "mitreTechnique", m.technique_id as "mitreTechniqueId"
        FROM alerts a
        LEFT JOIN mitre_mappings m ON m.entity_type = 'alert' AND m.entity_id = a.id
        ORDER BY a.timestamp DESC
      `);
      return res.rows.map((row) => ({
        id: row.id,
        title: row.title,
        severity: row.severity,
        category: row.category,
        timestamp: row.timestamp,
        sourceIp: row.sourceIp,
        destIp: row.destIp,
        status: row.status,
        description: row.description,
        assignedTo: row.assignedTo,
        tenantId: row.tenantId,
        mitreAttack: row.mitreTactic ? {
          tactic: row.mitreTactic,
          technique: row.mitreTechnique,
          id: row.mitreTechniqueId
        } : undefined
      }));
    }
    return this.readJsonDb().alerts;
  }

  public static async createAlert(alert: Partial<Alert>): Promise<Alert> {
    const id = alert.id || `alt-${Math.floor(100 + Math.random() * 900)}`;
    const title = alert.title || "Anomalous Endpoint Telemetry Triggered";
    const severity = alert.severity || "Medium";
    const category = alert.category || "Defense Evasion";
    const timestamp = alert.timestamp || new Date().toISOString();
    const sourceIp = alert.sourceIp || "127.0.0.1";
    const destIp = alert.destIp || "0.0.0.0";
    const status = alert.status || "Active";
    const description = alert.description || "Security event alert compiled automatically by engine scanner.";
    const assignedTo = alert.assignedTo || "analyst@secassist.ai";
    const tenantId = alert.tenantId || "tenant-alpha";

    if (this.isPostgres && this.pool) {
      await this.pool.query(
        `INSERT INTO alerts (id, title, severity, category, timestamp, source_ip, dest_ip, status, description, assigned_to, tenant_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [id, title, severity, category, timestamp, sourceIp, destIp, status, description, assignedTo, tenantId]
      );

      if (alert.mitreAttack) {
        const mmId = `mm-${id}`;
        await this.pool.query(
          `INSERT INTO mitre_mappings (id, tactic, technique, technique_id, entity_type, entity_id)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [mmId, alert.mitreAttack.tactic, alert.mitreAttack.technique, alert.mitreAttack.id, "alert", id]
        );
      }

      return { ...alert, id, title, severity, category, timestamp, sourceIp, destIp, status, description, assignedTo, tenantId } as Alert;
    }

    const db = this.readJsonDb();
    const newAlert: Alert = {
      id, title, severity, category, timestamp, sourceIp, destIp, status, description, assignedTo, tenantId,
      mitreAttack: alert.mitreAttack
    };
    db.alerts.unshift(newAlert);
    this.writeJsonDb(db);
    return newAlert;
  }

  public static async updateAlert(id: string, updates: Partial<Alert>): Promise<Alert | null> {
    if (this.isPostgres && this.pool) {
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (updates.title !== undefined) { fields.push(`title = $${idx++}`); values.push(updates.title); }
      if (updates.severity !== undefined) { fields.push(`severity = $${idx++}`); values.push(updates.severity); }
      if (updates.category !== undefined) { fields.push(`category = $${idx++}`); values.push(updates.category); }
      if (updates.status !== undefined) { fields.push(`status = $${idx++}`); values.push(updates.status); }
      if (updates.description !== undefined) { fields.push(`description = $${idx++}`); values.push(updates.description); }
      if (updates.assignedTo !== undefined) { fields.push(`assigned_to = $${idx++}`); values.push(updates.assignedTo); }

      if (fields.length > 0) {
        values.push(id);
        const query = `UPDATE alerts SET ${fields.join(", ")} WHERE id = $${idx}`;
        await this.pool.query(query, values);
      }

      if (updates.mitreAttack) {
        await this.pool.query("DELETE FROM mitre_mappings WHERE entity_type = 'alert' AND entity_id = $1", [id]);
        const mmId = `mm-${id}`;
        await this.pool.query(
          `INSERT INTO mitre_mappings (id, tactic, technique, technique_id, entity_type, entity_id)
           VALUES ($1, $2, $3, $4, 'alert', $5)`,
          [mmId, updates.mitreAttack.tactic, updates.mitreAttack.technique, updates.mitreAttack.id, id]
        );
      }

      const all = await this.getAlerts();
      return all.find((a) => a.id === id) || null;
    }

    const db = this.readJsonDb();
    const alertIdx = db.alerts.findIndex((a) => a.id === id);
    if (alertIdx === -1) return null;

    db.alerts[alertIdx] = { ...db.alerts[alertIdx], ...updates };
    this.writeJsonDb(db);
    return db.alerts[alertIdx];
  }

  public static async deleteAlert(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      await this.pool.query("DELETE FROM mitre_mappings WHERE entity_type = 'alert' AND entity_id = $1", [id]);
      const res = await this.pool.query("DELETE FROM alerts WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.alerts.length;
    db.alerts = db.alerts.filter((a) => a.id !== id);
    this.writeJsonDb(db);
    return db.alerts.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - INCIDENTS
  // =========================================================================
  public static async getIncidents(): Promise<Incident[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("SELECT id, title, severity, status, description, assigned_to as \"assignedTo\", tenant_id as \"tenantId\", created_at as \"createdAt\" FROM incidents ORDER BY created_at DESC");
      return res.rows;
    }
    return this.readJsonDb().incidents;
  }

  public static async createIncident(incident: Partial<Incident>): Promise<Incident> {
    const id = incident.id || `inc-${Math.floor(500 + Math.random() * 500)}`;
    const title = incident.title || "Unauthorized Account Elevation Triage Session";
    const severity = incident.severity || "High";
    const status = incident.status || "Open";
    const description = incident.description || "SOC Incident Log tracking ongoing security reviews.";
    const assignedTo = incident.assignedTo || "admin@secassist.ai";
    const tenantId = incident.tenantId || "tenant-alpha";
    const createdAt = incident.createdAt || new Date().toISOString();

    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(
        `INSERT INTO incidents (id, title, severity, status, description, assigned_to, tenant_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, title, severity, status, description, assigned_to as "assignedTo", tenant_id as "tenantId", created_at as "createdAt"`,
        [id, title, severity, status, description, assignedTo, tenantId, createdAt]
      );
      return res.rows[0];
    }

    const db = this.readJsonDb();
    const newIncident: Incident = { id, title, severity, status, description, assignedTo, tenantId, createdAt };
    db.incidents.unshift(newIncident);
    this.writeJsonDb(db);
    return newIncident;
  }

  public static async updateIncident(id: string, updates: Partial<Incident>): Promise<Incident | null> {
    if (this.isPostgres && this.pool) {
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (updates.title !== undefined) { fields.push(`title = $${idx++}`); values.push(updates.title); }
      if (updates.severity !== undefined) { fields.push(`severity = $${idx++}`); values.push(updates.severity); }
      if (updates.status !== undefined) { fields.push(`status = $${idx++}`); values.push(updates.status); }
      if (updates.description !== undefined) { fields.push(`description = $${idx++}`); values.push(updates.description); }
      if (updates.assignedTo !== undefined) { fields.push(`assigned_to = $${idx++}`); values.push(updates.assignedTo); }

      if (fields.length === 0) {
        const res = await this.pool.query("SELECT id, title, severity, status, description, assigned_to as \"assignedTo\", tenant_id as \"tenantId\", created_at as \"createdAt\" FROM incidents WHERE id = $1", [id]);
        return res.rows[0] || null;
      }

      values.push(id);
      const query = `UPDATE incidents SET ${fields.join(", ")} WHERE id = $${idx} RETURNING id, title, severity, status, description, assigned_to as "assignedTo", tenant_id as "tenantId", created_at as "createdAt"`;
      const res = await this.pool.query(query, values);
      return res.rows[0] || null;
    }

    const db = this.readJsonDb();
    const idx = db.incidents.findIndex((i) => i.id === id);
    if (idx === -1) return null;
    db.incidents[idx] = { ...db.incidents[idx], ...updates };
    this.writeJsonDb(db);
    return db.incidents[idx];
  }

  public static async deleteIncident(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("DELETE FROM incidents WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.incidents.length;
    db.incidents = db.incidents.filter((i) => i.id !== id);
    this.writeJsonDb(db);
    return db.incidents.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - ASSETS
  // =========================================================================
  public static async getAssets(): Promise<Asset[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(`
        SELECT id, name, type, ip_address as "ipAddress", os, criticality, status, owner, 
               active_alerts_count as "activeAlertsCount", last_seen as "lastSeen" 
        FROM assets ORDER BY id ASC
      `);
      return res.rows;
    }
    return this.readJsonDb().assets;
  }

  public static async createAsset(asset: Partial<Asset>): Promise<Asset> {
    const id = asset.id || `ast-${Math.floor(10 + Math.random() * 90)}`;
    const name = asset.name || "Default asset";
    const type = asset.type || "Endpoint";
    const ipAddress = asset.ipAddress || "10.100.12.10";
    const os = asset.os || "Linux";
    const criticality = asset.criticality || "Medium";
    const status = asset.status || "Online";
    const owner = asset.owner || "analyst@secassist.ai";
    const activeAlertsCount = asset.activeAlertsCount || 0;
    const lastSeen = asset.lastSeen || new Date().toISOString();

    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(
        `INSERT INTO assets (id, name, type, ip_address, os, criticality, status, owner, active_alerts_count, last_seen)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id, name, type, ip_address as "ipAddress", os, criticality, status, owner, active_alerts_count as "activeAlertsCount", last_seen as "lastSeen"`,
        [id, name, type, ipAddress, os, criticality, status, owner, activeAlertsCount, lastSeen]
      );
      return res.rows[0];
    }

    const db = this.readJsonDb();
    const newAsset: Asset = { id, name, type, ipAddress, os, criticality, status, owner, activeAlertsCount, lastSeen };
    db.assets.push(newAsset);
    this.writeJsonDb(db);
    return newAsset;
  }

  public static async updateAsset(id: string, updates: Partial<Asset>): Promise<Asset | null> {
    if (this.isPostgres && this.pool) {
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (updates.name !== undefined) { fields.push(`name = $${idx++}`); values.push(updates.name); }
      if (updates.status !== undefined) { fields.push(`status = $${idx++}`); values.push(updates.status); }
      if (updates.criticality !== undefined) { fields.push(`criticality = $${idx++}`); values.push(updates.criticality); }
      if (updates.activeAlertsCount !== undefined) { fields.push(`active_alerts_count = $${idx++}`); values.push(updates.activeAlertsCount); }

      if (fields.length === 0) {
        const res = await this.pool.query("SELECT id, name, type, ip_address as \"ipAddress\", os, criticality, status, owner, active_alerts_count as \"activeAlertsCount\", last_seen as \"lastSeen\" FROM assets WHERE id = $1", [id]);
        return res.rows[0] || null;
      }

      values.push(id);
      const query = `UPDATE assets SET ${fields.join(", ")} WHERE id = $${idx} RETURNING id, name, type, ip_address as "ipAddress", os, criticality, status, owner, active_alerts_count as "activeAlertsCount", last_seen as "lastSeen"`;
      const res = await this.pool.query(query, values);
      return res.rows[0] || null;
    }

    const db = this.readJsonDb();
    const assetIdx = db.assets.findIndex((a) => a.id === id);
    if (assetIdx === -1) return null;

    db.assets[assetIdx] = { ...db.assets[assetIdx], ...updates };
    this.writeJsonDb(db);
    return db.assets[assetIdx];
  }

  public static async deleteAsset(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("DELETE FROM assets WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.assets.length;
    db.assets = db.assets.filter((a) => a.id !== id);
    this.writeJsonDb(db);
    return db.assets.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - VULNERABILITIES
  // =========================================================================
  public static async getVulnerabilities(): Promise<Vulnerability[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(`
        SELECT id, title, score, severity, affected_asset_id as "affectedAssetId", 
               affected_asset_name as "affectedAssetName", status, 
               patch_recommendation as "patchRecommendation", published_date as "publishedDate", description
        FROM vulnerabilities ORDER BY score DESC
      `);
      return res.rows.map((row) => ({
        ...row,
        score: parseFloat(row.score)
      }));
    }
    return this.readJsonDb().vulnerabilities;
  }

  public static async createVulnerability(vuln: Partial<Vulnerability>): Promise<Vulnerability> {
    const id = vuln.id || `CVE-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
    const title = vuln.title || "Undocumented web library buffer overrun";
    const score = vuln.score || 7.5;
    const severity = vuln.severity || "High";
    const affectedAssetId = vuln.affectedAssetId || "ast-2";
    const affectedAssetName = vuln.affectedAssetName || "WAF-Public-Web";
    const status = vuln.status || "Open";
    const patchRecommendation = vuln.patchRecommendation || "Apply latest patch.";
    const publishedDate = vuln.publishedDate || new Date().toISOString().split("T")[0];
    const description = vuln.description || "A zero-day exploit module scanning target frameworks.";

    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(
        `INSERT INTO vulnerabilities (id, title, score, severity, affected_asset_id, affected_asset_name, status, patch_recommendation, published_date, description)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id, title, score, severity, affected_asset_id as "affectedAssetId", affected_asset_name as "affectedAssetName", status, patch_recommendation as "patchRecommendation", published_date as "publishedDate", description`,
        [id, title, score, severity, affectedAssetId, affectedAssetName, status, patchRecommendation, publishedDate, description]
      );
      return { ...res.rows[0], score: parseFloat(res.rows[0].score) };
    }

    const db = this.readJsonDb();
    const newVuln: Vulnerability = { id, title, score, severity, affectedAssetId, affectedAssetName, status, patchRecommendation, publishedDate, description };
    db.vulnerabilities.push(newVuln);
    this.writeJsonDb(db);
    return newVuln;
  }

  public static async updateVulnerability(id: string, updates: Partial<Vulnerability>): Promise<Vulnerability | null> {
    if (this.isPostgres && this.pool) {
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (updates.status !== undefined) { fields.push(`status = $${idx++}`); values.push(updates.status); }

      if (fields.length === 0) {
        const res = await this.pool.query("SELECT id, title, score, severity, affected_asset_id as \"affectedAssetId\", affected_asset_name as \"affectedAssetName\", status, patch_recommendation as \"patchRecommendation\", published_date as \"publishedDate\", description FROM vulnerabilities WHERE id = $1", [id]);
        return res.rows[0] ? { ...res.rows[0], score: parseFloat(res.rows[0].score) } : null;
      }

      values.push(id);
      const query = `UPDATE vulnerabilities SET ${fields.join(", ")} WHERE id = $${idx} RETURNING id, title, score, severity, affected_asset_id as "affectedAssetId", affected_asset_name as "affectedAssetName", status, patch_recommendation as "patchRecommendation", published_date as "publishedDate", description`;
      const res = await this.pool.query(query, values);
      return res.rows[0] ? { ...res.rows[0], score: parseFloat(res.rows[0].score) } : null;
    }

    const db = this.readJsonDb();
    const idx = db.vulnerabilities.findIndex((v) => v.id === id);
    if (idx === -1) return null;
    db.vulnerabilities[idx] = { ...db.vulnerabilities[idx], ...updates };
    this.writeJsonDb(db);
    return db.vulnerabilities[idx];
  }

  public static async deleteVulnerability(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("DELETE FROM vulnerabilities WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.vulnerabilities.length;
    db.vulnerabilities = db.vulnerabilities.filter((v) => v.id !== id);
    this.writeJsonDb(db);
    return db.vulnerabilities.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - THREAT INTELLIGENCE
  // =========================================================================
  public static async getThreatIntelligence(): Promise<ThreatIntelligence[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(`
        SELECT t.id, t.name, t.severity, t.explanation, t.remediation, 
               t.detection_signature as "detectionSignature", t.affected_assets as "affectedAssets",
               m.tactic as "mitreTactic", m.technique as "mitreTechnique", m.technique_id as "mitreTechniqueId"
        FROM threat_intelligence t
        LEFT JOIN mitre_mappings m ON m.entity_type = 'threat' AND m.entity_id = t.id
        ORDER BY t.id ASC
      `);
      return res.rows.map((row) => ({
        id: row.id,
        name: row.name,
        severity: row.severity,
        explanation: row.explanation,
        remediation: row.remediation,
        detectionSignature: row.detectionSignature,
        affectedAssets: typeof row.affectedAssets === "string" ? JSON.parse(row.affectedAssets) : row.affectedAssets || [],
        mitreMapping: row.mitreTactic ? {
          tactic: row.mitreTactic,
          technique: row.mitreTechnique,
          id: row.mitreTechniqueId
        } : undefined
      }));
    }
    return this.readJsonDb().threats;
  }

  public static async createThreatIntel(threat: Partial<ThreatIntelligence>): Promise<ThreatIntelligence> {
    const id = threat.id || `th-${Math.floor(300 + Math.random() * 700)}`;
    const name = threat.name || "Default active ransomware payload variant";
    const severity = threat.severity || "High";
    const explanation = threat.explanation || "No explanation provided.";
    const remediation = threat.remediation || "Isolate outbound traffic.";
    const detectionSignature = threat.detectionSignature || "N/A";
    const affectedAssets = threat.affectedAssets || ["Internal Servers"];

    if (this.isPostgres && this.pool) {
      await this.pool.query(
        `INSERT INTO threat_intelligence (id, name, severity, explanation, remediation, detection_signature, affected_assets)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [id, name, severity, explanation, remediation, detectionSignature, JSON.stringify(affectedAssets)]
      );

      if (threat.mitreMapping) {
        const mmId = `mm-${id}`;
        await this.pool.query(
          `INSERT INTO mitre_mappings (id, tactic, technique, technique_id, entity_type, entity_id)
           VALUES ($1, $2, $3, $4, 'threat', $5)`,
          [mmId, threat.mitreMapping.tactic, threat.mitreMapping.technique, threat.mitreMapping.id, id]
        );
      }

      return { ...threat, id, name, severity, explanation, remediation, detectionSignature, affectedAssets } as ThreatIntelligence;
    }

    const db = this.readJsonDb();
    const newThreat: ThreatIntelligence = { id, name, severity, explanation, remediation, detectionSignature, affectedAssets, mitreMapping: threat.mitreMapping };
    db.threats.unshift(newThreat);
    this.writeJsonDb(db);
    return newThreat;
  }

  public static async updateThreatIntel(id: string, updates: Partial<ThreatIntelligence>): Promise<ThreatIntelligence | null> {
    if (this.isPostgres && this.pool) {
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (updates.name !== undefined) { fields.push(`name = $${idx++}`); values.push(updates.name); }
      if (updates.severity !== undefined) { fields.push(`severity = $${idx++}`); values.push(updates.severity); }
      if (updates.explanation !== undefined) { fields.push(`explanation = $${idx++}`); values.push(updates.explanation); }
      if (updates.remediation !== undefined) { fields.push(`remediation = $${idx++}`); values.push(updates.remediation); }
      if (updates.detectionSignature !== undefined) { fields.push(`detection_signature = $${idx++}`); values.push(updates.detectionSignature); }
      if (updates.affectedAssets !== undefined) { fields.push(`affected_assets = $${idx++}`); values.push(JSON.stringify(updates.affectedAssets)); }

      if (fields.length > 0) {
        values.push(id);
        const query = `UPDATE threat_intelligence SET ${fields.join(", ")} WHERE id = $${idx}`;
        await this.pool.query(query, values);
      }

      if (updates.mitreMapping) {
        await this.pool.query("DELETE FROM mitre_mappings WHERE entity_type = 'threat' AND entity_id = $1", [id]);
        const mmId = `mm-${id}`;
        await this.pool.query(
          `INSERT INTO mitre_mappings (id, tactic, technique, technique_id, entity_type, entity_id)
           VALUES ($1, $2, $3, $4, 'threat', $5)`,
          [mmId, updates.mitreMapping.tactic, updates.mitreMapping.technique, updates.mitreMapping.id, id]
        );
      }

      const all = await this.getThreatIntelligence();
      return all.find((t) => t.id === id) || null;
    }

    const db = this.readJsonDb();
    const idx = db.threats.findIndex((t) => t.id === id);
    if (idx === -1) return null;
    db.threats[idx] = { ...db.threats[idx], ...updates };
    this.writeJsonDb(db);
    return db.threats[idx];
  }

  public static async deleteThreatIntel(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      await this.pool.query("DELETE FROM mitre_mappings WHERE entity_type = 'threat' AND entity_id = $1", [id]);
      const res = await this.pool.query("DELETE FROM threat_intelligence WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.threats.length;
    db.threats = db.threats.filter((t) => t.id !== id);
    this.writeJsonDb(db);
    return db.threats.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - REPORTS
  // =========================================================================
  public static async getReports(): Promise<Report[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(`
        SELECT r.id, r.title, r.alert_id as "alertId", r.threat_name as "threatName", r.severity,
               r.executive_summary as "executiveSummary", r.technical_details as "technicalDetails",
               r.remediation_plan as "remediationPlan", r.generated_by as "generatedBy", r.timestamp,
               r.root_cause_assessment as "rootCauseAssessment", r.risk_rating as "riskRating",
               m.tactic as "mitreTactic", m.technique as "mitreTechnique", m.technique_id as "mitreTechniqueId"
        FROM reports r
        LEFT JOIN mitre_mappings m ON m.entity_type = 'report' AND m.entity_id = r.id
        ORDER BY r.timestamp DESC
      `);
      return res.rows.map((row) => ({
        id: row.id,
        title: row.title,
        alertId: row.alertId,
        threatName: row.threatName,
        severity: row.severity,
        executiveSummary: row.executiveSummary,
        technicalDetails: row.technicalDetails,
        remediationPlan: row.remediationPlan,
        generatedBy: row.generatedBy,
        timestamp: row.timestamp,
        rootCauseAssessment: row.rootCauseAssessment,
        riskRating: row.riskRating,
        mitreMapping: row.mitreTactic ? {
          tactic: row.mitreTactic,
          technique: row.mitreTechnique,
          id: row.mitreTechniqueId
        } : undefined
      }));
    }
    return this.readJsonDb().reports;
  }

  public static async createReport(report: Partial<Report>): Promise<Report> {
    const id = report.id || `rep-${Math.floor(400 + Math.random() * 600)}`;
    const title = report.title || "Triage Operations Case Log";
    const alertId = report.alertId || "alt-101";
    const threatName = report.threatName || "Suspicious beacon logs";
    const severity = report.severity || "High";
    const executiveSummary = report.executiveSummary || "";
    const technicalDetails = report.technicalDetails || "";
    const remediationPlan = report.remediationPlan || "";
    const generatedBy = report.generatedBy || "admin@secassist.ai";
    const timestamp = report.timestamp || new Date().toISOString();
    const rootCauseAssessment = report.rootCauseAssessment || "";
    const riskRating = report.riskRating || "Medium";

    if (this.isPostgres && this.pool) {
      await this.pool.query(
        `INSERT INTO reports (id, title, alert_id, threat_name, severity, executive_summary, technical_details, remediation_plan, generated_by, timestamp, root_cause_assessment, risk_rating)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [id, title, alertId, threatName, severity, executiveSummary, technicalDetails, remediationPlan, generatedBy, timestamp, rootCauseAssessment, riskRating]
      );

      if (report.mitreMapping) {
        const mmId = `mm-${id}`;
        await this.pool.query(
          `INSERT INTO mitre_mappings (id, tactic, technique, technique_id, entity_type, entity_id)
           VALUES ($1, $2, $3, $4, 'report', $5)`,
          [mmId, report.mitreMapping.tactic, report.mitreMapping.technique, report.mitreMapping.id, id]
        );
      }

      return { ...report, id, title, alertId, threatName, severity, executiveSummary, technicalDetails, remediationPlan, generatedBy, timestamp, rootCauseAssessment, riskRating } as Report;
    }

    const db = this.readJsonDb();
    const newReport: Report = { id, title, alertId, threatName, severity, executiveSummary, technicalDetails, remediationPlan, generatedBy, timestamp, rootCauseAssessment, riskRating, mitreMapping: report.mitreMapping };
    db.reports.unshift(newReport);
    this.writeJsonDb(db);
    return newReport;
  }

  public static async deleteReport(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      await this.pool.query("DELETE FROM mitre_mappings WHERE entity_type = 'report' AND entity_id = $1", [id]);
      const res = await this.pool.query("DELETE FROM reports WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.reports.length;
    db.reports = db.reports.filter((r) => r.id !== id);
    this.writeJsonDb(db);
    return db.reports.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - AUDIT LOGS (logs in local database structure)
  // =========================================================================
  public static async getAuditLogs(): Promise<AuditLog[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(`
        SELECT id, filename, uploaded_by as "uploadedBy", timestamp, 
               parsed_count as "parsedCount", status, raw_content as "rawContent", analysis 
        FROM audit_logs ORDER BY timestamp DESC
      `);
      return res.rows.map((row) => ({
        ...row,
        analysis: typeof row.analysis === "string" ? JSON.parse(row.analysis) : row.analysis
      }));
    }
    return this.readJsonDb().logs;
  }

  public static async createAuditLog(log: Partial<AuditLog>): Promise<AuditLog> {
    const id = log.id || `log-${Math.floor(200 + Math.random() * 800)}`;
    const filename = log.filename || "unnamed_system.log";
    const uploadedBy = log.uploadedBy || "analyst@secassist.ai";
    const timestamp = log.timestamp || new Date().toISOString();
    const parsedCount = log.parsedCount || 0;
    const status = log.status || "Pending";
    const rawContent = log.rawContent || "";
    const analysis = log.analysis || undefined;

    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(
        `INSERT INTO audit_logs (id, filename, uploaded_by, timestamp, parsed_count, status, raw_content, analysis)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, filename, uploaded_by as "uploadedBy", timestamp, parsed_count as "parsedCount", status, raw_content as "rawContent", analysis`,
        [id, filename, uploadedBy, timestamp, parsedCount, status, rawContent, analysis ? JSON.stringify(analysis) : null]
      );
      return {
        ...res.rows[0],
        analysis: typeof res.rows[0].analysis === "string" ? JSON.parse(res.rows[0].analysis) : res.rows[0].analysis
      };
    }

    const db = this.readJsonDb();
    const newLog: AuditLog = { id, filename, uploadedBy, timestamp, parsedCount, status, rawContent, analysis };
    db.logs.unshift(newLog);
    this.writeJsonDb(db);
    return newLog;
  }

  public static async updateAuditLog(id: string, updates: Partial<AuditLog>): Promise<AuditLog | null> {
    if (this.isPostgres && this.pool) {
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (updates.status !== undefined) { fields.push(`status = $${idx++}`); values.push(updates.status); }
      if (updates.analysis !== undefined) { fields.push(`analysis = $${idx++}`); values.push(JSON.stringify(updates.analysis)); }

      if (fields.length === 0) {
        const res = await this.pool.query("SELECT id, filename, uploaded_by as \"uploadedBy\", timestamp, parsed_count as \"parsedCount\", status, raw_content as \"rawContent\", analysis FROM audit_logs WHERE id = $1", [id]);
        return res.rows[0] ? { ...res.rows[0], analysis: typeof res.rows[0].analysis === "string" ? JSON.parse(res.rows[0].analysis) : res.rows[0].analysis } : null;
      }

      values.push(id);
      const query = `UPDATE audit_logs SET ${fields.join(", ")} WHERE id = $${idx} RETURNING id, filename, uploaded_by as "uploadedBy", timestamp, parsed_count as "parsedCount", status, raw_content as "rawContent", analysis`;
      const res = await this.pool.query(query, values);
      return res.rows[0] ? { ...res.rows[0], analysis: typeof res.rows[0].analysis === "string" ? JSON.parse(res.rows[0].analysis) : res.rows[0].analysis } : null;
    }

    const db = this.readJsonDb();
    const idx = db.logs.findIndex((l) => l.id === id);
    if (idx === -1) return null;
    db.logs[idx] = { ...db.logs[idx], ...updates };
    this.writeJsonDb(db);
    return db.logs[idx];
  }

  public static async deleteAuditLog(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("DELETE FROM audit_logs WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.logs.length;
    db.logs = db.logs.filter((l) => l.id !== id);
    this.writeJsonDb(db);
    return db.logs.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - COMPLIANCE RECORDS (GRC metrics)
  // =========================================================================
  public static async getComplianceRecords(): Promise<ComplianceRecord[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(`
        SELECT id, framework, control_id as "controlId", control_name as "controlName", 
               status, maturity_score as "maturityScore", evidence, last_audited as "lastAudited" 
        FROM compliance_records ORDER BY framework ASC, control_id ASC
      `);
      return res.rows;
    }
    return this.readJsonDb().compliance;
  }

  public static async createComplianceRecord(record: Partial<ComplianceRecord>): Promise<ComplianceRecord> {
    const id = record.id || `cr-${Math.floor(600 + Math.random() * 400)}`;
    const framework = record.framework || "SOC2";
    const controlId = record.controlId || "CC1.1";
    const controlName = record.controlName || "Corporate Policy Configuration Standard";
    const status = record.status || "In Progress";
    const maturityScore = record.maturityScore || 50;
    const evidence = record.evidence || "Initial evidence gathering session logged.";
    const lastAudited = record.lastAudited || new Date().toISOString();

    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(
        `INSERT INTO compliance_records (id, framework, control_id, control_name, status, maturity_score, evidence, last_audited)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, framework, control_id as "controlId", control_name as "controlName", status, maturity_score as "maturityScore", evidence, last_audited as "lastAudited"`,
        [id, framework, controlId, controlName, status, maturityScore, evidence, lastAudited]
      );
      return res.rows[0];
    }

    const db = this.readJsonDb();
    const newRecord: ComplianceRecord = { id, framework, controlId, controlName, status, maturityScore, evidence, lastAudited };
    db.compliance.push(newRecord);
    this.writeJsonDb(db);
    return newRecord;
  }

  public static async updateComplianceRecord(id: string, updates: Partial<ComplianceRecord>): Promise<ComplianceRecord | null> {
    if (this.isPostgres && this.pool) {
      const fields: string[] = [];
      const values: any[] = [];
      let idx = 1;

      if (updates.status !== undefined) { fields.push(`status = $${idx++}`); values.push(updates.status); }
      if (updates.maturityScore !== undefined) { fields.push(`maturity_score = $${idx++}`); values.push(updates.maturityScore); }
      if (updates.evidence !== undefined) { fields.push(`evidence = $${idx++}`); values.push(updates.evidence); }

      if (fields.length === 0) {
        const res = await this.pool.query("SELECT id, framework, control_id as \"controlId\", control_name as \"controlName\", status, maturity_score as \"maturityScore\", evidence, last_audited as \"lastAudited\" FROM compliance_records WHERE id = $1", [id]);
        return res.rows[0] || null;
      }

      values.push(id);
      const query = `UPDATE compliance_records SET ${fields.join(", ")} WHERE id = $${idx} RETURNING id, framework, control_id as "controlId", control_name as "controlName", status, maturity_score as "maturityScore", evidence, last_audited as "lastAudited"`;
      const res = await this.pool.query(query, values);
      return res.rows[0] || null;
    }

    const db = this.readJsonDb();
    const idx = db.compliance.findIndex((c) => c.id === id);
    if (idx === -1) return null;
    db.compliance[idx] = { ...db.compliance[idx], ...updates };
    this.writeJsonDb(db);
    return db.compliance[idx];
  }

  public static async deleteComplianceRecord(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("DELETE FROM compliance_records WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.compliance.length;
    db.compliance = db.compliance.filter((c) => c.id !== id);
    this.writeJsonDb(db);
    return db.compliance.length < originalLength;
  }

  // =========================================================================
  // ENTITY CRUD - MITRE MAPPINGS
  // =========================================================================
  public static async getMitreMappings(): Promise<MitreMappingEntity[]> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(`
        SELECT id, tactic, technique, technique_id as "technique_id", entity_type as "entity_type", entity_id as "entity_id" 
        FROM mitre_mappings
      `);
      return res.rows;
    }
    return this.readJsonDb().mitre_mappings;
  }

  public static async createMitreMapping(mapping: Partial<MitreMappingEntity>): Promise<MitreMappingEntity> {
    const id = mapping.id || `mm-${Math.floor(100 + Math.random() * 900)}`;
    const tactic = mapping.tactic || "Execution";
    const technique = mapping.technique || "Command and Scripting Interpreter";
    const technique_id = mapping.technique_id || "T1059";
    const entity_type = mapping.entity_type || "alert";
    const entity_id = mapping.entity_id || "alt-101";

    if (this.isPostgres && this.pool) {
      const res = await this.pool.query(
        `INSERT INTO mitre_mappings (id, tactic, technique, technique_id, entity_type, entity_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, tactic, technique, technique_id as "technique_id", entity_type as "entity_type", entity_id as "entity_id"`,
        [id, tactic, technique, technique_id, entity_type, entity_id]
      );
      return res.rows[0];
    }

    const db = this.readJsonDb();
    const newMapping: MitreMappingEntity = { id, tactic, technique, technique_id, entity_type, entity_id };
    db.mitre_mappings.push(newMapping);
    this.writeJsonDb(db);
    return newMapping;
  }

  public static async deleteMitreMapping(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      const res = await this.pool.query("DELETE FROM mitre_mappings WHERE id = $1", [id]);
      return (res.rowCount ?? 0) > 0;
    }
    const db = this.readJsonDb();
    const originalLength = db.mitre_mappings.length;
    db.mitre_mappings = db.mitre_mappings.filter((m) => m.id !== id);
    this.writeJsonDb(db);
    return db.mitre_mappings.length < originalLength;
  }
}
