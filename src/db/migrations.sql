-- SecAssistAI PostgreSQL Database Schema & Migration Setup
-- Generates and seeds tables for robust persistent SOC state management

-- 1. Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    domain VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Users (linked with organizations)
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(50) DEFAULT 'Analyst', -- 'Admin', 'Analyst', 'Viewer'
    tenant_id VARCHAR(50) REFERENCES organizations(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Alerts (linked with users & organizations)
CREATE TABLE IF NOT EXISTS alerts (
    id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    severity VARCHAR(20) DEFAULT 'Low', -- 'Critical', 'High', 'Medium', 'Low'
    category VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(50),
    dest_ip VARCHAR(50),
    status VARCHAR(30) DEFAULT 'Active', -- 'Active', 'Investigating', 'Resolved'
    description TEXT,
    assigned_to VARCHAR(100) REFERENCES users(email) ON DELETE SET NULL,
    tenant_id VARCHAR(50) REFERENCES organizations(id) ON DELETE SET NULL
);

-- 4. Incidents (linked with users & organizations)
CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    severity VARCHAR(20) DEFAULT 'Low',
    status VARCHAR(30) DEFAULT 'Open', -- 'Open', 'Investigating', 'Resolved'
    description TEXT,
    assigned_to VARCHAR(100) REFERENCES users(email) ON DELETE SET NULL,
    tenant_id VARCHAR(50) REFERENCES organizations(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. Assets (linked with users)
CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'Server', 'Endpoint', 'Cloud'
    ip_address VARCHAR(50) NOT NULL,
    os VARCHAR(100),
    criticality VARCHAR(20) DEFAULT 'Medium', -- 'Critical', 'High', 'Medium', 'Low'
    status VARCHAR(20) DEFAULT 'Online', -- 'Online', 'Offline', 'Investigating'
    owner VARCHAR(100) REFERENCES users(email) ON DELETE SET NULL,
    active_alerts_count INTEGER DEFAULT 0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. Vulnerabilities (linked with assets)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id VARCHAR(50) PRIMARY KEY, -- e.g., 'CVE-2024-3094'
    title VARCHAR(200) NOT NULL,
    score NUMERIC(3, 1) DEFAULT 0.0,
    severity VARCHAR(20) DEFAULT 'Low',
    affected_asset_id VARCHAR(50) REFERENCES assets(id) ON DELETE SET NULL,
    affected_asset_name VARCHAR(100),
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'In Progress', 'Patched'
    patch_recommendation TEXT,
    published_date VARCHAR(50),
    description TEXT
);

-- 7. Threat Intelligence
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    severity VARCHAR(20) DEFAULT 'Low',
    explanation TEXT,
    remediation TEXT,
    detection_signature TEXT,
    affected_assets JSONB -- list of affected components/servers
);

-- 8. Reports (linked with alerts & users)
CREATE TABLE IF NOT EXISTS reports (
    id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    alert_id VARCHAR(50) REFERENCES alerts(id) ON DELETE SET NULL,
    threat_name VARCHAR(100),
    severity VARCHAR(20) DEFAULT 'Low',
    executive_summary TEXT,
    technical_details TEXT,
    remediation_plan TEXT,
    generated_by VARCHAR(100) REFERENCES users(email) ON DELETE SET NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    root_cause_assessment TEXT,
    risk_rating VARCHAR(50)
);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS root_cause_assessment TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS risk_rating VARCHAR(50);

-- 9. Audit Logs (linked with users)
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(50) PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    uploaded_by VARCHAR(100) REFERENCES users(email) ON DELETE SET NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    parsed_count INTEGER DEFAULT 0,
    status VARCHAR(30) DEFAULT 'Analyzed', -- 'Pending', 'Analyzed', 'Failed'
    raw_content TEXT,
    analysis JSONB -- detailed AI analysis reports
);

-- 10. Compliance Records (GRC Scorecards)
CREATE TABLE IF NOT EXISTS compliance_records (
    id VARCHAR(50) PRIMARY KEY,
    framework VARCHAR(50) NOT NULL, -- 'SOC2', 'ISO27001', 'NIST', 'HIPAA'
    control_id VARCHAR(50) NOT NULL,
    control_name VARCHAR(200) NOT NULL,
    status VARCHAR(30) DEFAULT 'Compliant', -- 'Compliant', 'Non-Compliant', 'In Progress'
    maturity_score INTEGER DEFAULT 0, -- maturity level 0-100
    evidence TEXT,
    last_audited TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 11. MITRE ATT&CK Mappings
CREATE TABLE IF NOT EXISTS mitre_mappings (
    id VARCHAR(50) PRIMARY KEY,
    tactic VARCHAR(100) NOT NULL,
    technique VARCHAR(100) NOT NULL,
    technique_id VARCHAR(50) NOT NULL, -- e.g. T1071.001
    entity_type VARCHAR(50) NOT NULL, -- 'alert', 'threat', 'log'
    entity_id VARCHAR(50) NOT NULL
);


-- =========================================================================
-- HIGH FIDELITY REALISTIC SEED DATA
-- =========================================================================

-- Seed Organizations
INSERT INTO organizations (id, name, domain, created_at) VALUES
('tenant-alpha', 'SecAssistAI HQ', 'secassist.ai', NOW() - INTERVAL '30 days')
ON CONFLICT (id) DO NOTHING;

-- Seed Users
INSERT INTO users (id, name, email, role, tenant_id, created_at) VALUES
('u-1', 'Sarah Connor', 'admin@secassist.ai', 'Admin', 'tenant-alpha', NOW() - INTERVAL '30 days'),
('u-2', 'John Doe', 'analyst@secassist.ai', 'Analyst', 'tenant-alpha', NOW() - INTERVAL '30 days'),
('u-3', 'Marcus Wright', 'viewer@secassist.ai', 'Viewer', 'tenant-alpha', NOW() - INTERVAL '30 days')
ON CONFLICT (id) DO NOTHING;

-- Seed Alerts
INSERT INTO alerts (id, title, severity, category, timestamp, source_ip, dest_ip, status, description, assigned_to, tenant_id) VALUES
('alt-101', 'Ransomware C2 Beaconing Detected', 'Critical', 'Malware', NOW() - INTERVAL '2 hours', '10.100.12.45', '185.112.144.12', 'Active', 'Repeated outbound HTTPS connections to known LockBit C2 infrastructure. Pattern matches periodic 30-second beacon jitter.', 'analyst@secassist.ai', 'tenant-alpha'),
('alt-102', 'Active Directory Domain Controller Brute-Force', 'High', 'Credential Access', NOW() - INTERVAL '5 hours', '192.168.1.112', '10.100.1.4', 'Investigating', 'Over 450 failed authentication attempts for ''Administrator'' account within 3 minutes followed by a successful login event from external IP range.', 'analyst@secassist.ai', 'tenant-alpha'),
('alt-103', 'SQL Injection on Public Web Server', 'Medium', 'Initial Access', NOW() - INTERVAL '12 hours', '198.51.100.73', '10.100.5.10', 'Resolved', 'WAF block event triggered by payload containing ''UNION SELECT'' and ''--'' comments targeting product catalog API parameter ''id''.', 'admin@secassist.ai', 'tenant-alpha'),
('alt-104', 'Suspicious AWS IAM Privilege Escalation', 'Critical', 'Privilege Escalation', NOW() - INTERVAL '24 hours', '203.0.113.88', 'AWS-IAM-Service', 'Active', 'IAM user ''Dev-Admin-Temp'' successfully updated policy to include AdministratorAccess using a previously unused session token from TOR exit node.', 'admin@secassist.ai', 'tenant-alpha'),
('alt-105', 'Anomalous Bulk Data Exfiltration', 'High', 'Exfiltration', NOW() - INTERVAL '36 hours', '10.100.12.89', '91.189.91.157', 'Resolved', 'Upload of 14.2 GB of compressed archives (.tar.gz) from backup repository to public object storage endpoints over port 443.', 'analyst@secassist.ai', 'tenant-alpha')
ON CONFLICT (id) DO NOTHING;

-- Seed Incidents
INSERT INTO incidents (id, title, severity, status, description, assigned_to, tenant_id, created_at) VALUES
('inc-501', 'Critical Production Outpost LockBit Exposure', 'Critical', 'Investigating', 'A critical LockBit ransomware beacon was traced to endpoint ast-3 (Finance-WS-45). Immediate EDR containment pending.', 'analyst@secassist.ai', 'tenant-alpha', NOW() - INTERVAL '1 hour'),
('inc-502', 'AD Account Lockout Avalanche', 'High', 'Open', 'Multiple domain controllers reporting lockouts for key service accounts.', 'admin@secassist.ai', 'tenant-alpha', NOW() - INTERVAL '4 hours')
ON CONFLICT (id) DO NOTHING;

-- Seed Assets
INSERT INTO assets (id, name, type, ip_address, os, criticality, status, owner, active_alerts_count, last_seen) VALUES
('ast-1', 'AD-Domain-Controller', 'Server', '10.100.1.4', 'Windows Server 2022', 'Critical', 'Online', 'admin@secassist.ai', 1, NOW() - INTERVAL '1 minute'),
('ast-2', 'WAF-Public-Web', 'Server', '10.100.5.10', 'Ubuntu Linux 22.04 LTS', 'High', 'Online', 'admin@secassist.ai', 0, NOW() - INTERVAL '5 minutes'),
('ast-3', 'Finance-WS-45', 'Endpoint', '10.100.12.45', 'Windows 11 Enterprise', 'High', 'Investigating', 'analyst@secassist.ai', 1, NOW() - INTERVAL '10 seconds'),
('ast-4', 'Dev-WS-89', 'Endpoint', '10.100.12.89', 'macOS Sequoia', 'Medium', 'Online', 'analyst@secassist.ai', 0, NOW() - INTERVAL '12 minutes'),
('ast-5', 'AWS-Prod-Kubernetes', 'Cloud', '172.31.44.10', 'Linux CoreOS', 'Critical', 'Online', 'admin@secassist.ai', 1, NOW() - INTERVAL '30 seconds')
ON CONFLICT (id) DO NOTHING;

-- Seed Vulnerabilities
INSERT INTO vulnerabilities (id, title, score, severity, affected_asset_id, affected_asset_name, status, patch_recommendation, published_date, description) VALUES
('CVE-2024-3094', 'XZ Utils Backdoor Vulnerability', 10.0, 'Critical', 'ast-2', 'WAF-Public-Web', 'Open', 'Downgrade or upgrade xz-utils package to unbackdoored version (e.g. 5.6.1+ or 5.4.6) immediately.', '2024-03-29', 'Malicious code was discovered in upstream xz-utils tarballs starting with version 5.6.0, allowing unauthorized SSH execution bypass.'),
('CVE-2023-38606', 'Apple WebKit Remote Code Execution', 8.8, 'High', 'ast-4', 'Dev-WS-89', 'In Progress', 'Apply the latest macOS Ventura 13.5 or macOS Sonoma security patches.', '2023-07-24', 'A stateful validation vulnerability in WebKit allowed remote attackers to execute arbitrary code via specially crafted web content.'),
('CVE-2022-22965', 'Spring4Shell Remote Code Execution', 9.8, 'Critical', 'ast-2', 'WAF-Public-Web', 'Patched', 'Upgrade Spring Framework dependency to 5.3.18+ or 5.2.20+.', '2022-03-31', 'A Spring MVC or Spring WebFlux application running on JDK 9+ was vulnerable to remote code execution via data binding.'),
('CVE-2023-22515', 'Confluence Privilege Escalation Vulnerability', 10.0, 'Critical', 'ast-1', 'AD-Domain-Controller', 'Open', 'Upgrade Atlassian Confluence Server to versions 8.3.3+, 8.4.3+ or 8.5.2+ immediately.', '2023-10-04', 'A privilege escalation vulnerability in Confluence Data Center and Server allowed unauthenticated attackers to create administrator accounts.')
ON CONFLICT (id) DO NOTHING;

-- Seed Threat Intelligence
INSERT INTO threat_intelligence (id, name, severity, explanation, remediation, detection_signature, affected_assets) VALUES
('th-301', 'LockBit 3.0 Ransomware Campaign', 'Critical', 'Active ransomware strain targeting Windows/Linux directories via customized GPO scripting. Beacons out on encrypted HTTPS channels.', 'Ensure offsite immutable backups are validated. Disable lateral administrative shares (C$) where possible.', 'Outbound DNS requests resolving to *.lockbit.onion or related command and control web proxy IP addresses.', '["Internal Domain Controllers", "Active Directory Servers", "User Workstations"]'),
('th-302', 'Kerberoasting Exploit', 'High', 'Attacker queries Active Directory SPNs and requests ticket-granting service (TGS) tickets offline to crack passwords.', 'Enforce long passwords for service accounts (minimum 25 characters) or migrate to Group Managed Service Accounts (gMSA).', 'Event ID 4769 with RC4 encryption type (0x17) indicating vulnerable password cracking exposure.', '["Active Directory Services", "Database Service Accounts"]')
ON CONFLICT (id) DO NOTHING;

-- Seed Reports
INSERT INTO reports (id, title, alert_id, threat_name, severity, executive_summary, technical_details, remediation_plan, generated_by, timestamp) VALUES
('rep-401', 'Incident Report: Lockheed C2 Outbound Beaconing Activity', 'alt-101', 'LockBit C2 Beaconing Activity', 'Critical', 'On June 24, SecAssistAI detected a high-volume, highly persistent HTTP-beaconing threat emanating from the internal system 10.100.12.45. Analysis indicates LockBit ransomware payload beacon execution. Immediate isolation and host forensics are required.', 'The endpoint was found transferring periodic HTTP GET requests with structured base64 headers. Jitter matches the telemetry for LockBit proxy hosts. Network analysis confirmed connections to 185.112.144.12 on port 443.', '1. Network-isolate endpoint 10.100.12.45 via EDR controller.\n2. Revoke active Active Directory credentials for compromised endpoints.\n3. Run a threat hunt on surrounding systems for lateral traversal artifacts.\n4. Re-image the target operating system.', 'admin@secassist.ai', NOW() - INTERVAL '2 hours')
ON CONFLICT (id) DO NOTHING;

-- Seed Audit Logs
INSERT INTO audit_logs (id, filename, uploaded_by, timestamp, parsed_count, status, raw_content, analysis) VALUES
('log-201', 'auth_failures_ssh.log', 'analyst@secassist.ai', NOW() - INTERVAL '3 hours', 42, 'Analyzed', 'Jun 24 02:15:33 core-ssh-server sshd[12495]: Failed password for root from 185.220.101.44 port 43224 ssh2\nJun 24 02:15:35 core-ssh-server sshd[12497]: Failed password for root from 185.220.101.44 port 43228 ssh2\nJun 24 02:15:37 core-ssh-server sshd[12499]: Failed password for root from 185.220.101.44 port 43232 ssh2\nJun 24 02:15:40 core-ssh-server sshd[12501]: Accepted publickey for admin from 10.100.12.4 port 38222 ssh2', '{
  "threatLevel": "High",
  "threatName": "SSH Brute-Force Attack with Tor Exit Node Connection",
  "explanation": "An external IP (185.220.101.44) known to be associated with Tor exit networks repeatedly attempted to brute force the root user via SSH. Immediately following these attempts, a legitimate user ''admin'' authenticated successfully from an internal IP (10.100.12.4). While the root attempts were blocked, the correlation with internal activity requires monitoring.",
  "remediationSteps": [
    "Disable root SSH logins on core-ssh-server in /etc/ssh/sshd_config (PermitRootLogin no).",
    "Add IP 185.220.101.44 to the corporate perimeter firewall blocklist.",
    "Enable rate-limiting or install fail2ban on core-ssh-server.",
    "Verify the owner of internal IP 10.100.12.4 was active and authorised at 02:15."
  ],
  "mitreMapping": {
    "tactic": "Credential Access",
    "technique": "Brute Force: Password Guessing",
    "id": "T1110.001"
  },
  "suspiciousIndicators": [
    "185.220.101.44",
    "Failed password for root",
    "Multiple login attempts in a short timeframe (2 second intervals)"
  ]
}'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- Seed Compliance Records (GRC Core metrics)
INSERT INTO compliance_records (id, framework, control_id, control_name, status, maturity_score, evidence, last_audited) VALUES
('cr-601', 'SOC2', 'CC6.1', 'Access Control and User Authentication', 'Compliant', 90, 'Configured enterprise SSO, password length requirements of 16+ chars, and mandatory MFA. Automated monitoring reviews occur every 12 hours.', NOW() - INTERVAL '1 day'),
('cr-602', 'SOC2', 'CC7.1', 'Vulnerability Management', 'In Progress', 75, 'Daily automated container scans via SecAssistAI configured. Open CVE tracking dashboard updated live.', NOW() - INTERVAL '2 days'),
('cr-603', 'ISO27001', 'A.12.6.1', 'Management of Technical Vulnerabilities', 'Compliant', 85, 'Asset patch policies published. Active monitoring for critical zero-days like XZ utils is automated.', NOW() - INTERVAL '4 days'),
('cr-604', 'NIST', 'PR.AC-1', 'Access Control Policies and Procedures', 'Compliant', 95, 'Multi-tenant boundaries secured at the API controller layer. Tenant separation confirmed by annual compliance review.', NOW() - INTERVAL '10 days'),
('cr-605', 'HIPAA', '164.312(a)(1)', 'Access Controls (Unique User Identification)', 'Compliant', 80, 'Every system asset and user audit session is logged with unique base64 session authorization tokens.', NOW() - INTERVAL '5 days'),
('cr-606', 'GDPR', 'Article 32', 'Security of Processing', 'In Progress', 65, 'Database connection proxy layer encrypted. Data exports restricted to standard CSV file format.', NOW() - INTERVAL '6 days')
ON CONFLICT (id) DO NOTHING;

-- Seed MITRE Mappings
INSERT INTO mitre_mappings (id, tactic, technique, technique_id, entity_type, entity_id) VALUES
('mm-101', 'Command and Control', 'Application Layer Protocol: Web Protocols', 'T1071.001', 'alert', 'alt-101'),
('mm-102', 'Credential Access', 'Brute Force: Password Guessing', 'T1110.001', 'alert', 'alt-102'),
('mm-103', 'Initial Access', 'Exploit Public-Facing Application', 'T1190', 'alert', 'alt-103'),
('mm-104', 'Privilege Escalation', 'Abuse Access Token / Role Assumption', 'T1548', 'alert', 'alt-104'),
('mm-105', 'Exfiltration', 'Exfiltration Over Web Service', 'T1567.002', 'alert', 'alt-105')
ON CONFLICT (id) DO NOTHING;
