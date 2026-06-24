export interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  mitigations: string[];
  detectionRecommendations: string[];
}

export interface MitreTactic {
  tactic: string;
  techs: MitreTechnique[];
}

export const MITRE_ATTACK_MATRIX: MitreTactic[] = [
  {
    tactic: "Initial Access",
    techs: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        description: "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program to gain initial access to a network or system. This can include vulnerabilities in web servers, databases, or API gateways.",
        mitigations: [
          "Apply security patches to web servers, applications, and operating systems regularly.",
          "Use Web Application Firewalls (WAF) to filter out known malicious payloads and injection patterns.",
          "Perform regular vulnerability scanning and penetration testing on internet-facing assets.",
          "Enforce strict input validation and parameterization on all public entry points."
        ],
        detectionRecommendations: [
          "Monitor application and web server access logs for anomalous request structures, unusual status codes, or payload signatures (e.g., SQL injection, directory traversal).",
          "Analyze incoming network traffic to public-facing applications for sudden spikes or unexpected source IPs.",
          "Track database query activity for abnormal data requests or errors originating from public web applications."
        ]
      },
      {
        id: "T1566",
        name: "Phishing: Attachment & Link",
        description: "Adversaries may send phishing messages containing malicious attachments or links to gain execution of payload programs on victim hosts. Phishing is a highly effective vector for gaining initial footholds.",
        mitigations: [
          "Deploy secure email gateways (SEG) with attachment sandboxing and link rewriting policies.",
          "Conduct regular employee security awareness training on identifying phishing attempts.",
          "Configure email server rules (e.g., SPF, DKIM, DMARC) to block spoofed sender domains.",
          "Disable or restrict macros in office documents across the enterprise group policy."
        ],
        detectionRecommendations: [
          "Monitor mail transfer agent logs for anomalous volumes of emails from external domains containing executable or compressed attachments.",
          "Track endpoint process creation where the parent process is a common mail client (e.g., Outlook) or browser.",
          "Correlate DNS request queries with threat intelligence feeds for recently registered or low-reputation domains."
        ]
      }
    ]
  },
  {
    tactic: "Execution",
    techs: [
      {
        id: "T1059",
        name: "Command and Script Interpreter",
        description: "Adversaries may abuse command and script interpreters (such as PowerShell, cmd, bash, Python) to execute commands, templates, or scripts. This is commonly used to run malicious payloads and automate system exploration.",
        mitigations: [
          "Enforce PowerShell Constrained Language Mode (CLM) for standard non-administrative users.",
          "Restrict execution of scripting interpreters to authorized system administrators only.",
          "Implement AppLocker or Software Restriction Policies (SRP) to block unauthorized scripts.",
          "Deploy endpoint detection and response (EDR) to block suspicious script behaviors dynamically."
        ],
        detectionRecommendations: [
          "Enable deep transcript logging for PowerShell (Event ID 4104) and monitor command lines for base64 encoded strings or bypass flags (-ep bypass, -w hidden).",
          "Monitor process creation events for shell interpreters spawned by web servers, database processes, or office applications.",
          "Audit command-line arguments for scripts running out of unusual temporary paths (e.g., AppData\\Local\\Temp)."
        ]
      },
      {
        id: "T1204",
        name: "User Execution Payload",
        description: "An adversary may rely on a user to perform an action (e.g., executing a binary, running an attachment, enabling macros, clicking links) to trigger the execution of malicious code, bypassing traditional network defense barriers.",
        mitigations: [
          "Enforce application control blocklists to prevent execution of unknown binaries in user directories.",
          "Disable auto-execution of untrusted scripts or software downloads on endpoint clients.",
          "Conduct simulated phishing and execution tests to assess and improve user susceptibility.",
          "Apply robust browser isolation and sandboxing strategies."
        ],
        detectionRecommendations: [
          "Monitor endpoint process telemetry for users running executable formats (.exe, .scr, .lnk, .vbs) downloaded directly from web browsers or chat programs.",
          "Detect elevated privilege requests immediately following user-triggered application execution.",
          "Correlate file writes to user download folders with subsequent execution of those same files."
        ]
      }
    ]
  },
  {
    tactic: "Persistence",
    techs: [
      {
        id: "T1547",
        name: "Boot or Logon Autostart",
        description: "Adversaries may configure system settings to automatically run program payloads upon system boot or user login. This guarantees persistent access even if the system is restarted or the current active user session is terminated.",
        mitigations: [
          "Restrict write access to startup directories and autostart Registry keys (HKLM and HKCU Run/RunOnce) using strict Access Control Lists.",
          "Enable OS-level secure boot configurations and monitor bootloader modifications.",
          "Enforce least privilege, preventing normal users from writing to local machine startup services."
        ],
        detectionRecommendations: [
          "Audit modifications to Windows Registry autostart subkeys (e.g., Run, RunOnce, Winlogon, Shell).",
          "Monitor the creation of new files inside startup folders on multi-user endpoints.",
          "Detect unexpected executables starting automatically with system processes during boot phases."
        ]
      },
      {
        id: "T1543",
        name: "Create or Modify System Process",
        description: "Adversaries may create or modify system processes (such as Windows Services or systemd services) to repeatedly execute malicious payloads. This is a common method for executing code with SYSTEM privileges on a recurring interval.",
        mitigations: [
          "Limit privileges of system services to the least authority needed to function.",
          "Restrict administrative user capabilities to create, modify, or delete system-level services.",
          "Enforce configuration management rules to track and revert unauthorized service changes."
        ],
        detectionRecommendations: [
          "Monitor Windows Security Event ID 4697 (A service was installed in the system) and System Event ID 7045.",
          "Analyze system service configuration changes, specifically binary path changes, for anomalies.",
          "Check for daemon configuration additions in Linux systems (/etc/systemd/system/ or cron configurations)."
        ]
      }
    ]
  },
  {
    tactic: "Privilege Escalation",
    techs: [
      {
        id: "T1548",
        name: "Abuse Access Token / UAC",
        description: "Adversaries may bypass user account control (UAC) mechanisms or abuse access tokens to run processes with elevated administrator-level privileges. This enables adversaries to perform sensitive actions restricted from normal users.",
        mitigations: [
          "Configure User Account Control (UAC) to 'Always Notify' and require administrator credentials for elevation.",
          "Restrict normal user accounts from being members of local administrative or backup groups.",
          "Implement the least privilege architecture across all user endpoints."
        ],
        detectionRecommendations: [
          "Monitor for process creation executing from known UAC bypass registry paths or scheduled task templates.",
          "Detect processes with high integrity levels spawned from low integrity parent processes.",
          "Track execution of utilities designed to escalate privileges (e.g., fodhelper.exe, sdclt.exe) with unexpected arguments."
        ]
      },
      {
        id: "T1068",
        name: "Exploitation for Privilege",
        description: "Adversaries may exploit vulnerabilities in software, kernel drivers, or the operating system to elevate system privileges to Administrator or SYSTEM. This bypasses structural permission isolation controls.",
        mitigations: [
          "Maintain up-to-date operating system security patch baselines.",
          "Enable exploit mitigation techniques such as Data Execution Prevention (DEP) and Address Space Layout Randomization (ASLR).",
          "Minimize the use of non-standard or third-party kernel-mode drivers."
        ],
        detectionRecommendations: [
          "Monitor system event logs for kernel crash dumps or service exception alerts preceding privilege shifts.",
          "Detect high-privilege system processes launching with unexpected command lines or from odd file locations.",
          "Correlate vulnerability scan data with active endpoint exploit attempts in real time."
        ]
      }
    ]
  },
  {
    tactic: "Defense Evasion",
    techs: [
      {
        id: "T1562",
        name: "Impair Defenses",
        description: "Adversaries may maliciously modify system components to disable, degrade, or bypass security tools, event logging, or host-based firewall configurations. This hides active malicious operations and prevents timely incident response.",
        mitigations: [
          "Enforce tamper protection policies in EDR, antivirus, and firewall agents.",
          "Require multi-factor authentication or secondary authorization for disabling or modifying security services.",
          "Prevent standard administrators from stopping key security and log-forwarding processes."
        ],
        detectionRecommendations: [
          "Alert immediately on security agent service stop events (e.g., Event ID 7036 for Defender, CrowdStrike, or Sysmon).",
          "Monitor Registry modifications targeting security tools or log configuration parameters (e.g., under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender).",
          "Track command-line usage of service-halting utilities (e.g., sc config, net stop, taskkill /f /im security_agent.exe)."
        ]
      },
      {
        id: "T1070",
        name: "Indicator Removal on Host",
        description: "Adversaries may clear system, security, or application event logs, history files, or directory contents to hide evidence of intrusion and prevent analysts from conducting full post-incident forensic investigations.",
        mitigations: [
          "Configure log forwarding to real-time central SIEM servers immediately upon creation.",
          "Restrict the privilege to clear or modify local event logs to dedicated non-compromised service accounts.",
          "Encrypt local log storage to prevent raw read-write bypass by hostile administrative tools."
        ],
        detectionRecommendations: [
          "Alert on Windows Security Event ID 1102 (The audit log was cleared) or System Event ID 104.",
          "Track command-line activity attempting to delete log directories or history logs (e.g., wevtutil.exe cl, rm -rf /var/log/*).",
          "Analyze sudden, unexplained gaps in telemetry stream metrics from specific target host endpoints."
        ]
      }
    ]
  },
  {
    tactic: "Credential Access",
    techs: [
      {
        id: "T1110.001",
        name: "Brute Force: Password Guessing",
        description: "Adversaries may use brute-force attacks such as direct password guessing, dictionary-based lookups, or automated sprays across multi-user environments to crack accounts and obtain active system credential access.",
        mitigations: [
          "Enforce multi-factor authentication (MFA) on all network login entry portals.",
          "Configure account lockout policies (e.g., lock account for 30 minutes after 5 failed attempts).",
          "Ensure password complexity requirements prevent dictionary or weak-guess credentials.",
          "Rotate administrative accounts and service tokens periodically."
        ],
        detectionRecommendations: [
          "Monitor for high frequencies of authentication failures (Event ID 4625) targeting a single user account from a single source IP.",
          "Detect password-spraying attempts characterized by single failed authentication attempts targeting many different accounts in a short time.",
          "Correlate failed authentication source IPs with threat intel lists of Tor nodes, proxy endpoints, or known botnet addresses."
        ]
      },
      {
        id: "T1558",
        name: "Steal/Forge Kerberos Ticket",
        description: "Adversaries may request Kerberos ticket-granting service (TGS) tickets for service principal names (SPNs) from Active Directory, subsequently attempting to crack the ticket passwords offline (Kerberoasting). This yields service account creds.",
        mitigations: [
          "Enforce strong service account password policies (minimum 25 characters, high randomness).",
          "Utilize Group Managed Service Accounts (gMSA) where password rotation is handled by Active Directory.",
          "Limit domain account permissions to prevent bulk SPN listing actions."
        ],
        detectionRecommendations: [
          "Audit Windows Security Event ID 4769 (A Kerberos service ticket was requested) specifically looking for weak encryption types like RC4 (0x17).",
          "Detect anomalous quantities of service ticket requests within short intervals originating from standard non-developer workstations.",
          "Analyze domain query logs for broad listing commands querying SPN mappings."
        ]
      }
    ]
  },
  {
    tactic: "Discovery",
    techs: [
      {
        id: "T1018",
        name: "System Network Discovery",
        description: "Adversaries may attempt to discover active network connections, routing tables, and neighboring live systems within the compromised subnet to build lateral movement targets and map routing paths.",
        mitigations: [
          "Implement host-based firewalls to prevent lateral peer-to-peer scanning and packet capture.",
          "Enforce strict network segmentation separating endpoint subnets from server zones."
        ],
        detectionRecommendations: [
          "Track execution of discovery utilities (e.g., ping, arp, netstat, route, nmap) by users who do not have system administration roles.",
          "Monitor firewall and network sensor logs for high-volume peer-to-peer sweeps on critical ports (e.g., 445, 135, 22, 3389).",
          "Detect rapid sequence port scans originating from single internal endpoints."
        ]
      },
      {
        id: "T1087",
        name: "Account Discovery",
        description: "Adversaries may attempt to list domain or local system accounts, user groups, and privilege mappings to determine high-value targets, active administrators, and credential cracking potential.",
        mitigations: [
          "Limit general read access to Active Directory LDAP schemas for standard domain users.",
          "Avoid using standard predictable names for service or administrative user groups."
        ],
        detectionRecommendations: [
          "Monitor local process telemetry for execution of account-enumeration queries (e.g., net user, net group, dsquery, whoami).",
          "Audit domain controller security logs for elevated LDAP search activity or unusual Active Directory structural queries.",
          "Track endpoint scripting logs for batch-based automated enumeration patterns."
        ]
      }
    ]
  },
  {
    tactic: "Lateral Movement",
    techs: [
      {
        id: "T1021",
        name: "Remote Services (RDP, SSH)",
        description: "Adversaries may abuse valid credentials to log in to remote services (such as Remote Desktop, SSH, or WinRM) on internal servers, allowing them to traverse laterally and execute code across the infrastructure.",
        mitigations: [
          "Enforce multi-factor authentication (MFA) for internal lateral remote desk logins.",
          "Disable RDP, SSH, and remote shell capabilities on endpoints where not strictly necessary.",
          "Utilize jump hosts and restrict direct peer-to-peer RDP/SSH routing."
        ],
        detectionRecommendations: [
          "Monitor Event ID 4624 (Successful Logon) with Logon Type 10 (RDP) or Logon Type 3 (Network) across internal servers.",
          "Audit SSH logs for credential logins traversing from one endpoint directly to another inside the same client subnet.",
          "Track anomalous lateral session timing, such as administrative access outside normal working hours."
        ]
      }
    ]
  },
  {
    tactic: "Command and Control",
    techs: [
      {
        id: "T1071.001",
        name: "Web Protocols Beaconing",
        description: "Adversaries may communicate using application-layer web protocols (HTTP, HTTPS) to blend command and control beacon traffic with legitimate outbound corporate web browsing activity.",
        mitigations: [
          "Deploy SSL/TLS inspection on web proxies to analyze encrypted outbound payload structures.",
          "Implement DNS and URL web filtering to block traffic resolving to newly registered, low-reputation, or dynamic IP networks.",
          "Enforce strict egress filtering restricting direct outbound web connections to approved corporate proxy servers."
        ],
        detectionRecommendations: [
          "Analyze proxy and network sensor logs for persistent, outbound connections displaying structured periodic intervals (jitter matching beacon patterns).",
          "Detect outbound HTTP/S requests with unusual User-Agent headers, invalid SSL certificate structures, or unexpected payload sizes.",
          "Identify outbound web connections referencing IP addresses directly rather than resolving standard domain hostnames."
        ]
      },
      {
        id: "T1071.004",
        name: "DNS Query Tunneling",
        description: "Adversaries may encode command and control instructions or stolen data within DNS query parameters (e.g., TXT or CNAME records). This bypasses traditional firewall blocks because DNS traffic is universally permitted.",
        mitigations: [
          "Configure enterprise DNS servers to block requests resolving to newly registered domains or dynamic DNS services.",
          "Enforce structural DNS query volume rate limits on internal clients.",
          "Implement security appliances capable of real-time DNS packet inspection."
        ],
        detectionRecommendations: [
          "Monitor internal DNS server logs for abnormally high volumes of subdomains resolved under a single parent domain (e.g., query-data.malicious-c2.com).",
          "Identify DNS query payloads containing high entropy strings, base64 data strings, or large TXT records.",
          "Track endpoints communicating directly with external DNS servers bypassing designated corporate name resolution systems."
        ]
      }
    ]
  },
  {
    tactic: "Exfiltration",
    techs: [
      {
        id: "T1567.002",
        name: "Exfil to Web Storage",
        description: "Adversaries may leverage existing cloud storage or web-hosting services (such as Dropbox, Google Drive, OneDrive, Mega) to exfiltrate compressed or encrypted archives. This blends exfil data with legitimate cloud usage traffic.",
        mitigations: [
          "Deploy Data Loss Prevention (DLP) endpoint rules to block bulk file copying to unapproved cloud endpoints.",
          "Implement cloud access security broker (CASB) rules to restrict access to unsanctioned web-storage platforms.",
          "Block outbound connection routes to generic file-sharing hostnames."
        ],
        detectionRecommendations: [
          "Audit proxy and firewall logs for massive file upload actions or sustained egress bandwidth utilization to known public storage API domains.",
          "Detect user endpoints running non-approved cloud sync clients in the background.",
          "Correlate local compression actions (e.g. creating large zip or tar files) immediately followed by high outbound web-service connections."
        ]
      },
      {
        id: "T1048",
        name: "Exfiltration Over Port 443",
        description: "Adversaries may exfiltrate data using alternative protocols or raw TCP channels mapped to port 443 (commonly used for HTTPS) to sneak compressed payloads past simple port-filtering firewalls.",
        mitigations: [
          "Implement application-layer deep packet inspection (DPI) to enforce protocol compliance (e.g., block raw SSH or TCP tunnels over port 443).",
          "Restrict outbound connections on port 443 to validated external corporate domains only."
        ],
        detectionRecommendations: [
          "Analyze outbound network session metrics on port 443 for non-compliant SSL handshakes or raw socket-level communication profiles.",
          "Identify abnormal data transfer volume sizes on port 443 initiated from non-server endpoints.",
          "Detect long-duration, high-bandwidth outbound TCP connections to unclassified external IP ranges."
        ]
      }
    ]
  },
  {
    tactic: "Impact",
    techs: [
      {
        id: "T1486",
        name: "Data Encrypted for Impact",
        description: "Adversaries may encrypt user or system data on target systems to interrupt system and business operations. They typically demand financial ransoms to provide decryption keys, causing severe operational disruptions.",
        mitigations: [
          "Maintain daily immutable, offline, or air-gapped data backups and test restore cycles regularly.",
          "Deploy automated ransomware protection features in local EDR or antivirus software to halt mass file modifications.",
          "Enforce least privilege access controls, preventing normal users from editing system files or broad shared network drives."
        ],
        detectionRecommendations: [
          "Detect rapid sequences of file modification and renaming events (e.g., appending extension names like .lockbit, .clop) inside system directories.",
          "Audit CPU and I/O metrics on endpoints for sudden sustained spikes caused by bulk cryptographic calculations.",
          "Monitor for mass deletion or clearing of Volume Shadow Copies (vssadmin.exe delete shadows) preceding encryption."
        ]
      }
    ]
  }
];
