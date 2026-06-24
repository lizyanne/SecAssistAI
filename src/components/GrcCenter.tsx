import React, { useState } from "react";
import {
  Shield,
  FileText,
  AlertTriangle,
  CheckCircle,
  XCircle,
  TrendingUp,
  Download,
  Users,
  Briefcase,
  History,
  FileCheck,
  Search,
  Plus,
  PlusCircle,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  Sparkles,
  ClipboardList,
  RefreshCw
} from "lucide-react";
import {
  ResponsiveContainer,
  ComposedChart,
  Line,
  Area,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  Cell,
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis
} from "recharts";

interface GrcCenterProps {
  token: string | null;
}

// Interfaces for our compliance records
interface Risk {
  id: string;
  title: string;
  category: "Access" | "Network" | "Data Security" | "Identity" | "Configuration";
  severity: "Critical" | "High" | "Medium" | "Low";
  likelihood: number; // 1-5
  impact: number; // 1-5
  score: number; // likelihood * impact (1-25)
  owner: string;
  treatment: "Mitigate" | "Accept" | "Transfer" | "Avoid";
  remediationPlan: string;
  progress: number; // percentage
  correlatedIssue?: string;
}

interface ComplianceControl {
  id: string;
  name: string;
  category: string;
  frameworks: ("ISO 27001" | "NIST CSF" | "SOC 2" | "CIS Controls")[];
  status: "Compliant" | "Partially Compliant" | "Non-Compliant";
  effectiveness: number; // 0-100%
  lastTested: string;
  testingHistory: { date: string; result: "Pass" | "Fail"; details: string; tester: string }[];
  evidenceFiles: string[];
}

interface GapFinding {
  id: string;
  controlName: string;
  framework: string;
  controlId: string;
  priority: "Critical" | "High" | "Medium" | "Low";
  gapDescription: string;
  recommendation: string;
  status: "Open" | "In Progress" | "Resolved";
}

export default function GrcCenter({ token }: GrcCenterProps) {
  // GRC Center inner tab state
  const [activeSubTab, setActiveSubTab] = useState<"dashboard" | "risks" | "controls" | "gap" | "audit" | "reports">("dashboard");

  // Filter framework on Dashboard or Control library
  const [selectedFramework, setSelectedFramework] = useState<"All" | "ISO 27001" | "NIST CSF" | "SOC 2" | "CIS Controls">("All");

  // Search keyword for controls
  const [controlSearch, setControlSearch] = useState<string>("");

  // Risks list (correlated with standard system threats like ransomware, SSH brute force, AWS IAM exfil, etc.)
  const [risks, setRisks] = useState<Risk[]>([
    {
      id: "RSK-201",
      title: "Credential Spraying & SSH Brute Force Attacks",
      category: "Access",
      severity: "High",
      likelihood: 4,
      impact: 4,
      score: 16,
      owner: "SecOps Lead (T. Miller)",
      treatment: "Mitigate",
      remediationPlan: "Deploy rate-limiting policies in API proxy gateway, force MFA, and trigger cloud server lockdown if thresholds exceed limit.",
      progress: 75,
      correlatedIssue: "Correlated: Active SSH Brute Force Attack Simulation"
    },
    {
      id: "RSK-202",
      title: "Ransomware Exfiltration & Malicious DNS Tunneling",
      category: "Network",
      severity: "Critical",
      likelihood: 3,
      impact: 5,
      score: 15,
      owner: "Network Architect (L. Vance)",
      treatment: "Mitigate",
      remediationPlan: "Implement deep packet inspection (DPI) in DNS firewalls, audit egress DNS traffic query volume, and enforce client isolations.",
      progress: 45,
      correlatedIssue: "Correlated: Ransomware DNS Tunneling Alerts"
    },
    {
      id: "RSK-203",
      title: "AWS Cloud Environment IAM Privilege Escalation",
      category: "Identity",
      severity: "Critical",
      likelihood: 3,
      impact: 5,
      score: 15,
      owner: "Cloud Sec Engineer (R. Diaz)",
      treatment: "Mitigate",
      remediationPlan: "Audit IAM wildcards, enforce strict row-level segregation in PostgreSQL storage layers, and restrict role creation API keys.",
      progress: 60,
      correlatedIssue: "Correlated: AWS IAM privilege exfil indicators"
    },
    {
      id: "RSK-204",
      title: "Unpatched Outdated Web Servers (CVE Vulnerability)",
      category: "Configuration",
      severity: "Medium",
      likelihood: 4,
      impact: 3,
      score: 12,
      owner: "SecDev Lead (S. Chen)",
      treatment: "Mitigate",
      remediationPlan: "Weekly vulnerability scans with automatic playbooks triggering patch actions for packages flagged above CVSS 7.0.",
      progress: 90,
      correlatedIssue: "Correlated: CVE-2024 Vulnerabilities on asset servers"
    },
    {
      id: "RSK-205",
      title: "Exposure of Private Encryption Keys on Storage Buckets",
      category: "Data Security",
      severity: "Critical",
      likelihood: 2,
      impact: 5,
      score: 10,
      owner: "DevOps Lead (J. Carter)",
      treatment: "Avoid",
      remediationPlan: "Migrate static configs to secure KMS systems, revoke public permissions on cloud buckets, and rotate keys every 90 days.",
      progress: 100,
      correlatedIssue: "Correlated: Cloud Storage Asset scans"
    },
    {
      id: "RSK-206",
      title: "Lack of Immature Syslog Write-Once Protections",
      category: "Data Security",
      severity: "Medium",
      likelihood: 3,
      impact: 3,
      score: 9,
      owner: "Audit Lead (M. Watson)",
      treatment: "Accept",
      remediationPlan: "Accepted after evaluation of offset log sinks. Forwarder duplicates logs to high fidelity airgapped write-once archives.",
      progress: 100,
      correlatedIssue: "Audited System Logs"
    }
  ]);

  // Expanded risk id for details
  const [expandedRiskId, setExpandedRiskId] = useState<string | null>(null);

  // GRC Controls library
  const [controls, setControls] = useState<ComplianceControl[]>([
    {
      id: "CTRL-101",
      name: "Multifactor Authentication Enforcement",
      category: "Access & Identity",
      frameworks: ["ISO 27001", "NIST CSF", "SOC 2"],
      status: "Compliant",
      effectiveness: 98,
      lastTested: "2026-06-20",
      testingHistory: [
        { date: "2026-06-20", result: "Pass", details: "MFA challenge successfully enforced for 100% of administration logins.", tester: "M. Watson" },
        { date: "2026-03-15", result: "Pass", details: "Verified identity challenges across federation providers.", tester: "M. Watson" }
      ],
      evidenceFiles: ["mfa_policy_signoff_2026.pdf", "okta_challenge_audit_log.csv"]
    },
    {
      id: "CTRL-102",
      name: "Row-Level Database Access Segregation",
      category: "Data Security & Multi-Tenancy",
      frameworks: ["SOC 2", "ISO 27001"],
      status: "Compliant",
      effectiveness: 100,
      lastTested: "2026-06-18",
      testingHistory: [
        { date: "2026-06-18", result: "Pass", details: "Row level restriction validated. Verified that Tenant A database queries strictly block Tenant B indicators.", tester: "M. Watson" }
      ],
      evidenceFiles: ["postgres_tenant_rls_rules.sql", "penetration_test_tenant_isolation_results.pdf"]
    },
    {
      id: "CTRL-103",
      name: "Continuous Vulnerability Scanning & Remediation",
      category: "Threat Management",
      frameworks: ["NIST CSF", "CIS Controls", "ISO 27001"],
      status: "Partially Compliant",
      effectiveness: 70,
      lastTested: "2026-06-22",
      testingHistory: [
        { date: "2026-06-22", result: "Pass", details: "Scans active. However, 2 open medium CVE findings on web-server-04 still awaiting patches.", tester: "M. Watson" },
        { date: "2026-05-10", result: "Fail", details: "Scan missed due to automated cron script credentials expiry error.", tester: "System Daemon" }
      ],
      evidenceFiles: ["vulnerability_weekly_status_2026-06-22.json"]
    },
    {
      id: "CTRL-104",
      name: "Immutability & Write-Once System Logs",
      category: "Audit Logging",
      frameworks: ["SOC 2", "CIS Controls"],
      status: "Partially Compliant",
      effectiveness: 65,
      lastTested: "2026-06-14",
      testingHistory: [
        { date: "2026-06-14", result: "Pass", details: "Logs forwarded to SIEM, but immutability storage vault block lock is not yet locked on cold-storage archive buckets.", tester: "M. Watson" }
      ],
      evidenceFiles: ["cold_bucket_policy_draft.json"]
    },
    {
      id: "CTRL-105",
      name: "Least Privilege Cloud IAM Rules Check",
      category: "Identity",
      frameworks: ["NIST CSF", "CIS Controls"],
      status: "Non-Compliant",
      effectiveness: 30,
      lastTested: "2026-06-10",
      testingHistory: [
        { date: "2026-06-10", result: "Fail", details: "Discovered 4 cloud IAM credentials with wildcard '*' permissions in active developer roles.", tester: "R. Diaz" }
      ],
      evidenceFiles: ["failed_iam_wildcard_audit.json"]
    },
    {
      id: "CTRL-106",
      name: "End-to-End Transport Layer Encryption (TLS 1.3)",
      category: "Data Security",
      frameworks: ["ISO 27001", "SOC 2", "CIS Controls"],
      status: "Compliant",
      effectiveness: 95,
      lastTested: "2026-06-12",
      testingHistory: [
        { date: "2026-06-12", result: "Pass", details: "Validated TLS cipher suites across external and internal proxy API routers. Retained perfect forward secrecy.", tester: "T. Miller" }
      ],
      evidenceFiles: ["nginx_proxy_ssl_config.conf"]
    }
  ]);

  // Selected Control for expansion or testing history view
  const [selectedControlId, setSelectedControlId] = useState<string | null>(null);

  // Evidence upload simulator state
  const [uploadControlId, setUploadControlId] = useState<string | null>(null);
  const [evidenceFileName, setEvidenceFileName] = useState<string>("");
  const [isUploading, setIsUploading] = useState<boolean>(false);

  // Gap Findings List
  const [gapFindings, setGapFindings] = useState<GapFinding[]>([
    {
      id: "GAP-301",
      controlName: "Cloud Infrastructure Privilege Auditing",
      framework: "NIST CSF PR.AC-1",
      controlId: "CTRL-105",
      priority: "Critical",
      gapDescription: "Developer cloud roles are active with administrator-like wildcard permissions, causing vulnerability to AWS privilege exfiltration attacks.",
      recommendation: "Reconstruct IAM policies into micro-roles, revoke wildcard assignments, and configure automated scans to flag custom IAM creations.",
      status: "In Progress"
    },
    {
      id: "GAP-302",
      controlName: "Log File Vault Airgap Locking",
      framework: "SOC 2 CC7.1",
      controlId: "CTRL-104",
      priority: "High",
      gapDescription: "Local logs are compiled and written, but do not yet sit in a write-once logical airgapped lock state, meaning a compromise of server privileges could result in local logs modification.",
      recommendation: "Activate Bucket Lock feature in Cloud Storage policies with a retention window of 365 days, and enforce strict append-only constraints.",
      status: "Open"
    },
    {
      id: "GAP-303",
      controlName: "Automated Micro-Patching for Host Vulnerabilities",
      framework: "CIS Controls 7.4",
      controlId: "CTRL-103",
      priority: "Medium",
      gapDescription: "Vulnerability scan reveals open medium score vulnerabilities on core asset server systems, needing manual triggers to complete patching.",
      recommendation: "Activate the automated patch runner workflow to roll updates onto sandbox systems before staging into the production environment.",
      status: "In Progress"
    }
  ]);

  // Executive summary states
  const [executiveAuthor, setExecutiveAuthor] = useState<string>("Chief Information Security Officer");
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);
  const [generatedMarkdownReport, setGeneratedMarkdownReport] = useState<string | null>(null);

  // Framework overall calculations
  const calculateFrameworkScore = (framework: string) => {
    const relevantControls = controls.filter(c => framework === "All" || c.frameworks.includes(framework as any));
    if (relevantControls.length === 0) return 100;
    const totalEffectiveness = relevantControls.reduce((sum, c) => sum + c.effectiveness, 0);
    return Math.round(totalEffectiveness / relevantControls.length);
  };

  const getOverallComplianceScore = () => {
    return Math.round(controls.reduce((sum, c) => sum + c.effectiveness, 0) / controls.length);
  };

  const frameworkScores = {
    "ISO 27001": calculateFrameworkScore("ISO 27001"),
    "NIST CSF": calculateFrameworkScore("NIST CSF"),
    "SOC 2": calculateFrameworkScore("SOC 2"),
    "CIS Controls": calculateFrameworkScore("CIS Controls")
  };

  const overallScore = getOverallComplianceScore();

  // Dynamic audit logs (Simulated realistic GRC logging trail)
  const auditLogs = [
    { date: "2026-06-24T06:20:12Z", user: "T. Miller", action: "Triggered active SSH brute force remediation workflow", module: "Incident Triage", outcome: "Success", severity: "Low" },
    { date: "2026-06-24T05:44:00Z", user: "M. Watson", action: "Conducted testing on Database Isolation control (CTRL-102)", module: "GRC Controls", outcome: "Pass", severity: "Low" },
    { date: "2026-06-23T11:15:22Z", user: "R. Diaz", action: "Uploaded evidence file failed_iam_wildcard_audit.json", module: "Control Library", outcome: "Success", severity: "Low" },
    { date: "2026-06-22T18:30:10Z", user: "System Scheduler", action: "Completed vulnerability weekly cron scan of asset servers", module: "Vulnerability Scan", outcome: "Completed", severity: "Low" },
    { date: "2026-06-21T09:40:15Z", user: "J. Carter", action: "Modified bucket retention policies on cold-log storage buckets", module: "Policy Center", outcome: "Success", severity: "Medium" },
    { date: "2026-06-20T14:52:11Z", user: "M. Watson", action: "Tested Multifactor Authentication Enforcement (CTRL-101)", module: "GRC Controls", outcome: "Pass", severity: "Low" },
  ];

  // Radar chart data for framework scores
  const radarData = [
    { subject: "ISO 27001", A: frameworkScores["ISO 27001"], fullMark: 100 },
    { subject: "NIST CSF", A: frameworkScores["NIST CSF"], fullMark: 100 },
    { subject: "SOC 2", A: frameworkScores["SOC 2"], fullMark: 100 },
    { subject: "CIS Controls", A: frameworkScores["CIS Controls"], fullMark: 100 },
  ];

  // Historical compliance trends data
  const trendData = [
    { month: "Jan", ISO: 72, NIST: 68, SOC: 74, CIS: 60, RiskPosture: 58 },
    { month: "Feb", ISO: 74, NIST: 70, SOC: 76, CIS: 62, RiskPosture: 61 },
    { month: "Mar", ISO: 78, NIST: 73, SOC: 77, CIS: 65, RiskPosture: 65 },
    { month: "Apr", ISO: 80, NIST: 76, SOC: 81, CIS: 69, RiskPosture: 70 },
    { month: "May", ISO: 85, NIST: 79, SOC: 84, CIS: 72, RiskPosture: 74 },
    { month: "Jun (Current)", ISO: frameworkScores["ISO 27001"], NIST: frameworkScores["NIST CSF"], SOC: frameworkScores["SOC 2"], CIS: frameworkScores["CIS Controls"], RiskPosture: 78 },
  ];

  // Simulator to upload an evidence file
  const handleUploadEvidence = (controlId: string) => {
    setUploadControlId(controlId);
    setEvidenceFileName("");
  };

  const submitEvidenceUpload = (e: React.FormEvent) => {
    e.preventDefault();
    if (!evidenceFileName.trim()) return;

    setIsUploading(true);
    setTimeout(() => {
      setControls(prev => prev.map(ctrl => {
        if (ctrl.id === uploadControlId) {
          return {
            ...ctrl,
            evidenceFiles: [...ctrl.evidenceFiles, evidenceFileName.trim()],
            // Slightly improve control effectiveness when evidence is uploaded
            effectiveness: Math.min(100, ctrl.effectiveness + 5),
            status: ctrl.effectiveness + 5 >= 95 ? "Compliant" : ctrl.status
          };
        }
        return ctrl;
      }));
      setIsUploading(false);
      setUploadControlId(null);
      setEvidenceFileName("");
    }, 1500);
  };

  // Compile Executive Report Draft
  const generateBoardReport = () => {
    setIsGeneratingReport(true);
    setTimeout(() => {
      const activeRisks = risks.filter(r => r.severity === "Critical" || r.severity === "High");
      const uncompliantControls = controls.filter(c => c.status !== "Compliant");
      const openGaps = gapFindings.filter(g => g.status !== "Resolved");

      const report = `# EXECUTIVE SECURITY & COMPLIANCE BOARD REPORT
*Generated on 2026-06-24T06:34:17Z by CISO Executive Compiler*

## 1. Executive Summary
Alpha Corporation's overall security architecture and controls alignment has been evaluated. The current comprehensive **Corporate Security Score stands at ${overallScore}/100**, placing the platform posture in a **Hardened Audit state**. Key threats such as SSH brute forcing, malicious DNS tunneling attempts, and IAM privilege wildcard policies are actively addressed and mitigated.

## 2. Framework Maturity Index
*   **ISO 27001 Validation Score**: ${frameworkScores["ISO 27001"]}% alignment
*   **NIST Cybersecurity Framework Index**: ${frameworkScores["NIST CSF"]}% alignment
*   **SOC 2 Trust Services Criteria Criteria**: ${frameworkScores["SOC 2"]}% alignment
*   **CIS Top 18 Controls implementation Checklist**: ${frameworkScores["CIS Controls"]}% alignment

## 3. Top Risk Matrix & Mitigation Actions
We are managing **${activeRisks.length} High or Critical Risks** correlated with our active SIEM incidents:
${activeRisks.map(r => `*   **${r.id} (${r.severity})**: ${r.title} - *Owner: ${r.owner}*. Status: Treatment [${r.treatment}] with ${r.progress}% remediation completed. Plan: ${r.remediationPlan}`).join("\n")}

## 4. Control Gaps & Action Recommendations
To push our compliance framework scores past 95%, we recommend immediate execution of the following remediation workflows:
${openGaps.map(g => `*   **${g.id} [${g.priority} Priority]** on ${g.framework}: ${g.gapDescription}\n    *Recommendation*: ${g.recommendation}`).join("\n")}

## 5. Certificate Sign-off Verification
This board summary has been digitally signed and sealed.
*   **Sealed by**: ${executiveAuthor}
*   **Verification Hash**: SHA256_GRC_BLOCK_${overallScore}_ALPHA_CORP
`;
      setGeneratedMarkdownReport(report);
      setIsGeneratingReport(false);
    }, 2000);
  };

  return (
    <div className="space-y-6">
      {/* Sub-tabs menu */}
      <div className="flex border-b border-white/5 pb-px gap-2 overflow-x-auto">
        {[
          { id: "dashboard", label: "GRC Dashboard", icon: ClipboardList },
          { id: "risks", label: "Risk Register", icon: AlertTriangle },
          { id: "controls", label: "Security Controls Library", icon: Shield },
          { id: "gap", label: "Gap Analysis Engine", icon: FileCheck },
          { id: "audit", label: "Audit Center & Logs", icon: History },
          { id: "reports", label: "Executive Board Reports", icon: FileText }
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id as any)}
              className={`px-4 py-2.5 text-xs font-mono font-bold transition-all border-b-2 cursor-pointer flex items-center gap-2 whitespace-nowrap ${
                activeSubTab === tab.id
                  ? "border-[#00E5FF] text-[#00E5FF] bg-white/[0.02]"
                  : "border-transparent text-slate-400 hover:text-slate-100 hover:bg-white/[0.01]"
              }`}
            >
              <Icon size={14} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* DASHBOARD TAB VIEW */}
      {activeSubTab === "dashboard" && (
        <div className="space-y-6">
          {/* Top KPI Score Widgets */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block">Overall GRC Score</span>
              <div className="flex items-baseline gap-2 mt-2">
                <span className="text-4xl font-extrabold tracking-tight text-[#00E5FF]">{overallScore}%</span>
                <span className="text-xs text-slate-400">Total Compliant</span>
              </div>
              <div className="w-full bg-white/5 h-1 rounded-full mt-3 overflow-hidden">
                <div className="bg-[#00E5FF] h-full" style={{ width: `${overallScore}%` }}></div>
              </div>
            </div>

            {/* Total Findings count */}
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block">Open Gap Findings</span>
              <div className="flex items-baseline gap-2 mt-2">
                <span className="text-4xl font-extrabold tracking-tight text-amber-400">
                  {gapFindings.filter(g => g.status !== "Resolved").length}
                </span>
                <span className="text-xs text-slate-400">Remediating Gaps</span>
              </div>
              <span className="text-[10px] font-mono text-slate-400 mt-2 block">
                {gapFindings.filter(g => g.priority === "Critical").length} Critical • {gapFindings.filter(g => g.priority === "High").length} High Priority
              </span>
            </div>

            {/* Managed Risks */}
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block">Corporate Risks Registered</span>
              <div className="flex items-baseline gap-2 mt-2">
                <span className="text-4xl font-extrabold tracking-tight text-rose-400">
                  {risks.length}
                </span>
                <span className="text-xs text-slate-400">Active Risks</span>
              </div>
              <span className="text-[10px] font-mono text-slate-400 mt-2 block">
                Avg Likelihood Matrix: {(risks.reduce((sum, r) => sum + r.likelihood, 0) / risks.length).toFixed(1)}/5
              </span>
            </div>

            {/* Framework alignment Card */}
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block">Framework Alignment</span>
              <div className="flex items-baseline gap-2 mt-2">
                <span className="text-3xl font-extrabold tracking-tight text-emerald-400">4 / 4</span>
                <span className="text-xs text-slate-400">Active Frameworks</span>
              </div>
              <span className="text-[10px] font-mono text-slate-400 mt-2 block truncate">
                ISO 27001 • NIST CSF • SOC 2 • CIS
              </span>
            </div>
          </div>

          {/* GRC Visual Analytics Chart Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* Chart Left 2 Cols: Compliance trends & frameworks */}
            <div className="lg:col-span-2 p-5 rounded-2xl bg-white/[0.02] border border-white/5 space-y-4">
              <div className="flex justify-between items-center pb-2 border-b border-white/5">
                <div>
                  <h3 className="text-sm font-semibold text-white flex items-center gap-1.5">
                    <TrendingUp size={15} className="text-[#00E5FF]" />
                    Corporate Compliance Score Trends (H1 2026)
                  </h3>
                  <p className="text-[11px] text-slate-400">Visual trends of audit alignment progress mapped against framework updates.</p>
                </div>
              </div>

              {/* Trend charts */}
              <div className="h-[220px]">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={trendData}>
                    <defs>
                      <linearGradient id="colorISO" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00E5FF" stopOpacity={0.1}/>
                        <stop offset="95%" stopColor="#00E5FF" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.08}/>
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
                    <XAxis dataKey="month" stroke="#64748B" fontSize={10} tickLine={false} />
                    <YAxis stroke="#64748B" fontSize={10} tickLine={false} domain={[40, 100]} />
                    <Tooltip contentStyle={{ backgroundColor: "#0F172A", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 11 }} />
                    <Legend wrapperStyle={{ fontSize: 10, paddingTop: 10 }} />
                    <Area type="monotone" name="ISO 27001 Score" dataKey="ISO" stroke="#00E5FF" fillOpacity={1} fill="url(#colorISO)" strokeWidth={1.5} />
                    <Area type="monotone" name="Overall Risk Posture" dataKey="RiskPosture" stroke="#10B981" fillOpacity={1} fill="url(#colorRisk)" strokeWidth={1.5} />
                    <Line type="monotone" name="SOC 2 Score" dataKey="SOC" stroke="#F59E0B" strokeWidth={2} dot={{ r: 3 }} />
                    <Bar name="NIST CSF Score" dataKey="NIST" barSize={15} fill="#8B5CF6" radius={[4, 4, 0, 0]} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Chart Right 1 Col: Radar Framework Alignments */}
            <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/5 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-1.5 border-b border-white/5 pb-2">
                  <Shield size={15} className="text-[#00E5FF]" />
                  Framework Maturity Index
                </h3>
                <p className="text-[11px] text-slate-400 mt-1">Multi-dimensional assessment score comparison.</p>
              </div>

              <div className="h-[180px] flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                    <PolarGrid stroke="rgba(255,255,255,0.05)" />
                    <PolarAngleAxis dataKey="subject" stroke="#64748B" fontSize={10} />
                    <PolarRadiusAxis stroke="#64748B" fontSize={8} angle={30} domain={[0, 100]} />
                    <Radar name="Maturity %" dataKey="A" stroke="#00E5FF" fill="#00E5FF" fillOpacity={0.15} />
                    <Tooltip contentStyle={{ backgroundColor: "#0F172A", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 10 }} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>

              {/* Dynamic Score stats list */}
              <div className="space-y-1.5 text-xs pt-2 border-t border-white/5 font-mono">
                {Object.entries(frameworkScores).map(([fw, val]) => (
                  <div key={fw} className="flex justify-between items-center">
                    <span className="text-slate-400">{fw} Index:</span>
                    <span className="text-white font-bold">{val}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* GRC Quick Links & Real Time Incidents Correlation Warning */}
          <div className="p-4 rounded-xl bg-amber-500/5 border border-amber-500/20 flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
            <div className="flex gap-3 items-start">
              <AlertTriangle className="text-amber-500 shrink-0 mt-0.5" size={20} />
              <div>
                <h4 className="text-xs font-bold text-amber-400">Critical GRC Incidents Correlation Found</h4>
                <p className="text-[11px] text-slate-300 mt-0.5">
                  The active "SSH Brute Force Attack" simulation on your SOC dashboard directly affects controls **CTRL-105 (Cloud IAM rules)** and **CTRL-101 (MFA Enforcement)**. Remediation requires patching wildcard roles to secure credentials.
                </p>
              </div>
            </div>
            <button
              onClick={() => setActiveSubTab("gap")}
              className="px-3 py-1.5 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 border border-amber-500/30 rounded-lg text-[10px] font-mono font-bold transition-all cursor-pointer whitespace-nowrap"
            >
              Examine Gap Remediation
            </button>
          </div>
        </div>
      )}

      {/* RISK REGISTER TAB VIEW */}
      {activeSubTab === "risks" && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-1.5">
                <AlertTriangle size={18} className="text-rose-400" />
                Corporate GRC Risk Register
              </h2>
              <p className="text-xs text-slate-400">Manage risk likelihood scores, calculate severity metrics, and edit treatment remediation playbooks.</p>
            </div>
            <button className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-white border border-white/10 rounded-xl text-xs font-mono font-bold flex items-center gap-1 cursor-pointer">
              <PlusCircle size={14} />
              <span>Add New Risk</span>
            </button>
          </div>

          {/* Risk Grid / List */}
          <div className="overflow-x-auto rounded-xl border border-white/5 bg-[#08080A]">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-white/[0.02] border-b border-white/5 font-mono text-slate-500 text-[10px] font-bold uppercase tracking-wider">
                  <th className="p-3">ID</th>
                  <th className="p-3">Risk Title & Correlated Issue</th>
                  <th className="p-3">Category</th>
                  <th className="p-3 text-center">Likelihood (1-5)</th>
                  <th className="p-3 text-center">Impact (1-5)</th>
                  <th className="p-3 text-center">Risk Vector Score</th>
                  <th className="p-3">Treatment Plan</th>
                  <th className="p-3 text-right">Mitigation Progress</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {risks.map((risk) => {
                  const isExpanded = expandedRiskId === risk.id;
                  const scoreColor = risk.score >= 15 ? "text-rose-500 font-extrabold" : risk.score >= 10 ? "text-amber-500 font-bold" : "text-teal-400";
                  return (
                    <React.Fragment key={risk.id}>
                      <tr 
                        onClick={() => setExpandedRiskId(isExpanded ? null : risk.id)}
                        className="hover:bg-white/[0.01] transition-colors cursor-pointer select-none"
                      >
                        <td className="p-3 font-mono text-slate-400 font-bold">{risk.id}</td>
                        <td className="p-3 max-w-sm">
                          <span className="text-white font-medium block">{risk.title}</span>
                          {risk.correlatedIssue && (
                            <span className="text-[10px] font-mono text-[#00E5FF] mt-0.5 block font-bold">
                              {risk.correlatedIssue}
                            </span>
                          )}
                        </td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded-md bg-white/5 border border-white/10 text-slate-300 text-[10px]">
                            {risk.category}
                          </span>
                        </td>
                        <td className="p-3 text-center font-mono font-semibold">{risk.likelihood}</td>
                        <td className="p-3 text-center font-mono font-semibold">{risk.impact}</td>
                        <td className="p-3 text-center font-mono">
                          <span className={`px-2 py-0.5 rounded bg-white/[0.02] border border-white/5 ${scoreColor}`}>
                            {risk.score} / 25
                          </span>
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                            risk.treatment === "Mitigate" ? "bg-blue-500/10 text-blue-400" :
                            risk.treatment === "Accept" ? "bg-slate-500/10 text-slate-400" :
                            risk.treatment === "Avoid" ? "bg-emerald-500/10 text-emerald-400" : "bg-purple-500/10 text-purple-400"
                          }`}>
                            {risk.treatment}
                          </span>
                        </td>
                        <td className="p-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <span className="text-[10px] font-mono text-slate-400">{risk.progress}%</span>
                            <div className="w-16 bg-white/5 h-1.5 rounded-full overflow-hidden">
                              <div className="bg-[#10B981] h-full" style={{ width: `${risk.progress}%` }}></div>
                            </div>
                          </div>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-white/[0.01]">
                          <td colSpan={8} className="p-4 border-b border-white/5">
                            <div className="space-y-3 pl-6 border-l-2 border-[#00E5FF] text-xs">
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <div>
                                  <span className="text-slate-500 font-mono text-[9px] block">RISK OWNER</span>
                                  <span className="text-slate-200 font-semibold">{risk.owner}</span>
                                </div>
                                <div>
                                  <span className="text-slate-500 font-mono text-[9px] block">SEVERITY RATING</span>
                                  <span className={`font-semibold ${
                                    risk.severity === "Critical" ? "text-rose-600" : risk.severity === "High" ? "text-rose-400" : "text-amber-500"
                                  }`}>{risk.severity} Severity</span>
                                </div>
                                <div>
                                  <span className="text-slate-500 font-mono text-[9px] block">REMEDIATION STATUS</span>
                                  <span className="text-slate-300">Remediation Action Playbook active</span>
                                </div>
                              </div>
                              <div>
                                <span className="text-slate-500 font-mono text-[9px] block">REMEDIATION & RISK TREATMENT PLAN</span>
                                <p className="text-slate-300 leading-relaxed font-sans text-xs mt-1">{risk.remediationPlan}</p>
                              </div>

                              {/* Interactive Progress Slider */}
                              <div className="pt-2">
                                <span className="text-slate-500 font-mono text-[9px] block mb-1">MITIGATION TRACKING SLIDER (UPDATE PROGRESS)</span>
                                <div className="flex items-center gap-3">
                                  <input 
                                    type="range" 
                                    min="0" 
                                    max="100" 
                                    value={risk.progress}
                                    onChange={(e) => {
                                      const val = parseInt(e.target.value);
                                      setRisks(prev => prev.map(r => r.id === risk.id ? { ...r, progress: val } : r));
                                    }}
                                    className="w-48 accent-[#00E5FF]"
                                  />
                                  <span className="font-mono text-slate-300 text-xs font-bold">{risk.progress}% Complete</span>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* COMPLIANCE CONTROLS LIBRARY TAB VIEW */}
      {activeSubTab === "controls" && (
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row justify-between md:items-center gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-1.5">
                <Shield size={18} className="text-[#00E5FF]" />
                Security Controls Library & Evidence Repository
              </h2>
              <p className="text-xs text-slate-400">Audit organizational security controls, track testing histories, and upload verification evidence files.</p>
            </div>

            {/* Framework Filter tab options */}
            <div className="flex gap-1 bg-white/5 p-1 rounded-xl border border-white/5 max-w-md overflow-x-auto self-start">
              {["All", "ISO 27001", "NIST CSF", "SOC 2", "CIS Controls"].map((fw) => (
                <button
                  key={fw}
                  onClick={() => setSelectedFramework(fw as any)}
                  className={`px-3 py-1 text-[10px] font-mono font-bold rounded-lg transition-all cursor-pointer whitespace-nowrap ${
                    selectedFramework === fw
                      ? "bg-[#00E5FF] text-black shadow-[0_0_8px_rgba(0,229,255,0.25)]"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  {fw}
                </button>
              ))}
            </div>
          </div>

          {/* Search bar */}
          <div className="relative">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" size={14} />
            <input
              type="text"
              placeholder="Search security controls, testing logs, evidence files..."
              value={controlSearch}
              onChange={e => setControlSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-white/[0.02] border border-white/5 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/40 font-sans"
            />
          </div>

          {/* Controls list */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {controls
              .filter(c => selectedFramework === "All" || c.frameworks.includes(selectedFramework as any))
              .filter(c => c.name.toLowerCase().includes(controlSearch.toLowerCase()) || c.category.toLowerCase().includes(controlSearch.toLowerCase()))
              .map((ctrl) => {
                const isExpanded = selectedControlId === ctrl.id;
                return (
                  <div 
                    key={ctrl.id} 
                    className="p-5 rounded-xl bg-white/[0.02] border border-white/5 hover:border-white/10 transition-colors flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex justify-between items-start mb-2">
                        <div>
                          <span className="text-[10px] font-mono text-slate-500 font-bold block">{ctrl.id} • {ctrl.category}</span>
                          <h3 className="text-sm font-bold text-white mt-0.5">{ctrl.name}</h3>
                        </div>
                        <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                          ctrl.status === "Compliant" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" :
                          ctrl.status === "Partially Compliant" ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                          "bg-rose-500/10 text-rose-400 border-rose-500/20"
                        }`}>
                          {ctrl.status}
                        </span>
                      </div>

                      {/* Framework Tags */}
                      <div className="flex flex-wrap gap-1 mb-3">
                        {ctrl.frameworks.map(fw => (
                          <span key={fw} className="px-1.5 py-0.5 rounded bg-white/5 text-slate-400 text-[9px] font-mono border border-white/5">
                            {fw}
                          </span>
                        ))}
                      </div>

                      <div className="space-y-2.5 text-xs">
                        {/* Effectiveness slider */}
                        <div>
                          <div className="flex justify-between items-center text-[10px] font-mono text-slate-400 mb-1">
                            <span>Control Effectiveness Metric:</span>
                            <span className="font-bold text-[#00E5FF]">{ctrl.effectiveness}%</span>
                          </div>
                          <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                            <div className="bg-[#00E5FF] h-full" style={{ width: `${ctrl.effectiveness}%` }}></div>
                          </div>
                        </div>

                        {/* Evidence Repository */}
                        <div>
                          <span className="text-[9px] font-mono text-slate-500 uppercase block mb-1">Uploaded Evidence Ledger</span>
                          <div className="space-y-1">
                            {ctrl.evidenceFiles.map((ev, idx) => (
                              <div key={idx} className="flex justify-between items-center bg-[#050507] p-1.5 rounded border border-white/5 text-[10px] font-mono">
                                <span className="text-slate-300 truncate max-w-[80%]">{ev}</span>
                                <a href="#" onClick={(e) => e.preventDefault()} className="text-[#38BDF8] hover:underline flex items-center gap-0.5">
                                  <Download size={10} />
                                  <span>Download</span>
                                </a>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Quick Action options */}
                    <div className="mt-4 pt-4 border-t border-white/5 flex gap-2">
                      <button
                        onClick={() => setSelectedControlId(isExpanded ? null : ctrl.id)}
                        className="flex-1 text-center py-1.5 bg-white/5 hover:bg-white/10 text-white rounded-lg text-[10px] font-mono font-bold transition-all border border-white/5 cursor-pointer"
                      >
                        {isExpanded ? "Hide Test History" : "View Test History"}
                      </button>
                      <button
                        onClick={() => handleUploadEvidence(ctrl.id)}
                        className="flex-1 text-center py-1.5 bg-[#00E5FF]/10 text-[#00E5FF] hover:bg-[#00E5FF]/20 border border-[#00E5FF]/20 rounded-lg text-[10px] font-mono font-bold transition-all cursor-pointer"
                      >
                        Attach Evidence
                      </button>
                    </div>

                    {/* Expansions: Test logs */}
                    {isExpanded && (
                      <div className="mt-4 pt-4 border-t border-white/5 space-y-2 text-xs">
                        <span className="text-[10px] font-mono text-slate-500 uppercase block">Testing Verification Ledger</span>
                        <div className="space-y-1.5">
                          {ctrl.testingHistory.map((test, idx) => (
                            <div key={idx} className="p-2 rounded bg-[#050507] border border-white/5 relative">
                              <div className="flex justify-between items-center mb-1 text-[10px] font-mono">
                                <span className="text-slate-400">{test.date} • Tester: {test.tester}</span>
                                <span className={`font-bold ${test.result === "Pass" ? "text-emerald-400" : "text-rose-400"}`}>
                                  {test.result.toUpperCase()}
                                </span>
                              </div>
                              <p className="text-slate-300 font-sans text-[11px] leading-relaxed">{test.details}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
          </div>

          {/* Evidence Upload Portal Dialog (Simulated) */}
          {uploadControlId && (
            <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
              <div className="w-full max-w-md p-6 rounded-2xl bg-[#09090C] border border-white/10 shadow-2xl space-y-4">
                <div className="flex justify-between items-center border-b border-white/5 pb-3">
                  <div>
                    <span className="text-[9px] font-mono text-[#00E5FF] font-bold block">SECURE COMPLIANCE INGESTION PORTAL</span>
                    <h3 className="text-sm font-bold text-white">Upload Audit Evidence for control {uploadControlId}</h3>
                  </div>
                  <button 
                    onClick={() => setUploadControlId(null)}
                    className="text-slate-400 hover:text-white text-sm font-bold cursor-pointer"
                  >
                    ✕
                  </button>
                </div>

                <form onSubmit={submitEvidenceUpload} className="space-y-3">
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-mono text-slate-400 block">EVIDENCE FILE NAME (e.g. mfa_enforcement_policy.pdf)</label>
                    <input
                      type="text"
                      placeholder="e.g. audit_log_mitigation_record.json"
                      value={evidenceFileName}
                      onChange={e => setEvidenceFileName(e.target.value)}
                      required
                      className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/40"
                    />
                  </div>

                  <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl text-[11px] text-slate-400 leading-relaxed font-sans">
                    <p>
                      <strong>Compliance Standard Notice</strong>: Once uploaded, files are cryptographically timestamped and committed to the Alpha GRC Ledger log repository, triggering an automatic recalculation of overall alignment status scores.
                    </p>
                  </div>

                  <div className="flex gap-2 justify-end pt-2">
                    <button
                      type="button"
                      onClick={() => setUploadControlId(null)}
                      className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-white text-xs font-mono font-bold transition-all cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={isUploading}
                      className="px-4 py-2 bg-[#00E5FF] text-black font-mono font-extrabold text-xs rounded-xl flex items-center gap-1.5 transition-all shadow-[0_0_10px_rgba(0,229,255,0.25)] hover:shadow-[0_0_15px_rgba(0,229,255,0.4)] cursor-pointer disabled:opacity-50"
                    >
                      {isUploading ? (
                        <>
                          <RefreshCw size={12} className="animate-spin" />
                          <span>Uploading Ledger...</span>
                        </>
                      ) : (
                        <>
                          <Plus size={12} />
                          <span>Commit Evidence</span>
                        </>
                      )}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {/* GAP ANALYSIS ENGINE TAB VIEW */}
      {activeSubTab === "gap" && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-1.5">
              <FileCheck size={18} className="text-amber-400" />
              Gap Analysis Engine
            </h2>
            <p className="text-xs text-slate-400">Map missing organizational safeguards, isolate gaps, and trace priority compliance remediation playbooks.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {gapFindings.map((gap) => {
              const priorityColor = gap.priority === "Critical" ? "text-rose-500 border-rose-500/20 bg-rose-500/10" : gap.priority === "High" ? "text-rose-400 border-rose-400/20 bg-rose-400/10" : "text-amber-500 border-amber-500/20 bg-amber-500/10";
              return (
                <div key={gap.id} className="p-5 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between space-y-4">
                  <div>
                    <div className="flex justify-between items-start mb-2">
                      <span className="text-[10px] font-mono text-slate-500 font-bold block">{gap.id} • {gap.framework}</span>
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${priorityColor}`}>
                        {gap.priority}
                      </span>
                    </div>

                    <h3 className="text-xs font-bold text-white leading-snug">{gap.controlName}</h3>
                    <p className="text-[11px] text-slate-400 mt-2 leading-relaxed font-sans">{gap.gapDescription}</p>

                    <div className="mt-4 p-3 rounded-lg bg-white/[0.01] border border-white/5 space-y-1.5">
                      <span className="text-[9px] font-mono text-[#00E5FF] font-bold block uppercase tracking-wider">Gap Action Plan recommendation</span>
                      <p className="text-slate-300 text-[11px] leading-relaxed font-sans">{gap.recommendation}</p>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-white/5 flex justify-between items-center text-[10px] font-mono">
                    <span className="text-slate-500">Execution Status:</span>
                    <span className={`font-bold ${gap.status === "Resolved" ? "text-emerald-400" : "text-amber-400 animate-pulse"}`}>
                      {gap.status}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* AUDIT logs & EVIDENCE REPOSITORY VIEW */}
      {activeSubTab === "audit" && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-1.5">
              <History size={18} className="text-indigo-400" />
              GRC Immutable Audit Trail
            </h2>
            <p className="text-xs text-slate-400 font-sans">Review compliance testing registers, credential edits, and continuous posture change logs.</p>
          </div>

          <div className="bg-[#050507] rounded-xl border border-white/5 overflow-hidden text-xs font-mono">
            <div className="p-3 bg-white/[0.02] border-b border-white/5 text-[10px] font-bold text-slate-500 uppercase tracking-widest flex justify-between items-center">
              <span>LEDGER SEQUENCE STREAM</span>
              <span>64-BIT CRYPTO PROXY</span>
            </div>
            
            <div className="divide-y divide-white/5">
              {auditLogs.map((log, idx) => (
                <div key={idx} className="p-3 flex flex-col md:flex-row md:items-center justify-between gap-2 hover:bg-white/[0.01]">
                  <div className="flex gap-3 items-start">
                    <span className="text-slate-500 text-[10px]">{log.date}</span>
                    <div>
                      <span className="text-slate-100 font-bold block">{log.action}</span>
                      <span className="text-slate-500 text-[10px] font-mono">
                        User: <span className="text-slate-300">{log.user}</span> • Module: <span className="text-slate-400">{log.module}</span>
                      </span>
                    </div>
                  </div>
                  <div className="flex gap-2 items-center text-[10px]">
                    <span className={`px-1.5 py-0.5 rounded ${
                      log.outcome === "Pass" || log.outcome === "Success" || log.outcome === "Completed"
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                        : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                    }`}>
                      {log.outcome}
                    </span>
                    <span className="text-slate-600">SEQ_#{idx + 1042}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* EXECUTIVE BOARD REPORTS TAB */}
      {activeSubTab === "reports" && (
        <div className="space-y-6">
          <div className="flex flex-col md:flex-row justify-between md:items-center gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-1.5">
                <FileText size={18} className="text-[#00E5FF]" />
                Executive Reporting Center
              </h2>
              <p className="text-xs text-slate-400">Compile professional board summaries, export compliance trends, and document audit outcomes.</p>
            </div>
          </div>

          {/* Interactive Report Config Compiler panel */}
          <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/5 grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Left config options */}
            <div className="space-y-4">
              <span className="text-[10px] font-mono text-[#00E5FF] font-bold block uppercase tracking-wider">Report Specifications</span>
              
              <div className="space-y-1.5">
                <label className="text-[10px] font-mono text-slate-500 block">COMPILER LEAD SIGN-OFF AUTHOR</label>
                <input
                  type="text"
                  value={executiveAuthor}
                  onChange={e => setExecutiveAuthor(e.target.value)}
                  className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/40 font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-[10px] font-mono text-slate-500 block">GRC SCOPE LEVEL</label>
                <select className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/40 font-mono">
                  <option>Full Corporate Audit Matrix (ISO, NIST, SOC2, CIS)</option>
                  <option>NIST CSF & Vulnerability Scope Only</option>
                  <option>SOC 2 Tenant Data Segregations Focus</option>
                </select>
              </div>

              <div className="space-y-2.5 pt-3">
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <CheckCircle size={14} className="text-emerald-400" />
                  <span>Includes dynamic risk matrix scores</span>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <CheckCircle size={14} className="text-emerald-400" />
                  <span>Includes live controls efficacy checklist</span>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <CheckCircle size={14} className="text-emerald-400" />
                  <span>Includes unpatched CVE correlation details</span>
                </div>
              </div>

              <button
                onClick={generateBoardReport}
                disabled={isGeneratingReport}
                className="w-full py-2.5 bg-[#00E5FF] hover:bg-[#00E5FF]/90 text-black font-mono font-extrabold text-xs rounded-xl flex items-center justify-center gap-1.5 transition-all shadow-[0_0_15px_rgba(0,229,255,0.2)] hover:shadow-[0_0_20px_rgba(0,229,255,0.35)] cursor-pointer disabled:opacity-50"
              >
                {isGeneratingReport ? (
                  <>
                    <RefreshCw size={13} className="animate-spin" />
                    <span>Compiling Report Findings...</span>
                  </>
                ) : (
                  <>
                    <Sparkles size={13} />
                    <span>Compile Board Report Summary</span>
                  </>
                )}
              </button>
            </div>

            {/* Right markdown visualizer */}
            <div className="md:col-span-2 bg-[#050507] rounded-xl border border-white/5 p-5 relative overflow-hidden flex flex-col justify-between">
              {generatedMarkdownReport ? (
                <>
                  <div className="prose prose-invert max-w-none text-xs text-slate-300 font-sans h-[320px] overflow-y-auto whitespace-pre-wrap leading-relaxed">
                    {generatedMarkdownReport}
                  </div>

                  {/* Print / Download simulator action */}
                  <div className="mt-4 pt-3 border-t border-white/5 flex justify-between items-center">
                    <span className="text-[9px] font-mono text-slate-500">COMPILER DIGITAL SHA256 BLOCK: #GRC_78_COMP</span>
                    <button
                      onClick={() => {
                        // Simulated plain text file download
                        const blob = new Blob([generatedMarkdownReport], { type: "text/plain" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `secassist_grc_board_report_2026.txt`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                      }}
                      className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-white rounded-lg border border-white/10 text-[10px] font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer"
                    >
                      <Download size={12} />
                      <span>Download .TXT Report</span>
                    </button>
                  </div>
                </>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500">
                  <FileText size={42} className="opacity-20 mb-3" />
                  <h4 className="text-xs font-bold text-slate-400">Board Report Compiler Ready</h4>
                  <p className="text-[11px] text-slate-500 max-w-xs mt-1">
                    Click the compilation button on the left to extract the latest security threat statistics and write an executive board-level security overview.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
