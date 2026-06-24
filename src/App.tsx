import React, { useState, useEffect } from "react";
import {
  Shield,
  AlertTriangle,
  FileText,
  Upload,
  Database,
  Users,
  Activity,
  User,
  LogOut,
  RefreshCw,
  Search,
  Filter,
  CheckCircle,
  FileSpreadsheet,
  Download,
  Flame,
  Globe,
  Terminal,
  Server,
  Key,
  Layers,
  ChevronRight,
  PlusCircle,
  Play,
  Moon,
  Sun,
  Lock,
  Cpu,
  Workflow,
  ClipboardList
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend
} from "recharts";
import { SecurityAlert, SecurityLog, ThreatIntel, IncidentReport, DashboardStats, UserRole } from "./types";
import ThreatHunting from "./components/ThreatHunting";
import AssetInventory from "./components/AssetInventory";
import VulnerabilityManagement from "./components/VulnerabilityManagement";
import SecurityKnowledgeGraph from "./components/SecurityKnowledgeGraph";
import AiThreatAgent from "./components/AiThreatAgent";
import SecurityArchitecture from "./components/SecurityArchitecture";
import GrcCenter from "./components/GrcCenter";
import { MITRE_ATTACK_MATRIX, MitreTactic, MitreTechnique } from "./data/mitreData";

export default function App() {
  // Theme state (dark mode is default for professional SOC vibe)
  const [isDarkMode, setIsDarkMode] = useState<boolean>(true);

  // Authentication states
  const [token, setToken] = useState<string>(() => localStorage.getItem("secassist_token") || "");
  const [currentUser, setCurrentUser] = useState<any | null>(null);
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [authError, setAuthError] = useState<string>("");
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(false);

  // Active view tab
  const [activeTab, setActiveTab] = useState<
    "dashboard" | "alerts" | "logs" | "mitre" | "threats" | "reports" |
    "threat-hunting" | "assets" | "vulnerabilities" | "knowledge-graph" | "ai-agent" |
    "security-architecture" | "grc-center"
  >("dashboard");

  // Domain states
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [threats, setThreats] = useState<ThreatIntel[]>([]);
  const [reports, setReports] = useState<IncidentReport[]>([]);

  // Triage state
  const [filterSeverity, setFilterSeverity] = useState<string>("All");
  const [filterStatus, setFilterStatus] = useState<string>("All");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);

  // Log upload state
  const [logFilename, setLogFilename] = useState<string>("custom_firewall.log");
  const [logContent, setLogContent] = useState<string>("");
  const [isUploadingLog, setIsUploadingLog] = useState<boolean>(false);
  const [uploadResult, setUploadResult] = useState<any | null>(null);
  const [dragOver, setDragOver] = useState<boolean>(false);

  // Active AI Report Generation state
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);
  const [reportSuccessMessage, setReportSuccessMessage] = useState<string>("");

  // Simulated Alert Constructor state
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simulationType, setSimulationType] = useState<string>("bruteforce");

  // Custom Threat Intell form
  const [newThreatName, setNewThreatName] = useState<string>("");
  const [newThreatSeverity, setNewThreatSeverity] = useState<"Critical" | "High" | "Medium" | "Low">("High");
  const [newThreatTactic, setNewThreatTactic] = useState<string>("Credential Access");
  const [newThreatExplanation, setNewThreatExplanation] = useState<string>("");
  const [newThreatRemediation, setNewThreatRemediation] = useState<string>("");

  // MITRE ATT&CK Matrix states
  const [mitreMatrix, setMitreMatrix] = useState<MitreTactic[]>(MITRE_ATTACK_MATRIX);
  const [selectedMitreTech, setSelectedMitreTech] = useState<MitreTechnique | null>(null);
  const [selectedMitreTacticName, setSelectedMitreTacticName] = useState<string>("");
  const [isLoadingMitre, setIsLoadingMitre] = useState<boolean>(false);

  // Real-time system monitoring logs
  const [systemConsoleLogs, setSystemConsoleLogs] = useState<string[]>([
    "SEC_SOC Core: Kernel threat listeners running...",
    "SEC_SOC Connection: Database connection established securely.",
    "SEC_SOC Firewall: Perimeter filtering rule synchronized with tenant policy."
  ]);

  // Load user info from token
  useEffect(() => {
    if (token) {
      localStorage.setItem("secassist_token", token);
      fetchUserProfile();
    } else {
      localStorage.removeItem("secassist_token");
      setCurrentUser(null);
    }
  }, [token]);

  // Refresh interval
  useEffect(() => {
    if (currentUser) {
      fetchDashboardData();
      const interval = setInterval(() => {
        fetchDashboardData();
      }, 10000); // refresh telemetry every 10 seconds
      return () => clearInterval(interval);
    }
  }, [currentUser, activeTab, filterSeverity, filterStatus]);

  // Sync logs when console stream expands
  const addConsoleLog = (text: string) => {
    setSystemConsoleLogs(prev => [`[${new Date().toLocaleTimeString()}] ${text}`, ...prev.slice(0, 15)]);
  };

  const fetchUserProfile = async () => {
    try {
      const res = await fetch("/api/auth/me", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setCurrentUser(data.user);
        addConsoleLog(`User '${data.user.name}' authenticated as [${data.user.role}]`);
      } else {
        handleLogout();
      }
    } catch (err) {
      console.error(err);
      handleLogout();
    }
  };

  const fetchDashboardData = async () => {
    if (!token) return;
    try {
      // Get Stats
      const statsRes = await fetch("/api/dashboard/stats", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      // Get Alerts with active filter query parameters
      const url = new URL("/api/alerts", window.location.origin);
      url.searchParams.append("severity", filterSeverity);
      url.searchParams.append("status", filterStatus);
      if (searchQuery) url.searchParams.append("search", searchQuery);

      const alertsRes = await fetch(url.toString(), {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        setAlerts(alertsData);
      }

      // Get Logs
      const logsRes = await fetch("/api/logs", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (logsRes.ok) {
        const logsData = await logsRes.json();
        setLogs(logsData);
      }

      // Get Threats intel
      const threatsRes = await fetch("/api/threats", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (threatsRes.ok) {
        const threatsData = await threatsRes.json();
        setThreats(threatsData);
      }

      // Get Incident Reports
      const reportsRes = await fetch("/api/reports", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (reportsRes.ok) {
        const reportsData = await reportsRes.json();
        setReports(reportsData);
      }

      // Get MITRE Matrix data
      setIsLoadingMitre(true);
      const mitreRes = await fetch("/api/mitre/matrix", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (mitreRes.ok) {
        const mitreData = await mitreRes.json();
        setMitreMatrix(mitreData);
      }
      setIsLoadingMitre(false);
    } catch (err) {
      console.error("Failed to load dashboard data telemetry:", err);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoggingIn(true);
    setAuthError("");
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (res.ok) {
        setToken(data.token);
        setCurrentUser(data.user);
        addConsoleLog(`Successful tenant login for user: ${email}`);
      } else {
        setAuthError(data.error || "Authentication failed.");
      }
    } catch (err) {
      setAuthError("Server unavailable.");
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleLogout = () => {
    setToken("");
    setCurrentUser(null);
    localStorage.removeItem("secassist_token");
  };

  // Pre-fill fields for easy developer demonstration
  const handleQuickLogin = (demoEmail: string) => {
    setEmail(demoEmail);
    setPassword("secassist_demo_2026");
  };

  const handleTriageStatusChange = async (alertId: string, newStatus: string) => {
    try {
      const res = await fetch(`/api/alerts/${alertId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        const updatedAlert = await res.json();
        addConsoleLog(`Alert ${alertId} status reassigned to: ${newStatus}`);
        fetchDashboardData();
        if (selectedAlert?.id === alertId) {
          setSelectedAlert(updatedAlert);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleTriageAssignmentChange = async (alertId: string, emailStr: string) => {
    try {
      const res = await fetch(`/api/alerts/${alertId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ assignedTo: emailStr })
      });
      if (res.ok) {
        const updatedAlert = await res.json();
        addConsoleLog(`Alert ${alertId} assigned to analyst: ${emailStr}`);
        fetchDashboardData();
        if (selectedAlert?.id === alertId) {
          setSelectedAlert(updatedAlert);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Upload logs for Gemini deep assessment
  const handleLogUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!logContent.trim()) return;

    setIsUploadingLog(true);
    setUploadResult(null);
    addConsoleLog(`Initiating AI payload parsing on log: ${logFilename}`);

    try {
      const res = await fetch("/api/logs/upload", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ filename: logFilename, content: logContent })
      });

      const data = await res.json();
      if (res.ok) {
        setUploadResult(data.analysis);
        addConsoleLog(`AI Security analysis complete. Identified: ${data.analysis.threatName} (${data.analysis.threatLevel} Severity)`);
        setLogContent("");
        fetchDashboardData();
      } else {
        addConsoleLog(`Error parsing log: ${data.error}`);
      }
    } catch (err) {
      addConsoleLog("Failed to analyze logs. Check network configuration.");
    } finally {
      setIsUploadingLog(false);
    }
  };

  // Prepopulate raw cybersecurity log scenarios
  const prefillLogScenario = (scenario: "ssh" | "sql" | "lockbit") => {
    if (scenario === "ssh") {
      setLogFilename("ssh_auth_harvest.log");
      setLogContent(
        "Jun 24 11:02:11 staging-web sshd[8841]: Failed password for invalid user guest from 192.168.12.8 port 55112 ssh2\n" +
        "Jun 24 11:02:13 staging-web sshd[8843]: Failed password for invalid user admin from 192.168.12.8 port 55114 ssh2\n" +
        "Jun 24 11:02:15 staging-web sshd[8845]: Failed password for invalid user root from 192.168.12.8 port 55116 ssh2\n" +
        "Jun 24 11:02:18 staging-web sshd[8847]: Failed password for root from 192.168.12.8 port 55118 ssh2\n" +
        "Jun 24 11:02:22 staging-web sshd[8851]: Accepted password for root from 10.100.12.4 port 55122 ssh2"
      );
    } else if (scenario === "sql") {
      setLogFilename("web_waf_payload.json");
      setLogContent(
        JSON.stringify([
          { timestamp: "2026-06-24T11:05:00Z", client_ip: "198.51.100.22", request_path: "/api/products?id=12%20UNION%20SELECT%20username,password%20FROM%20users--", user_agent: "Mozilla/5.0 sqlmap/1.4.12", status: 200 },
          { timestamp: "2026-06-24T11:05:05Z", client_ip: "198.51.100.22", request_path: "/api/products?id=12%20AND%201=1", user_agent: "Mozilla/5.0 sqlmap/1.4.12", status: 200 }
        ], null, 2)
      );
    } else if (scenario === "lockbit") {
      setLogFilename("edr_dns_beaconing.txt");
      setLogContent(
        "11:07:01 outbound_traffic DNS_REQUEST domain=lockbit-update-mirror.onion resolved_ip=185.112.144.12 proto=HTTPS len=512\n" +
        "11:07:31 outbound_traffic DNS_REQUEST domain=lockbit-update-mirror.onion resolved_ip=185.112.144.12 proto=HTTPS len=512\n" +
        "11:08:01 outbound_traffic DNS_REQUEST domain=lockbit-update-mirror.onion resolved_ip=185.112.144.12 proto=HTTPS len=512"
      );
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      setLogFilename(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          setLogContent(String(event.target.result));
        }
      };
      reader.readAsText(file);
    }
  };

  // Generate complete formal incident response report with Gemini
  const handleGenerateReport = async (alertId: string) => {
    setIsGeneratingReport(true);
    setReportSuccessMessage("");
    addConsoleLog(`Requesting AI Incident Response compiler for Alert: ${alertId}`);

    try {
      const res = await fetch("/api/reports/generate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ alertId })
      });
      const data = await res.json();
      if (res.ok) {
        setReportSuccessMessage(`Incident report generated successfully! ID: ${data.id}`);
        addConsoleLog(`AI Incident Response compilation completed for ID: ${data.id}`);
        fetchDashboardData();
        setActiveTab("reports");
      } else {
        addConsoleLog(`Failed to compile incident report: ${data.error}`);
      }
    } catch (err) {
      addConsoleLog("Server connection interrupted while assembling report.");
    } finally {
      setIsGeneratingReport(false);
    }
  };

  // Interactive Live Attack Simulation (Automated alerting trigger engine)
  const handleTriggerSimulation = async () => {
    setIsSimulating(true);
    addConsoleLog(`Executing automated threat injector simulation: [${simulationType}]`);

    let payload = {};
    if (simulationType === "bruteforce") {
      payload = {
        title: "AD DC LDAP Password Guessing Sweep",
        severity: "High",
        category: "Credential Access",
        sourceIp: "172.16.54.91",
        destIp: "10.100.1.4",
        description: "Automated authentication sweep matching dictionary attacks target LDAP directories from local user segment subnet.",
        mitreTactic: "Credential Access",
        mitreTechnique: "Brute Force: Password Guessing",
        mitreId: "T1110.001"
      };
    } else if (simulationType === "dns_tunnel") {
      payload = {
        title: "DNS Query Data Tunneling Attempt",
        severity: "Critical",
        category: "Command and Control",
        sourceIp: "10.100.12.181",
        destIp: "8.8.8.8",
        description: "Anomalous multi-label sub-domains containing base32 encoded data payload tunneling across default standard UDP DNS protocols.",
        mitreTactic: "Command and Control",
        mitreTechnique: "Application Layer Protocol: DNS Request Encoding",
        mitreId: "T1071.004"
      };
    } else if (simulationType === "cloud_escalation") {
      payload = {
        title: "Suspicious API Instance Metadata Credential Exfiltration",
        severity: "Medium",
        category: "Exfiltration",
        sourceIp: "10.100.44.12",
        destIp: "169.254.169.254",
        description: "Anomalous continuous script querying cloud metadata credentials from container environment violating container role boundaries.",
        mitreTactic: "Exfiltration",
        mitreTechnique: "Exfiltration Over Web Service",
        mitreId: "T1567"
      };
    }

    try {
      const res = await fetch("/api/alerts", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        const newAlert = await res.json();
        addConsoleLog(`[ALERT REBOOT] New alert registered on tenant: ${newAlert.title}`);
        fetchDashboardData();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setTimeout(() => {
        setIsSimulating(false);
      }, 800);
    }
  };

  // Threat Intel manual bulletin posting
  const handleAddThreatIntel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newThreatName) return;

    addConsoleLog(`Registering threat intelligence advisory: ${newThreatName}`);
    try {
      const res = await fetch("/api/threats", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          name: newThreatName,
          severity: newThreatSeverity,
          tactic: newThreatTactic,
          technique: "Custom Tactic Activity",
          id: "T1000",
          explanation: newThreatExplanation || "Threat intelligence report compiled by local administration center.",
          remediation: newThreatRemediation || "Perform continuous patch verification on matching endpoint groups."
        })
      });
      if (res.ok) {
        addConsoleLog(`Advisory compiled and posted successfully: ${newThreatName}`);
        setNewThreatName("");
        setNewThreatExplanation("");
        setNewThreatRemediation("");
        fetchDashboardData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Client-side quick CSV download trigger
  const triggerCsvDownload = async (type: "alerts" | "reports") => {
    try {
      addConsoleLog(`Initiating CSV export for segment: ${type}...`);
      const response = await fetch(`/api/export?type=${type}&format=csv`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      if (!response.ok) {
        let errMsg = `Export failed with status ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson.error) errMsg = errJson.error;
        } catch (_) {}
        addConsoleLog(`[ERROR] ${errMsg}`);
        return;
      }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `secassist_${type}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      addConsoleLog(`CSV file export compiled and downloaded for segment: ${type}`);
    } catch (err: any) {
      console.error(err);
      addConsoleLog(`[ERROR] Failed to export CSV: ${err.message || err}`);
    }
  };

  // Severity style mapping helper
  const getSeverityStyles = (sev: string) => {
    switch (sev) {
      case "Critical":
        return {
          bg: "bg-cyber-red/10 border border-cyber-red/20 text-cyber-red",
          badge: "bg-cyber-red text-white animate-pulse",
          text: "text-cyber-red",
          glow: "shadow-[0_0_15px_rgba(255,61,0,0.25)] border-cyber-red/40"
        };
      case "High":
        return {
          bg: "bg-cyber-yellow/10 border border-cyber-yellow/20 text-cyber-yellow",
          badge: "bg-cyber-yellow text-black",
          text: "text-cyber-yellow",
          glow: "shadow-[0_0_15px_rgba(255,214,0,0.2)] border-cyber-yellow/40"
        };
      case "Medium":
        return {
          bg: "bg-cyber-cyan/10 border border-cyber-cyan/20 text-cyber-cyan",
          badge: "bg-cyber-cyan text-black",
          text: "text-cyber-cyan",
          glow: "shadow-[0_0_15px_rgba(0,229,255,0.2)] border-cyber-cyan/40"
        };
      case "Low":
        return {
          bg: "bg-cyber-green/10 border border-cyber-green/20 text-cyber-green",
          badge: "bg-cyber-green text-black",
          text: "text-cyber-green",
          glow: "border-cyber-green/30"
        };
      default:
        return {
          bg: "bg-slate-500/10 border border-slate-500/20 text-slate-400",
          badge: "bg-slate-500 text-white",
          text: "text-slate-500",
          glow: "border-slate-500/30"
        };
    }
  };

  const getStatusStyles = (status: string) => {
    switch (status) {
      case "Active":
        return "bg-cyber-red/15 text-cyber-red border border-cyber-red/30";
      case "Investigating":
        return "bg-cyber-yellow/15 text-cyber-yellow border border-cyber-yellow/30";
      case "Resolved":
        return "bg-cyber-green/15 text-cyber-green border border-cyber-green/30";
      default:
        return "bg-slate-800 text-slate-400 border border-slate-700";
    }
  };

  // Render Login Panel if unauthorized
  if (!currentUser) {
    return (
      <div className="min-h-screen flex items-center justify-center font-sans bg-[#050507] text-[#D1D5DB] relative overflow-hidden">
        {/* Ambient Glows */}
        <div className="absolute top-[-10%] right-[-5%] w-[400px] h-[400px] bg-[#00E5FF]/10 rounded-full blur-[120px] pointer-events-none"></div>
        <div className="absolute bottom-[-10%] left-[-5%] w-[400px] h-[400px] bg-[#FF3D00]/5 rounded-full blur-[120px] pointer-events-none"></div>

        <div className="w-full max-w-md p-8 rounded-2xl border border-white/5 bg-[#0A0A0C]/80 backdrop-blur-md shadow-2xl relative z-10">
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-gradient-to-br from-[#00E5FF] to-[#0060FF] rounded-xl text-black shadow-[0_0_15px_rgba(0,229,255,0.4)]">
                <Shield size={24} className="animate-pulse" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">SecAssist<span className="text-[#00E5FF]">AI</span></h1>
                <p className="text-[10px] text-[#00E5FF] font-mono tracking-wider font-bold">SOC CO-PILOT PLATFORM</p>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-white/5 text-slate-400 border border-white/10 uppercase">
              V3.2.1
            </span>
          </div>

          <div className="p-4 rounded-xl bg-white/5 border border-white/10 mb-6 text-xs text-slate-300 font-sans leading-relaxed">
            <span className="font-bold block text-white mb-1">Enterprise Demo Credentials</span>
            Select an identity profile from the quick-load keys below to assess multi-tenant and role-based privilege controls.
          </div>

          <div className="flex gap-2 flex-wrap mb-6">
            <button
              type="button"
              onClick={() => handleQuickLogin("admin@secassist.ai")}
              className="text-[11px] px-3 py-1.5 rounded-lg bg-cyber-red/10 hover:bg-cyber-red/20 border border-cyber-red/20 text-cyber-red font-mono font-bold transition-all duration-150 cursor-pointer"
            >
              Sarah (Admin)
            </button>
            <button
              type="button"
              onClick={() => handleQuickLogin("analyst@secassist.ai")}
              className="text-[11px] px-3 py-1.5 rounded-lg bg-cyber-yellow/10 hover:bg-cyber-yellow/20 border border-cyber-yellow/20 text-cyber-yellow font-mono font-bold transition-all duration-150 cursor-pointer"
            >
              John (Analyst)
            </button>
            <button
              type="button"
              onClick={() => handleQuickLogin("viewer@secassist.ai")}
              className="text-[11px] px-3 py-1.5 rounded-lg bg-cyber-cyan/10 hover:bg-cyber-cyan/20 border border-cyber-cyan/20 text-cyber-cyan font-mono font-bold transition-all duration-150 cursor-pointer"
            >
              Marcus (Viewer)
            </button>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-[10px] font-mono mb-1.5 text-slate-400 uppercase tracking-wider">SEC_SOC Identity ID</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                className="w-full px-4 py-2.5 rounded-xl border border-white/10 bg-white/5 text-white font-mono text-xs placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all duration-150"
                placeholder="analyst@secassist.ai"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono mb-1.5 text-slate-400 uppercase tracking-wider">Access Token Key</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                className="w-full px-4 py-2.5 rounded-xl border border-white/10 bg-white/5 text-white font-mono text-xs placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all duration-150"
                placeholder="••••••••••••••"
              />
            </div>

            {authError && (
              <div className="p-3 text-xs rounded-lg bg-cyber-red/10 border border-cyber-red/20 text-cyber-red font-mono flex items-center gap-2">
                <AlertTriangle size={14} />
                {authError}
              </div>
            )}

            <button
              type="submit"
              disabled={isLoggingIn}
              className="w-full mt-2 py-3 bg-[#00E5FF] hover:bg-[#00e5ff]/90 text-black font-extrabold rounded-xl shadow-[0_4px_15px_rgba(0,229,255,0.3)] hover:shadow-[0_4px_20px_rgba(0,229,255,0.5)] transition-all duration-150 flex items-center justify-center gap-2 text-xs uppercase tracking-widest cursor-pointer disabled:opacity-50"
            >
              {isLoggingIn ? (
                <>
                  <RefreshCw className="animate-spin" size={14} />
                  SEC_SOC Authorizing...
                </>
              ) : (
                <>
                  <Lock size={14} />
                  Authorize Session
                </>
              )}
            </button>
          </form>

          <div className="mt-8 pt-4 border-t border-white/5 text-center">
            <span className="text-[10px] text-slate-500 font-mono uppercase tracking-widest block">Enterprise Grade Protected Workspace</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col font-sans bg-[#050507] text-[#D1D5DB] relative overflow-hidden">
      {/* Background Ambient Glows */}
      <div className="absolute top-[-10%] right-[-5%] w-[400px] h-[400px] bg-[#00E5FF]/10 rounded-full blur-[120px] pointer-events-none z-0"></div>
      <div className="absolute bottom-[-10%] left-[-5%] w-[400px] h-[400px] bg-[#FF3D00]/5 rounded-full blur-[120px] pointer-events-none z-0"></div>
      
      {/* Header telemetry status bar */}
      <header className="px-6 py-3 border-b border-white/5 flex flex-wrap items-center justify-between gap-4 bg-[#0A0A0C]/40 backdrop-blur-md relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-1.5 bg-gradient-to-br from-[#00E5FF] to-[#0060FF] rounded text-black shadow-[0_0_12px_rgba(0,229,255,0.3)]">
            <Shield size={20} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-lg leading-none tracking-tight text-white">
                SecAssist<span className="text-[#00E5FF]">AI</span>
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/20 uppercase">
                ENTERPRISE SOC
              </span>
            </div>
            <span className="text-[9px] text-slate-400 font-mono uppercase tracking-widest block mt-0.5">
              Secure Agentic Co-pilot • Tenant: <span className="text-[#00E5FF] font-bold">ALPHA_CORP</span>
            </span>
          </div>
        </div>

        {/* Real-time Telemetry Health status metrics */}
        <div className="flex flex-wrap items-center gap-5 text-xs z-10">
          <div className="hidden lg:flex items-center gap-2 font-mono text-[11px]">
            <Server size={14} className="text-[#00E676]" />
            <span className="text-slate-500">SYS_HOST:</span>
            <span className="text-[#00E676] font-bold animate-pulse">● ONLINE</span>
          </div>
          <div className="hidden sm:flex items-center gap-2 font-mono text-[11px]">
            <Cpu size={14} className="text-[#00E5FF]" />
            <span className="text-slate-500">Gemini Model:</span>
            <span className="text-[#00E5FF] font-bold">gemini-3.5-flash</span>
          </div>
          <div className="flex items-center gap-2 font-mono bg-white/5 px-2.5 py-1 rounded-xl border border-white/10 text-[11px]">
            <User size={14} className="text-[#00E5FF]" />
            <span className="text-white font-bold">{currentUser.name}</span>
            <span className="text-[9px] font-bold px-1.5 py-0.2 bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/20 rounded uppercase">
              {currentUser.role}
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="p-1.5 rounded-lg bg-white/5 border border-white/10 text-slate-300 hover:text-white hover:border-[#00E5FF]/30 transition-all duration-150 cursor-pointer"
              title="Toggle view filter mode"
            >
              {isDarkMode ? <Sun size={14} /> : <Moon size={14} />}
            </button>
            <button
              onClick={() => fetchDashboardData()}
              className="p-1.5 rounded-lg bg-white/5 border border-white/10 text-slate-300 hover:text-cyber-cyan hover:border-[#00E5FF]/30 transition-all duration-150 cursor-pointer"
              title="Refresh telemetry"
            >
              <RefreshCw size={14} />
            </button>
            <button
              onClick={handleLogout}
              className="p-1.5 rounded-lg bg-white/5 border border-white/10 text-slate-300 hover:bg-cyber-red/10 hover:text-cyber-red hover:border-cyber-red/30 transition-all duration-150 cursor-pointer"
              title="Revoke session"
            >
              <LogOut size={14} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Container Workspace */}
      <div className="flex-1 flex flex-col md:flex-row min-h-0 relative z-10">
        
        {/* Workspace Side rail navigation */}
        <aside className="w-full md:w-64 flex flex-col justify-between border-r border-white/5 bg-[#0A0A0C]/80 backdrop-blur-lg transition-all duration-200 z-10">
          <div className="p-4 space-y-1.5">
            <span className="text-[10px] font-mono text-slate-500 tracking-widest uppercase block mb-3 px-3">SOC WORKSPACE</span>
            
            <button
              onClick={() => setActiveTab("dashboard")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "dashboard"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Activity size={18} className={activeTab === "dashboard" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Security Dashboard</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("alerts")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "alerts"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <AlertTriangle size={18} className={activeTab === "alerts" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Alert Triage Center</span>
              </div>
              {alerts.length > 0 && (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-[#00E5FF] text-black font-extrabold font-mono shadow-[0_0_8px_rgba(0,229,255,0.4)]">
                  {alerts.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab("logs")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "logs"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Upload size={18} className={activeTab === "logs" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Deep AI Log Analyzer</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("mitre")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "mitre"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Layers size={18} className={activeTab === "mitre" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>MITRE ATT&CK Matrix</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("threats")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "threats"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Database size={18} className={activeTab === "threats" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Threat Intelligence</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("reports")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "reports"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <FileText size={18} className={activeTab === "reports" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Incident Reports</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("threat-hunting")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "threat-hunting"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Terminal size={18} className={activeTab === "threat-hunting" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Threat Hunting Workbench</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("assets")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "assets"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Server size={18} className={activeTab === "assets" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Asset Inventory</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("vulnerabilities")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "vulnerabilities"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Flame size={18} className={activeTab === "vulnerabilities" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Vulnerability Mgmt</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("knowledge-graph")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "knowledge-graph"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Globe size={18} className={activeTab === "knowledge-graph" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Security Knowledge Graph</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("ai-agent")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "ai-agent"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Cpu size={18} className={activeTab === "ai-agent" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>AI Threat Agent</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("security-architecture")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "security-architecture"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Workflow size={18} className={activeTab === "security-architecture" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>Security Architecture</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            <button
              onClick={() => setActiveTab("grc-center")}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                activeTab === "grc-center"
                  ? "bg-white/5 text-[#00E5FF] border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                  : "text-slate-400 hover:bg-white/[0.02] hover:text-slate-100 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <ClipboardList size={18} className={activeTab === "grc-center" ? "text-[#00E5FF]" : "text-slate-400"} />
                <span>GRC Compliance Center</span>
              </div>
              <ChevronRight size={14} className="opacity-50" />
            </button>

            {/* Simulated Live Attack Core Panel */}
            <div className="mt-6 pt-6 border-t border-white/5">
              <span className="text-[10px] font-mono text-slate-500 tracking-widest uppercase block mb-3 px-3">SEC_SOC Threat Simulator</span>
              <div className="px-3 space-y-2.5">
                <select
                  value={simulationType}
                  onChange={e => setSimulationType(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded-lg border border-white/10 bg-white/5 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#00E5FF]/50"
                >
                  <option value="bruteforce">SSH Brute Force Attack</option>
                  <option value="dns_tunnel">Ransomware DNS Tunneling</option>
                  <option value="cloud_escalation">AWS IAM privilege exfiltrate</option>
                </select>

                <button
                  type="button"
                  onClick={handleTriggerSimulation}
                  disabled={isSimulating || currentUser.role === "Viewer"}
                  className="w-full text-xs py-2 bg-cyber-red/10 border border-cyber-red/20 hover:bg-cyber-red/20 text-cyber-red rounded-xl font-mono flex items-center justify-center gap-2 transition-all duration-150 shadow-[0_0_10px_rgba(255,61,0,0.15)] hover:shadow-[0_0_15px_rgba(255,61,0,0.25)] disabled:opacity-50 cursor-pointer"
                >
                  {isSimulating ? (
                    <>
                      <RefreshCw size={12} className="animate-spin" />
                      Injecting Payload...
                    </>
                  ) : (
                    <>
                      <Play size={12} />
                      Simulate Attack Scan
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Core System Diagnostic Console */}
          <div className="p-4 border-t border-white/5 hidden md:block">
            <span className="text-[10px] font-mono text-slate-500 uppercase block mb-2 px-1">SYSTEM_TELEMETRY_LOGS</span>
            <div className="h-28 bg-[#050507] p-2.5 rounded-xl border border-white/5 font-mono text-[9px] text-[#00E676] overflow-y-auto space-y-1">
              {systemConsoleLogs.map((log, idx) => (
                <div key={idx} className="truncate select-all leading-tight">
                  {log}
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* Real-time Workspace Display Frame */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* DASHBOARD TAB VIEW */}
          {activeTab === "dashboard" && stats && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-white">Security Telemetry Hub</h1>
                  <p className="text-sm text-slate-400">Continuous enterprise threat analysis and risk score tracking.</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400 font-mono">Last updated: {new Date().toLocaleTimeString()}</span>
                  <span className="w-2.5 h-2.5 rounded-full bg-[#00E676] animate-pulse shadow-[0_0_8px_#00E676]" />
                </div>
              </div>

              {/* High-level dynamic summary cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Threat Risk Score Gauge */}
                <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 flex items-center justify-between shadow-lg backdrop-blur-md relative overflow-hidden">
                  <div className="space-y-1 z-10">
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest block">Tenant Threat Risk Score</span>
                    <span className="text-3xl font-extrabold tracking-tight text-white">{stats.riskScore}%</span>
                    <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded-md mt-1 block w-fit ${
                      stats.riskScore > 65 
                        ? "bg-cyber-red/10 text-cyber-red border border-cyber-red/20 shadow-[0_0_10px_rgba(255,61,0,0.1)]" 
                        : stats.riskScore > 35 
                          ? "bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/20" 
                          : "bg-cyber-green/10 text-cyber-green border border-cyber-green/20"
                    }`}>
                      {stats.riskScore > 65 ? "⚠️ HIGH EXPOSURE ALERT" : stats.riskScore > 35 ? "⚡ MODERATE ALERT" : "✓ SYS_NORMAL"}
                    </span>
                  </div>
                  <div className="relative flex items-center justify-center z-10">
                    <svg className="w-16 h-16 transform -rotate-90">
                      <circle cx="32" cy="32" r="26" stroke="rgba(255,255,255,0.05)" strokeWidth="6" fill="transparent" />
                      <circle
                        cx="32"
                        cy="32"
                        r="26"
                        stroke={stats.riskScore > 65 ? "#FF3D00" : stats.riskScore > 35 ? "#FFD600" : "#00E676"}
                        strokeWidth="6"
                        fill="transparent"
                        strokeDasharray={163.36}
                        strokeDashoffset={163.36 - (163.36 * stats.riskScore) / 100}
                        strokeLinecap="round"
                        className="transition-all duration-500"
                      />
                    </svg>
                    <div className="absolute font-mono text-[10px] font-extrabold text-[#00E5FF]">{stats.riskScore}</div>
                  </div>
                </div>

                {/* Critical threats card */}
                <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 flex items-center justify-between shadow-lg backdrop-blur-md relative overflow-hidden">
                  <div className="space-y-1 z-10">
                    <span className="text-[10px] font-mono text-cyber-red uppercase tracking-widest block font-bold">Critical Incidents</span>
                    <span className="text-3xl font-extrabold tracking-tight text-cyber-red drop-shadow-[0_0_8px_rgba(255,61,0,0.4)] animate-pulse">{stats.criticalCount}</span>
                    <span className="text-xs text-slate-400 block">Active root exploits</span>
                  </div>
                  <div className="p-3.5 bg-cyber-red/10 border border-cyber-red/20 text-cyber-red rounded-xl shadow-[0_0_12px_rgba(255,61,0,0.2)]">
                    <Flame size={22} />
                  </div>
                </div>

                {/* High/Medium count */}
                <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 flex items-center justify-between shadow-lg backdrop-blur-md relative overflow-hidden">
                  <div className="space-y-1 z-10">
                    <span className="text-[10px] font-mono text-cyber-yellow uppercase tracking-widest block font-bold">High / Medium Alerts</span>
                    <span className="text-3xl font-extrabold tracking-tight text-cyber-yellow">
                      {stats.highCount + stats.mediumCount}
                    </span>
                    <span className="text-xs text-slate-400 block">Triaged and queued</span>
                  </div>
                  <div className="p-3.5 bg-cyber-yellow/10 border border-cyber-yellow/20 text-cyber-yellow rounded-xl">
                    <AlertTriangle size={22} />
                  </div>
                </div>

                {/* Total Alerts monitored */}
                <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 flex items-center justify-between shadow-lg backdrop-blur-md relative overflow-hidden">
                  <div className="space-y-1 z-10">
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest block">Analyzed Events</span>
                    <span className="text-3xl font-extrabold tracking-tight text-[#00E5FF] drop-shadow-[0_0_8px_rgba(0,229,255,0.3)]">{stats.totalAlerts}</span>
                    <span className="text-xs text-slate-400 block">{stats.resolvedIncidents} resolved cases</span>
                  </div>
                  <div className="p-3.5 bg-cyber-cyan/10 border border-cyber-cyan/20 text-cyber-cyan rounded-xl">
                    <Shield size={22} />
                  </div>
                </div>
              </div>

              {/* Data Visualizations grid */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Timeline trend Area Chart */}
                <div className="lg:col-span-2 p-5 rounded-2xl border border-white/5 bg-[#121214]/60 shadow-lg backdrop-blur-md relative overflow-hidden flex flex-col justify-between">
                  <div>
                    <h3 className="font-bold text-sm tracking-tight text-white mb-1">Threat Progression Trend</h3>
                    <p className="text-xs text-slate-400 mb-4">Daily security event counts categorized by incident severity levels.</p>
                  </div>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={stats.timelineData} margin={{ left: -15, right: 10, top: 10, bottom: 0 }}>
                        <XAxis dataKey="time" stroke="rgba(255,255,255,0.15)" fontSize={10} tickLine={false} />
                        <YAxis stroke="rgba(255,255,255,0.15)" fontSize={10} tickLine={false} />
                        <Tooltip contentStyle={{ background: "#0A0A0C", borderColor: "rgba(255,255,255,0.08)", borderRadius: "12px", color: "#D1D5DB" }} />
                        <Legend wrapperStyle={{ fontSize: 10, marginTop: 10 }} />
                        <Area type="monotone" dataKey="Critical" stackId="1" stroke="#FF3D00" fill="rgba(255, 61, 0, 0.15)" />
                        <Area type="monotone" dataKey="High" stackId="1" stroke="#FFD600" fill="rgba(255, 214, 0, 0.15)" />
                        <Area type="monotone" dataKey="Medium" stackId="1" stroke="#00E5FF" fill="rgba(0, 229, 255, 0.1)" />
                        <Area type="monotone" dataKey="Low" stackId="1" stroke="#00E676" fill="rgba(0, 230, 118, 0.05)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Category distribution Pie Chart */}
                <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 shadow-lg backdrop-blur-md relative overflow-hidden flex flex-col justify-between">
                  <div>
                    <h3 className="font-bold text-sm tracking-tight text-white mb-1">Attack Category Breakdown</h3>
                    <p className="text-xs text-slate-400 mb-4">Event classification based on security event signatures.</p>
                  </div>
                  <div className="h-56 flex items-center justify-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={stats.categoryDistribution}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {stats.categoryDistribution.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={["#00E5FF", "#FF3D00", "#FFD600", "#00E676", "#0060FF"][index % 5]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ background: "#0A0A0C", borderColor: "rgba(255,255,255,0.08)", borderRadius: "12px" }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="flex flex-wrap gap-2 justify-center mt-3 text-[10px]">
                    {stats.categoryDistribution.map((entry, index) => (
                      <div key={index} className="flex items-center gap-1.5 px-2 py-0.5 rounded-lg border border-white/5 bg-white/5">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: ["#00E5FF", "#FF3D00", "#FFD600", "#00E676", "#0060FF"][index % 5] }} />
                        <span className="text-slate-400">{entry.name}:</span>
                        <span className="font-bold text-white">{entry.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* MITRE ATT&CK Matrix Interactive Dashboard segment */}
              <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 shadow-lg backdrop-blur-md relative overflow-hidden">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 gap-2">
                  <div>
                    <h3 className="font-bold text-sm tracking-tight text-white">Interactive MITRE ATT&CK Mapping Grid</h3>
                    <p className="text-xs text-slate-400">Tactics matched against active enterprise intrusion alerts.</p>
                  </div>
                  <button
                    onClick={() => setActiveTab("mitre")}
                    className="text-xs text-[#00E5FF] hover:text-[#00e5ff]/80 font-bold flex items-center gap-1.5 cursor-pointer"
                  >
                    View Framework Matrix
                    <ChevronRight size={14} />
                  </button>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
                  {stats.mitreHeatmap.map((heatmap, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 rounded-xl border font-mono flex flex-col justify-between transition-all duration-150 relative overflow-hidden"
                      style={{
                        backgroundColor: heatmap.count > 0 ? "rgba(0, 229, 255, 0.08)" : "rgba(255,255,255,0.02)",
                        borderColor: heatmap.count > 0 ? "rgba(0, 229, 255, 0.3)" : "rgba(255,255,255,0.05)"
                      }}
                    >
                      <span className={`text-[10px] font-bold block leading-tight ${heatmap.count > 0 ? "text-[#00E5FF]" : "text-slate-400"}`}>
                        {heatmap.tactic}
                      </span>
                      <div className="mt-4 flex items-baseline justify-between">
                        <span className={`text-[10px] ${heatmap.count > 0 ? "text-[#00E5FF]/80" : "text-slate-500"}`}>Active Alerts</span>
                        <span className={`text-lg font-extrabold ${heatmap.count > 0 ? "text-[#00E5FF] drop-shadow-[0_0_6px_rgba(0,229,255,0.4)]" : "text-slate-500"}`}>
                          {heatmap.count}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recent Active Alerts listing */}
              <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 shadow-lg backdrop-blur-md relative overflow-hidden">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold text-sm tracking-tight text-white">Live Security Monitor (Active Alerts)</h3>
                  <button
                    onClick={() => setActiveTab("alerts")}
                    className="text-xs text-[#00E5FF] hover:text-[#00e5ff]/80 font-bold cursor-pointer"
                  >
                    Manage All Alerts
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-white/5 text-slate-400 font-mono text-[10px] uppercase tracking-wider">
                        <th className="py-2.5 px-3">Severity</th>
                        <th className="py-2.5 px-3">Threat</th>
                        <th className="py-2.5 px-3">Tactic</th>
                        <th className="py-2.5 px-3">IP Source / Destination</th>
                        <th className="py-2.5 px-3">Time</th>
                        <th className="py-2.5 px-3">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {alerts.slice(0, 3).map((alert, idx) => {
                        const sev = getSeverityStyles(alert.severity);
                        return (
                          <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                            <td className="py-3 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${sev.bg}`}>
                                {alert.severity}
                              </span>
                            </td>
                            <td className="py-3 px-3 font-medium">
                              <div>
                                <span className="block font-bold text-white">{alert.title}</span>
                                <span className="text-[10px] text-slate-400">{alert.category}</span>
                              </div>
                            </td>
                            <td className="py-3 px-3 font-mono text-[10px]">
                              {alert.mitreAttack?.tactic || "N/A"}
                            </td>
                            <td className="py-3 px-3 font-mono text-[10px]">
                              <span className="text-slate-400">{alert.sourceIp}</span>
                              <ChevronRight size={10} className="inline mx-1 text-slate-600" />
                              <span>{alert.destIp}</span>
                            </td>
                            <td className="py-3 px-3 text-slate-400">
                              {new Date(alert.timestamp).toLocaleTimeString()}
                            </td>
                            <td className="py-3 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${getStatusStyles(alert.status)}`}>
                                {alert.status}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ALERTS TRIAGE HUB TAB VIEW */}
          {activeTab === "alerts" && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-white">Security Incident Triage Center</h1>
                  <p className="text-sm text-slate-400">Inspect, reassign, and generate complete incident response plans.</p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => triggerCsvDownload("alerts")}
                    className="text-[10px] px-4 py-2.5 bg-[#00E5FF] hover:bg-[#00e5ff]/90 text-black rounded-xl font-extrabold flex items-center gap-1.5 shadow-[0_4px_12px_rgba(0,229,255,0.25)] uppercase tracking-wider cursor-pointer transition-all duration-150"
                  >
                    <FileSpreadsheet size={14} />
                    Export Alerts (CSV)
                  </button>
                </div>
              </div>

              {/* Filtering Controls */}
              <div className="p-4 rounded-2xl border border-white/5 bg-[#121214]/60 flex flex-wrap gap-4 items-center justify-between shadow-lg backdrop-blur-md">
                <div className="flex flex-wrap gap-3 items-center flex-1">
                  <div className="relative flex-1 max-w-sm">
                    <Search className="absolute left-3 top-2.5 text-slate-500" size={16} />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                      placeholder="Search assets, categories, IPs..."
                      className="w-full pl-9 pr-4 py-2.5 text-xs rounded-xl border border-white/10 bg-white/5 text-white placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all duration-150"
                    />
                  </div>

                  <div className="flex items-center gap-1.5 text-xs">
                    <span className="text-slate-400">Severity:</span>
                    <select
                      value={filterSeverity}
                      onChange={e => setFilterSeverity(e.target.value)}
                      className="px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#00E5FF]/50"
                    >
                      <option value="All">All Severities</option>
                      <option value="Critical">Critical</option>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-1.5 text-xs">
                    <span className="text-slate-400">Status:</span>
                    <select
                      value={filterStatus}
                      onChange={e => setFilterStatus(e.target.value)}
                      className="px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 text-slate-300 font-mono text-xs focus:outline-none focus:border-[#00E5FF]/50"
                    >
                      <option value="All">All Statuses</option>
                      <option value="Active">Active</option>
                      <option value="Investigating">Investigating</option>
                      <option value="Resolved">Resolved</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Alert triage grid split layout */}
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                
                {/* Left: Alerts List */}
                <div className="xl:col-span-2 space-y-3">
                  {alerts.length === 0 ? (
                    <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-white/10 rounded-2xl bg-[#121214]/20">
                      No security incidents found matching current filter parameters.
                    </div>
                  ) : (
                    alerts.map((alert, idx) => {
                      const styles = getSeverityStyles(alert.severity);
                      const isSelected = selectedAlert?.id === alert.id;
                      return (
                        <div
                          key={idx}
                          onClick={() => setSelectedAlert(alert)}
                          className={`p-4 rounded-2xl border cursor-pointer transition-all hover:scale-[1.005] duration-150 ${
                            isSelected
                              ? "bg-white/5 border-[#00E5FF]/40 ring-1 ring-[#00E5FF]/20 shadow-[0_0_15px_rgba(0,229,255,0.15)]"
                              : "bg-[#121214]/40 border-white/5 hover:bg-[#121214]/60"
                          }`}
                        >
                          <div className="flex flex-wrap items-start justify-between gap-2 mb-2">
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${styles.bg}`}>
                                {alert.severity}
                              </span>
                              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest font-semibold">{alert.category}</span>
                            </div>
                            <span className="text-[10px] font-mono text-slate-400">
                              {new Date(alert.timestamp).toLocaleString()}
                            </span>
                          </div>

                          <h3 className="font-bold text-sm tracking-tight mb-1 text-white">{alert.title}</h3>
                          <p className="text-xs text-slate-400 line-clamp-2 mb-3 leading-relaxed">{alert.description}</p>

                          <div className="flex flex-wrap items-center justify-between pt-3 border-t border-white/5 text-[10px] font-mono">
                            <div className="flex items-center gap-4">
                              <div>
                                <span className="text-slate-500">SRC:</span> <span className="font-bold text-slate-300">{alert.sourceIp}</span>
                              </div>
                              <div>
                                <span className="text-slate-500">DST:</span> <span className="font-bold text-slate-300">{alert.destIp}</span>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${getStatusStyles(alert.status)}`}>
                                {alert.status}
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

                {/* Right: Selected Alert Inspection Panel */}
                <div className="space-y-4">
                  {selectedAlert ? (
                    <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/80 backdrop-blur-md sticky top-6 shadow-xl z-10">
                      <div className="flex items-center justify-between pb-3 border-b border-white/5 mb-4">
                        <span className="font-mono text-[10px] text-slate-400 uppercase tracking-wider font-bold">SEC_SOC INSPECTOR</span>
                        <span className="font-mono text-xs font-bold text-[#00E5FF] drop-shadow-[0_0_5px_rgba(0,229,255,0.3)]">{selectedAlert.id}</span>
                      </div>

                      <h2 className="text-lg font-bold tracking-tight text-white mb-2">{selectedAlert.title}</h2>
                      
                      <div className="flex gap-2 flex-wrap mb-4">
                        <span className={`px-2.5 py-0.5 rounded-lg text-[10px] font-bold ${getSeverityStyles(selectedAlert.severity).bg}`}>
                          {selectedAlert.severity} Severity
                        </span>
                        <span className="px-2 py-0.5 rounded-lg bg-white/5 text-slate-300 text-[10px] font-mono border border-white/10 uppercase">
                          {selectedAlert.category}
                        </span>
                      </div>

                      <div className="space-y-4 text-xs">
                        <div>
                          <span className="font-mono text-[10px] uppercase text-slate-500 block mb-1">Alert Description</span>
                          <p className="p-3 rounded-xl font-sans leading-relaxed bg-white/5 text-slate-300 border border-white/5">
                            {selectedAlert.description}
                          </p>
                        </div>

                        {selectedAlert.mitreAttack && (
                          <div className="p-3.5 rounded-xl border border-[#00E5FF]/20 bg-[#00E5FF]/5">
                            <span className="font-mono text-[10px] uppercase text-slate-400 block mb-1 font-bold">MITRE ATT&CK Mapped Technique</span>
                            <div className="flex justify-between items-baseline mb-1">
                              <span className="font-bold text-[#00E5FF]">{selectedAlert.mitreAttack.technique}</span>
                              <span className="font-mono text-[#00E5FF] text-[11px] font-bold">{selectedAlert.mitreAttack.id}</span>
                            </div>
                            <span className="text-[10px] text-slate-400 font-mono">Tactic Category: {selectedAlert.mitreAttack.tactic}</span>
                          </div>
                        )}

                        <div className="grid grid-cols-2 gap-4 pt-2 font-mono text-[11px]">
                          <div>
                            <span className="text-slate-500 block uppercase text-[9px] mb-0.5">Source IP Address</span>
                            <span className="font-bold text-white">{selectedAlert.sourceIp}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block uppercase text-[9px] mb-0.5">Destination Asset IP</span>
                            <span className="font-bold text-white">{selectedAlert.destIp}</span>
                          </div>
                        </div>

                        {/* Interactive Triage management controls */}
                        <div className="pt-4 border-t border-white/5 gap-3 space-y-3.5">
                          <div>
                            <span className="font-mono text-[10px] uppercase text-slate-500 block mb-1.5">Incident Workflow Status</span>
                            <div className="grid grid-cols-3 gap-1.5">
                              {["Active", "Investigating", "Resolved"].map((st) => {
                                const isActive = selectedAlert.status === st;
                                let btnStyle = "bg-white/5 border-white/10 text-slate-400 hover:text-white";
                                if (isActive) {
                                  if (st === "Active") {
                                    btnStyle = "bg-cyber-red/20 border-cyber-red/40 text-cyber-red shadow-[0_0_10px_rgba(255,61,0,0.2)]";
                                  } else if (st === "Investigating") {
                                    btnStyle = "bg-cyber-yellow/20 border-cyber-yellow/40 text-cyber-yellow shadow-[0_0_10px_rgba(255,214,0,0.2)]";
                                  } else {
                                    btnStyle = "bg-cyber-green/20 border-cyber-green/40 text-cyber-green shadow-[0_0_10px_rgba(0,230,118,0.2)]";
                                  }
                                }
                                return (
                                  <button
                                    key={st}
                                    onClick={() => handleTriageStatusChange(selectedAlert.id, st)}
                                    className={`py-1.5 text-[10px] rounded-lg font-mono font-bold border transition-all duration-150 cursor-pointer ${btnStyle}`}
                                  >
                                    {st}
                                  </button>
                                );
                              })}
                            </div>
                          </div>

                          <div>
                            <span className="font-mono text-[10px] uppercase text-slate-500 block mb-1.5">Assign Active Analyst</span>
                            <select
                                value={selectedAlert.assignedTo || ""}
                                onChange={e => handleTriageAssignmentChange(selectedAlert.id, e.target.value)}
                                className="w-full px-2.5 py-2 text-xs rounded-xl border border-white/10 bg-[#121214] text-slate-300 font-mono focus:outline-none focus:border-[#00E5FF]/50"
                            >
                              <option value="">Unassigned</option>
                              <option value="admin@secassist.ai">Sarah Connor (Admin)</option>
                              <option value="analyst@secassist.ai">John Doe (Analyst)</option>
                              <option value="external@secassist.ai">Elena Rostova (Analyst)</option>
                            </select>
                          </div>

                          {/* Dynamic AI Incident Response Builder */}
                          <div className="pt-2">
                            <button
                              type="button"
                              onClick={() => handleGenerateReport(selectedAlert.id)}
                              disabled={isGeneratingReport || currentUser.role === "Viewer"}
                              className="w-full py-2.5 bg-[#00E5FF] hover:bg-[#00e5ff]/90 disabled:opacity-50 text-black font-extrabold rounded-xl text-xs flex items-center justify-center gap-2 shadow-[0_4px_12px_rgba(0,229,255,0.25)] uppercase tracking-wider cursor-pointer"
                            >
                              {isGeneratingReport ? (
                                <>
                                  <RefreshCw size={12} className="animate-spin" />
                                  Compiling Case Report...
                                </>
                              ) : (
                                <>
                                  <Cpu size={14} />
                                  Compile AI Incident Report
                                </>
                              )}
                            </button>
                            {reportSuccessMessage && (
                              <span className="text-[10px] text-cyber-green text-center block mt-1.5 font-mono font-bold">{reportSuccessMessage}</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-white/10 rounded-2xl bg-[#121214]/20">
                      Select an incident from the alerts queue to begin triage, forensic inspection, and report generation.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* DEEP AI LOG ANALYZER TAB VIEW */}
          {activeTab === "logs" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">AI Log Telemetry Analyzer</h1>
                <p className="text-sm text-slate-400">Upload CSV, JSON or plain-text firewall logs to trigger Gemini threat detection, MITRE mapping, and remediations.</p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                
                {/* Left: Upload and paste interface */}
                <div className="space-y-4">
                  <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 shadow-lg backdrop-blur-md">
                    <h3 className="font-bold text-sm tracking-tight text-white mb-3">Load Log Segment File</h3>

                    <div className="flex gap-2 mb-4 flex-wrap">
                      <button
                        type="button"
                        onClick={() => prefillLogScenario("lockbit")}
                        className="text-[10px] px-3 py-1.5 rounded-lg bg-cyber-red/10 hover:bg-cyber-red/20 text-cyber-red border border-cyber-red/30 font-mono font-bold transition-all duration-150 cursor-pointer shadow-[0_0_8px_rgba(255,61,0,0.15)]"
                      >
                        Sample LockBit Beacon log
                      </button>
                      <button
                        type="button"
                        onClick={() => prefillLogScenario("ssh")}
                        className="text-[10px] px-3 py-1.5 rounded-lg bg-cyber-yellow/10 hover:bg-cyber-yellow/20 text-cyber-yellow border border-cyber-yellow/30 font-mono font-bold transition-all duration-150 cursor-pointer shadow-[0_0_8px_rgba(255,214,0,0.15)]"
                      >
                        Sample SSH Brute log
                      </button>
                      <button
                        type="button"
                        onClick={() => prefillLogScenario("sql")}
                        className="text-[10px] px-3 py-1.5 rounded-lg bg-cyber-cyan/10 hover:bg-cyber-cyan/20 text-[#00E5FF] border border-[#00E5FF]/30 font-mono font-bold transition-all duration-150 cursor-pointer shadow-[0_0_8px_rgba(0,229,255,0.15)]"
                      >
                        Sample SQL Inject log
                      </button>
                    </div>

                    <form onSubmit={handleLogUploadSubmit} className="space-y-4">
                      <div>
                        <label className="block text-xs font-mono mb-1 text-slate-400 font-bold">FILENAME LABEL</label>
                        <input
                          type="text"
                          value={logFilename}
                          onChange={e => setLogFilename(e.target.value)}
                          required
                          className="w-full px-3 py-2 text-xs rounded-xl border border-white/10 bg-[#121214] text-white font-mono focus:outline-none focus:border-[#00E5FF]/50 transition-all duration-150"
                        />
                      </div>

                      {/* Drag & Drop target area */}
                      <div
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onDrop={handleDrop}
                        className={`border-2 border-dashed rounded-xl p-5 text-center transition-all duration-150 cursor-pointer ${
                          dragOver
                            ? "border-[#00E5FF] bg-[#00E5FF]/10 shadow-[0_0_15px_rgba(0,229,255,0.1)]"
                            : "border-white/10 bg-white/5 hover:bg-white/[0.08]"
                        }`}
                      >
                        <Upload className="mx-auto text-[#00E5FF] mb-2 animate-bounce" size={24} />
                        <span className="text-xs font-sans text-slate-400 block mb-1">
                          Drag and drop security logs (JSON, CSV, TXT) here, or browse local files
                        </span>
                        <input
                          type="file"
                          id="file-selector"
                          className="hidden"
                          onChange={e => {
                            if (e.target.files && e.target.files[0]) {
                              const file = e.target.files[0];
                              setLogFilename(file.name);
                              const r = new FileReader();
                              r.onload = ev => setLogContent(String(ev.target?.result));
                              r.readAsText(file);
                            }
                          }}
                        />
                        <label htmlFor="file-selector" className="text-xs text-[#00E5FF] hover:text-[#00e5ff]/80 font-bold block mt-2 underline cursor-pointer">
                          Choose File
                        </label>
                      </div>

                      <div>
                        <label className="block text-xs font-mono mb-1 text-slate-400 font-bold">RAW SECURITY LOG FILE CONTENT</label>
                        <textarea
                          rows={8}
                          value={logContent}
                          onChange={e => setLogContent(e.target.value)}
                          placeholder="Paste audit logs or security daemon logs directly here..."
                          className="w-full p-3 rounded-xl font-mono text-xs border border-white/10 bg-[#121214] text-cyber-green focus:outline-none focus:border-[#00E5FF]/50 transition-all duration-150"
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={isUploadingLog || !logContent.trim() || currentUser.role === "Viewer"}
                        className="w-full py-2.5 bg-[#00E5FF] hover:bg-[#00e5ff]/90 disabled:opacity-50 text-black font-extrabold rounded-xl text-[10px] uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer shadow-[0_4px_12px_rgba(0,229,255,0.25)] transition-all duration-150"
                      >
                        {isUploadingLog ? (
                          <>
                            <RefreshCw className="animate-spin" size={14} />
                            AI Analyzing Telemetry...
                          </>
                        ) : (
                          <>
                            <Cpu size={14} />
                            Submit and Analyze Security Logs
                          </>
                        )}
                      </button>
                    </form>
                  </div>
                </div>

                {/* Right: AI Analysis Results details */}
                <div className="space-y-4">
                  {isUploadingLog ? (
                    <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-white/10 rounded-2xl bg-[#121214]/60 flex flex-col items-center justify-center gap-4">
                      <RefreshCw size={24} className="text-[#00E5FF] animate-spin" />
                      <span className="text-slate-300 leading-relaxed">Connecting to Gemini threat mapping model... Analyzing attack indicators and compiling response mitigation actions. Please stand by.</span>
                    </div>
                  ) : uploadResult ? (
                    <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/80 shadow-xl backdrop-blur-md space-y-4">
                      <div className="flex items-center justify-between pb-3 border-b border-white/5">
                        <span className="font-mono text-[10px] text-slate-400 font-bold uppercase tracking-wider">GEMINI SOC THREAT REPORT</span>
                        <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold ${getSeverityStyles(uploadResult.threatLevel).bg}`}>
                          {uploadResult.threatLevel}
                        </span>
                      </div>

                      <div>
                        <span className="font-mono text-[10px] text-slate-500 uppercase block mb-1 font-bold">Identified Signature</span>
                        <h2 className="text-base font-bold text-white">{uploadResult.threatName}</h2>
                      </div>

                      <div className="p-3.5 rounded-xl border border-white/5 bg-white/5">
                        <span className="font-mono text-[10px] text-slate-400 uppercase block mb-1 font-bold">MITRE Tactic Mapping</span>
                        <div className="flex justify-between items-baseline mb-1">
                          <span className="text-sm font-bold text-[#00E5FF]">{uploadResult.mitreMapping.technique}</span>
                          <span className="font-mono text-[#00E5FF] font-bold text-xs">{uploadResult.mitreMapping.id}</span>
                        </div>
                        <span className="text-[10px] font-mono text-slate-400">Tactic Class: {uploadResult.mitreMapping.tactic}</span>
                      </div>

                      <div>
                        <span className="font-mono text-[10px] text-slate-500 uppercase block mb-1 font-bold">Threat Explanation</span>
                        <p className="text-xs leading-relaxed text-slate-300 bg-white/5 border border-white/5 p-3 rounded-xl">
                          {uploadResult.explanation}
                        </p>
                      </div>

                      <div>
                        <span className="font-mono text-[10px] text-slate-500 uppercase block mb-1.5 font-bold">Actionable SOC Remediations</span>
                        <ul className="space-y-2">
                          {uploadResult.remediationSteps.map((step: string, sIdx: number) => (
                            <li key={sIdx} className="text-xs flex items-start gap-2 text-slate-300 font-sans leading-relaxed">
                              <span className="text-[#00E5FF] font-bold text-xs font-mono">{sIdx + 1}.</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div>
                        <span className="font-mono text-[10px] text-slate-500 uppercase block mb-1.5 font-bold">Suspicious Attack Indicators Found</span>
                        <div className="flex flex-wrap gap-1.5">
                          {uploadResult.suspiciousIndicators.map((ind: string, iIdx: number) => (
                            <span key={iIdx} className="text-[10px] px-2 py-0.5 rounded-lg bg-cyber-red/10 text-cyber-red border border-cyber-red/20 font-mono font-bold">
                              {ind}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-white/10 rounded-2xl bg-[#121214]/20">
                      Paste or select a security log payload on the left panel to execute real-time generative threat intelligence analysis.
                    </div>
                  )}

                  {/* Upload log registry index */}
                  <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 shadow-lg backdrop-blur-md">
                    <h3 className="font-bold text-sm tracking-tight text-white mb-3">Tenant Log Upload Log</h3>
                    <div className="space-y-2">
                      {logs.map((log, idx) => (
                        <div key={idx} className="flex justify-between items-center text-xs p-2.5 rounded-xl border border-white/5 bg-white/5 font-mono">
                          <div className="truncate flex-1 pr-4">
                            <span className="text-[#00E5FF] font-bold text-[11px] block truncate">{log.filename}</span>
                            <span className="text-[9px] text-slate-500">Uploaded: {new Date(log.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <span className={`px-2 py-0.5 rounded-lg text-[10px] uppercase font-bold font-mono ${
                            log.status === "Analyzed" ? "bg-cyber-green/10 text-cyber-green border border-cyber-green/20" : "bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/20"
                          }`}>
                            {log.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* MITRE MATRIX TAB VIEW */}
          {activeTab === "mitre" && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-white">MITRE ATT&CK Enterprise Matrix</h1>
                  <p className="text-sm text-slate-400">
                    Visualize active threat alerts mapped dynamically onto real security industry tactical matrices. Click any technique to view descriptions, mitigations, and detections.
                  </p>
                </div>
                {isLoadingMitre && (
                  <div className="flex items-center gap-2 text-xs text-[#00E5FF] font-mono animate-pulse">
                    <RefreshCw size={14} className="animate-spin" />
                    Synchronizing Matrix...
                  </div>
                )}
              </div>

              {/* Legend & Summary */}
              <div className="p-4 rounded-2xl border border-white/5 bg-white/[0.02] flex flex-wrap gap-4 items-center justify-between text-xs text-slate-300">
                <div className="flex items-center gap-4 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className="w-3 h-3 rounded bg-cyber-red/20 border border-cyber-red/50" />
                    <span>Triggered / Active Technique</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-3 h-3 rounded bg-[#121214]/40 border border-white/5" />
                    <span>Inactive Technique</span>
                  </div>
                </div>
                <div className="font-mono text-[10px] text-slate-400">
                  Total Tactics: <span className="text-[#00E5FF] font-bold">{mitreMatrix.length}</span> |
                  Total Techniques: <span className="text-[#00E5FF] font-bold">
                    {mitreMatrix.reduce((acc, col) => acc + col.techs.length, 0)}
                  </span>
                </div>
              </div>

              {/* Horizontal Scrollable Kanban-style MITRE Matrix Board */}
              <div className="overflow-x-auto pb-6 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
                <div className="flex gap-4 min-w-max pb-2">
                  {mitreMatrix.map((col, cIdx) => (
                    <div key={cIdx} className="w-80 p-4 rounded-2xl border border-white/5 bg-[#121214]/60 shadow-lg backdrop-blur-md flex flex-col gap-3">
                      <span className="font-mono text-[10px] font-extrabold uppercase text-[#00E5FF] tracking-wider pb-2 border-b border-white/5 flex justify-between items-center">
                        <span>{col.tactic}</span>
                        <span className="bg-white/5 px-1.5 py-0.5 rounded text-[8px] text-slate-400">
                          {col.techs.length}
                        </span>
                      </span>
                      <div className="space-y-2 flex-1">
                        {col.techs.map((tech, tIdx) => {
                          // Check if any of our active alerts map to this technique ID
                          const matchingAlerts = alerts.filter(a => a.mitreAttack?.id === tech.id);
                          const isTriggered = matchingAlerts.length > 0;
                          return (
                            <div
                              key={tIdx}
                              onClick={() => {
                                setSelectedMitreTech(tech);
                                setSelectedMitreTacticName(col.tactic);
                              }}
                              className={`p-3 rounded-xl border font-mono text-[10px] leading-tight select-none relative overflow-hidden transition-all duration-150 cursor-pointer hover:border-white/20 hover:scale-[1.02] active:scale-[0.98] ${
                                isTriggered
                                  ? "bg-cyber-red/10 border-cyber-red/30 shadow-[0_0_10px_rgba(255,61,0,0.1)] text-red-300"
                                  : "bg-[#121214]/40 border-white/5 text-slate-400"
                              }`}
                            >
                              <div className="flex justify-between mb-1.5 items-center font-bold">
                                <span className={isTriggered ? "text-cyber-red font-bold" : "text-[#00E5FF] font-semibold"}>
                                  {tech.id}
                                </span>
                                {isTriggered && (
                                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-red animate-ping" />
                                )}
                              </div>
                              <span className={`block font-bold mb-1 font-sans text-xs ${isTriggered ? "text-red-200" : "text-white"}`}>
                                {tech.name}
                              </span>
                              {isTriggered && (
                                <div className="mt-2 pt-1.5 border-t border-cyber-red/20">
                                  <span className="text-[9px] text-cyber-red uppercase font-bold block mb-0.5">Matched Detections:</span>
                                  {matchingAlerts.map((m, mIdx) => (
                                    <span key={mIdx} className="block text-[8px] bg-cyber-red/20 px-1 py-0.5 rounded text-red-200 truncate mb-0.5 font-bold">
                                      {m.title}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* MITRE TECHNIQUE DETAILS MODAL */}
              {selectedMitreTech && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-md">
                  <div className="w-full max-w-2xl rounded-2xl border border-white/10 bg-[#0c0c0e] text-white overflow-hidden shadow-2xl animate-fade-in flex flex-col max-h-[85vh]">
                    {/* Header */}
                    <div className="p-6 border-b border-white/5 bg-gradient-to-r from-cyber-red/10 to-transparent flex justify-between items-start">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#00E5FF]/10 text-[#00E5FF] uppercase border border-[#00E5FF]/20">
                            {selectedMitreTech.id}
                          </span>
                          <span className="text-xs text-slate-400 font-mono">
                            {selectedMitreTacticName}
                          </span>
                        </div>
                        <h2 className="text-xl font-bold tracking-tight text-white">{selectedMitreTech.name}</h2>
                      </div>
                      <button
                        onClick={() => setSelectedMitreTech(null)}
                        className="p-1.5 rounded-lg hover:bg-white/5 text-slate-400 hover:text-white transition-colors font-bold"
                      >
                        ✕
                      </button>
                    </div>

                    {/* Content */}
                    <div className="p-6 overflow-y-auto space-y-6">
                      {/* Description */}
                      <div className="space-y-2">
                        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Technique Description</h3>
                        <p className="text-sm leading-relaxed text-slate-300 bg-white/5 p-4 rounded-xl border border-white/5">
                          {selectedMitreTech.description}
                        </p>
                      </div>

                      {/* Mitigations */}
                      <div className="space-y-2">
                        <h3 className="text-xs font-semibold text-[#00E5FF] uppercase tracking-wider flex items-center gap-1.5">
                          <Shield size={14} /> Actionable Industry Mitigations
                        </h3>
                        <div className="grid grid-cols-1 gap-2">
                          {selectedMitreTech.mitigations.map((mit, idx) => (
                            <div key={idx} className="flex gap-2.5 items-start text-xs text-slate-300 bg-white/[0.02] p-3 rounded-lg border border-white/5">
                              <span className="text-[#00E5FF] mt-0.5">✔</span>
                              <span>{mit}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Detection Recommendations */}
                      <div className="space-y-2">
                        <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                          <Terminal size={14} /> Detection Recommendations
                        </h3>
                        <div className="grid grid-cols-1 gap-2">
                          {selectedMitreTech.detectionRecommendations.map((det, idx) => (
                            <div key={idx} className="flex gap-2.5 items-start text-xs text-slate-300 bg-white/[0.02] p-3 rounded-lg border border-white/5">
                              <span className="text-amber-400 mt-0.5">🔍</span>
                              <span>{det}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Active Mapped Alerts */}
                      <div className="space-y-2">
                        <h3 className="text-xs font-semibold text-cyber-red uppercase tracking-wider">
                          Active Mapped Detections ({alerts.filter(a => a.mitreAttack?.id === selectedMitreTech.id).length})
                        </h3>
                        {(() => {
                          const matchedAlerts = alerts.filter(a => a.mitreAttack?.id === selectedMitreTech.id);
                          if (matchedAlerts.length === 0) {
                            return (
                              <div className="text-xs text-slate-500 bg-white/[0.01] p-4 rounded-xl border border-white/5 text-center">
                                No active system alerts matched to this MITRE technique.
                              </div>
                            );
                          }
                          return (
                            <div className="space-y-2">
                              {matchedAlerts.map((alt) => (
                                <div key={alt.id} className="p-3 rounded-xl border border-cyber-red/20 bg-cyber-red/5 flex justify-between items-center text-xs">
                                  <div>
                                    <div className="flex items-center gap-2 mb-1">
                                      <span className="font-bold text-red-200">{alt.id}</span>
                                      <span className="px-1.5 py-0.5 rounded text-[8px] font-bold uppercase bg-cyber-red/20 text-red-300 border border-cyber-red/30">
                                        {alt.severity}
                                      </span>
                                      <span className="text-slate-400 text-[10px]">IP: {alt.sourceIp}</span>
                                    </div>
                                    <p className="font-semibold text-white">{alt.title}</p>
                                    <p className="text-[10px] text-slate-400 mt-1">{alt.description}</p>
                                  </div>
                                  <div className="text-right ml-4">
                                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-white/5 text-slate-300">
                                      {alt.status}
                                    </span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          );
                        })()}
                      </div>
                    </div>

                    {/* Footer */}
                    <div className="p-4 border-t border-white/5 bg-white/[0.02] flex justify-end">
                      <button
                        onClick={() => setSelectedMitreTech(null)}
                        className="px-4 py-2 rounded-xl text-xs font-bold bg-white/5 hover:bg-white/10 text-slate-300 transition-colors border border-white/10"
                      >
                        Dismiss
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* THREAT INTEL BULLETIN TAB VIEW */}
          {activeTab === "threats" && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-white">Threat Intelligence Library</h1>
                  <p className="text-sm text-slate-400">View active global threat definitions, signatures and remediation guides.</p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Left: Form to submit threat bulletin */}
                <div className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 shadow-lg backdrop-blur-md flex flex-col h-fit">
                  <h3 className="font-bold text-sm tracking-tight text-white mb-4">Post Threat Intel Bulletins</h3>
                  <form onSubmit={handleAddThreatIntel} className="space-y-4">
                    <div>
                      <label className="block text-xs font-mono mb-1 text-slate-400 font-bold">ADVISORY TITLE</label>
                      <input
                        type="text"
                        value={newThreatName}
                        onChange={e => setNewThreatName(e.target.value)}
                        required
                        placeholder="e.g. Hive Ransomware Campaign"
                        className="w-full px-3 py-2 text-xs rounded-xl border border-white/10 bg-[#121214] text-white placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all duration-150"
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs font-mono mb-1 text-slate-400 font-bold">SEVERITY</label>
                        <select
                          value={newThreatSeverity}
                          onChange={e => setNewThreatSeverity(e.target.value as any)}
                          className="w-full px-2.5 py-2 text-xs rounded-xl border border-white/10 bg-[#121214] text-slate-300 font-mono focus:outline-none focus:border-[#00E5FF]/50"
                        >
                          <option value="Critical">Critical</option>
                          <option value="High">High</option>
                          <option value="Medium">Medium</option>
                          <option value="Low">Low</option>
                        </select>
                      </div>

                      <div>
                        <label className="block text-xs font-mono mb-1 text-slate-400 font-bold">MITRE TACTIC</label>
                        <select
                          value={newThreatTactic}
                          onChange={e => setNewThreatTactic(e.target.value)}
                          className="w-full px-2.5 py-2 text-xs rounded-xl border border-white/10 bg-[#121214] text-slate-300 font-mono focus:outline-none focus:border-[#00E5FF]/50"
                        >
                          <option value="Initial Access">Initial Access</option>
                          <option value="Execution">Execution</option>
                          <option value="Credential Access">Credential Access</option>
                          <option value="Command and Control">Command and Control</option>
                          <option value="Exfiltration">Exfiltration</option>
                        </select>
                      </div>
                    </div>

                    <div>
                      <label className="block text-xs font-mono mb-1 text-slate-400 font-bold">TECHNICAL OVERVIEW</label>
                      <textarea
                        rows={4}
                        value={newThreatExplanation}
                        onChange={e => setNewThreatExplanation(e.target.value)}
                        placeholder="Provide details of execution patterns and Indicators of Compromise (IOC)..."
                        className="w-full p-2.5 rounded-xl border border-white/10 bg-[#121214] text-white placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all duration-150"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-mono mb-1 text-slate-400 font-bold">REMEDIATION ACTION SCHEDULER</label>
                      <textarea
                        rows={3}
                        value={newThreatRemediation}
                        onChange={e => setNewThreatRemediation(e.target.value)}
                        placeholder="Actionable steps for enterprise endpoint isolation and patch management..."
                        className="w-full p-2.5 rounded-xl border border-white/10 bg-[#121214] text-white placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all duration-150"
                      />
                    </div>

                    <button
                      type="submit"
                      disabled={currentUser.role === "Viewer" || !newThreatName}
                      className="w-full py-2.5 bg-[#00E5FF] hover:bg-[#00e5ff]/90 disabled:opacity-50 text-black font-extrabold rounded-xl text-[10px] uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer shadow-[0_4px_12px_rgba(0,229,255,0.25)] transition-all duration-150"
                    >
                      Post Intel Bulletin
                    </button>
                  </form>
                </div>

                {/* Right: Bulletin board */}
                <div className="lg:col-span-2 space-y-4">
                  {threats.map((threat, idx) => (
                    <div key={idx} className="p-5 rounded-2xl border border-white/5 bg-[#121214]/60 shadow-lg backdrop-blur-md relative overflow-hidden">
                      <div className="flex items-center justify-between pb-3 border-b border-white/5 mb-4">
                        <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold ${getSeverityStyles(threat.severity).bg}`}>
                          {threat.severity} Alert
                        </span>
                        <span className="font-mono text-xs text-slate-500 font-semibold">Advisory: {threat.id}</span>
                      </div>

                      <h3 className="text-base font-bold tracking-tight text-white mb-2">{threat.name}</h3>
                      <span className="text-[10px] font-mono text-[#00E5FF] block mb-3 font-semibold">
                        MITRE technique mapped: {threat.mitreMapping.technique} ({threat.mitreMapping.id})
                      </span>

                      <div className="space-y-3 text-xs">
                        <div>
                          <span className="font-mono text-[9px] uppercase text-slate-500 block mb-0.5 font-bold">Exploit Mechanism</span>
                          <p className="text-slate-300 leading-relaxed font-sans">{threat.explanation}</p>
                        </div>
                        <div>
                          <span className="font-mono text-[9px] uppercase text-slate-500 block mb-0.5 font-bold">Corporate Remediation Plan</span>
                          <p className="text-slate-300 leading-relaxed font-sans">{threat.remediation}</p>
                        </div>
                        {threat.detectionSignature && (
                          <div className="bg-[#0A0A0C] p-3 rounded-xl border border-white/5 font-mono text-[10px] text-cyber-green leading-relaxed select-all">
                            <span className="text-slate-500 block text-[9px] uppercase mb-1 font-bold">Detection Signature Log Check</span>
                            {threat.detectionSignature}
                          </div>
                        )}
                        {threat.affectedAssets && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {threat.affectedAssets.map((asset, aIdx) => (
                              <span key={aIdx} className="text-[10px] px-2 py-0.5 rounded-lg bg-white/5 border border-white/10 text-slate-400 font-mono font-bold">
                                {asset}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* INCIDENT REPORTS PORTAL TAB VIEW */}
          {activeTab === "reports" && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-white">AI Incident Response Reports</h1>
                  <p className="text-sm text-slate-400">Formal compiled security reviews ready for auditing, exfiltration claims and network assessments.</p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => triggerCsvDownload("reports")}
                    className="text-[10px] px-4 py-2.5 bg-[#00E5FF] hover:bg-[#00e5ff]/90 text-black rounded-xl font-extrabold flex items-center gap-1.5 shadow-[0_4px_12px_rgba(0,229,255,0.25)] transition-all duration-150 uppercase tracking-wider cursor-pointer"
                  >
                    <Download size={14} />
                    Export Reports (CSV)
                  </button>
                </div>
              </div>

              <div className="space-y-6">
                {reports.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 font-mono text-xs border border-dashed border-white/10 rounded-2xl bg-[#121214]/20">
                    No security report incidents have been generated yet. Triaging and generating reports can be initiated from the Alert Center.
                  </div>
                ) : (
                  reports.map((rep, idx) => (
                    <div key={idx} className="p-6 rounded-2xl border border-white/5 bg-[#121214]/80 shadow-xl backdrop-blur-md relative overflow-hidden">
                      <div className="absolute right-0 top-0 p-5 font-mono text-[9px] text-slate-500 font-bold tracking-wider">
                        OFFICIAL INCIDENT MEMORANDUM
                      </div>

                      <div className="pb-4 border-b border-white/5 mb-6 flex flex-wrap items-center justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <div className="p-2.5 bg-[#00E5FF]/10 text-[#00E5FF] rounded-xl border border-[#00E5FF]/20 shadow-[0_0_10px_rgba(0,229,255,0.15)]">
                            <Shield size={24} />
                          </div>
                          <div>
                            <h2 className="text-lg font-bold tracking-tight text-white">{rep.title}</h2>
                            <span className="text-[10px] text-slate-400 font-mono block mt-0.5 font-semibold">
                              Report ID: <span className="font-bold text-[#00E5FF]">{rep.id}</span> • Authored: {new Date(rep.timestamp).toLocaleString()}
                            </span>
                          </div>
                        </div>
                        <span className={`px-2.5 py-1 rounded-lg text-xs font-bold ${getSeverityStyles(rep.severity).bg}`}>
                          {rep.severity} Severity Threat
                        </span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-6 text-xs">
                        {/* Executive Summary */}
                        <div className="space-y-2">
                          <span className="font-mono text-[10px] uppercase text-[#00E5FF] block border-b border-white/5 pb-1 font-extrabold tracking-wider">
                            I. Executive Summary
                          </span>
                          <p className="text-slate-300 leading-relaxed font-sans">{rep.executiveSummary}</p>
                        </div>

                        {/* Technical Details */}
                        <div className="space-y-2">
                          <span className="font-mono text-[10px] uppercase text-[#00E5FF] block border-b border-white/5 pb-1 font-extrabold tracking-wider">
                            II. Forensic Technical Analysis
                          </span>
                          <p className="text-slate-300 leading-relaxed font-sans whitespace-pre-wrap">{rep.technicalDetails}</p>
                        </div>

                        {/* Root Cause Assessment */}
                        <div className="space-y-2">
                          <span className="font-mono text-[10px] uppercase text-[#00E5FF] block border-b border-white/5 pb-1 font-extrabold tracking-wider">
                            III. Root Cause Assessment
                          </span>
                          <p className="text-slate-300 leading-relaxed font-sans whitespace-pre-wrap">{rep.rootCauseAssessment || "No root cause correlated yet."}</p>
                        </div>

                        {/* Action Plan */}
                        <div className="space-y-2">
                          <span className="font-mono text-[10px] uppercase text-[#00E5FF] block border-b border-white/5 pb-1 font-extrabold tracking-wider">
                            IV. Remediation Execution Steps
                          </span>
                          <p className="text-slate-300 leading-relaxed font-sans whitespace-pre-wrap">{rep.remediationPlan}</p>
                        </div>

                        {/* Risk Rating */}
                        <div className="space-y-2">
                          <span className="font-mono text-[10px] uppercase text-[#00E5FF] block border-b border-white/5 pb-1 font-extrabold tracking-wider">
                            V. Risk Rating & Impact
                          </span>
                          <div className="mt-1 space-y-2">
                            <span className={`inline-block px-2.5 py-1 rounded-lg text-[10px] font-bold ${
                              (rep.riskRating || rep.severity) === "Critical" ? "bg-red-500/15 text-red-400 border border-red-500/30" :
                              (rep.riskRating || rep.severity) === "High" ? "bg-orange-500/15 text-orange-400 border border-orange-500/30" :
                              (rep.riskRating || rep.severity) === "Medium" ? "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30" :
                              "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                            }`}>
                              Calculated Risk: {rep.riskRating || rep.severity}
                            </span>
                            <p className="text-slate-400 leading-relaxed font-sans">
                              Dynamic risk rating computed via vulnerability mapping and asset criticality index.
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="mt-8 pt-4 border-t border-white/5 flex flex-wrap justify-between items-center text-[10px] font-mono text-slate-500 font-semibold">
                        <span>Lead Forensic Analyst Signature: <span className="text-slate-200 font-bold">{rep.generatedBy}</span></span>
                        <span>Corporate Verification Hash: <span className="text-[#00E5FF]">MD5_{rep.id}_SEC_CORP</span></span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* THREAT HUNTING WORKBENCH TAB VIEW */}
          {activeTab === "threat-hunting" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Threat Hunting Workbench</h1>
                <p className="text-sm text-slate-400">Search IOC indicators, audit endpoints and accounts, and correlate advanced attacks with high fidelity.</p>
              </div>
              <ThreatHunting token={token} onNavigateToAlerts={(alertId) => {
                setActiveTab("alerts");
              }} />
            </div>
          )}

          {/* ASSET INVENTORY TAB VIEW */}
          {activeTab === "assets" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Enterprise Asset Inventory</h1>
                <p className="text-sm text-slate-400">Manage, track and audit criticality indexes for servers, endpoints and cloud host environments.</p>
              </div>
              <AssetInventory token={token} />
            </div>
          )}

          {/* VULNERABILITY MANAGEMENT TAB VIEW */}
          {activeTab === "vulnerabilities" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Vulnerability Management & CVE Track</h1>
                <p className="text-sm text-slate-400">Audit system exposures, review technical CVSS vectors, and trace patch remediation playbooks.</p>
              </div>
              <VulnerabilityManagement token={token} />
            </div>
          )}

          {/* SECURITY KNOWLEDGE GRAPH TAB VIEW */}
          {activeTab === "knowledge-graph" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Security Knowledge Graph</h1>
                <p className="text-sm text-slate-400">Analyze relationships and correlations between users, devices, alerts, incidents, and threat intel.</p>
              </div>
              <SecurityKnowledgeGraph token={token} />
            </div>
          )}

          {/* AI THREAT AGENT TAB VIEW */}
          {activeTab === "ai-agent" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">AI Threat Investigation Agent</h1>
                <p className="text-sm text-slate-400">Deploy autonomous Tier-3 AI security agents to reconstruct forensics, compile findings, and recommend mitigations.</p>
              </div>
              <AiThreatAgent token={token} alerts={alerts} onRefreshAlerts={fetchDashboardData} />
            </div>
          )}

          {/* SECURITY ARCHITECTURE TAB VIEW */}
          {activeTab === "security-architecture" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Security Architecture Center</h1>
                <p className="text-sm text-slate-400">Model complete end-to-end cloud environment flows, examine cryptographic security controls, and inspect live data pipelines.</p>
              </div>
              <SecurityArchitecture token={token} />
            </div>
          )}

          {/* GRC CENTER COMPLIANCE VIEW */}
          {activeTab === "grc-center" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Governance, Risk & Compliance (GRC) Center</h1>
                <p className="text-sm text-slate-400 font-sans">Audit framework scorecards, mitigate logged corporate risk vectors, and compile Board-level compliance reports.</p>
              </div>
              <GrcCenter token={token} />
            </div>
          )}

        </main>
      </div>

      {/* Corporate System Footer */}
      <footer className="px-6 py-4 border-t border-white/5 text-center text-[10px] font-mono text-slate-500 bg-[#050507]">
        SecAssistAI Security Operations Control Suite v3.2.1 • © 2026 Alpha Corporation Inc. Authorized System Personnel Only.
      </footer>
    </div>
  );
}
