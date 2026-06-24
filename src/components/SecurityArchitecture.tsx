import React, { useState } from "react";
import {
  Shield,
  Cpu,
  Database,
  Lock,
  Network,
  Server,
  Globe,
  RefreshCw,
  Play,
  CheckCircle,
  AlertTriangle,
  FileText,
  Layers,
  Terminal,
  ArrowRight,
  Key,
  ShieldCheck,
  ToggleLeft,
  ToggleRight,
  Activity,
  Workflow,
  Sparkles,
  Search
} from "lucide-react";

interface SecurityArchitectureProps {
  token: string | null;
}

// Custom types for our interactive diagram nodes
type ArchNodeId = "frontend" | "backend" | "auth" | "ai" | "database" | "intel";

interface ArchNodeDetails {
  title: string;
  subtitle: string;
  exposedPorts: string;
  protocol: string;
  spec: string;
  controls: string[];
  connectedAssets: string[];
  vulnerabilityStatus: "Secure" | "Audited" | "Hardened";
}

export default function SecurityArchitecture({ token }: SecurityArchitectureProps) {
  // Active selected node in diagram
  const [selectedNode, setSelectedNode] = useState<ArchNodeId>("backend");

  // Selected Data Flow Pipeline
  const [activePipeline, setActivePipeline] = useState<"ingestion" | "threat" | "ai" | "incident" | "report">("threat");
  const [pipelineStep, setPipelineStep] = useState<number>(0);
  const [isPipelineRunning, setIsPipelineRunning] = useState<boolean>(false);

  // Security Controls state (toggles)
  const [controlsState, setControlsState] = useState({
    mfaEnabled: true,
    rbacEnforced: true,
    tlsForced: true,
    aesRestEnabled: true,
    piiEncrypted: false,
    writeOnceLogs: true,
    siemIntegrated: true,
    tenantIsolation: true,
  });

  // AI Pipeline Simulator State
  const [aiSimulationStep, setAiSimulationStep] = useState<number>(0);
  const [isAiSimulating, setIsAiSimulating] = useState<boolean>(false);
  const [aiLogs, setAiLogs] = useState<string[]>([]);

  // Toggle utility
  const toggleControl = (key: keyof typeof controlsState) => {
    setControlsState(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  // Recalculate Architecture Security Rating based on toggled controls
  const calculateSecurityRating = () => {
    const totalControls = Object.keys(controlsState).length;
    const enabledControls = Object.values(controlsState).filter(Boolean).length;
    const percentage = (enabledControls / totalControls) * 100;

    if (percentage >= 95) return { grade: "A+", color: "text-[#00E5FF]", label: "Compliant & Hardened", percent: percentage };
    if (percentage >= 85) return { grade: "A", color: "text-emerald-400", label: "Highly Secure", percent: percentage };
    if (percentage >= 70) return { grade: "B+", color: "text-teal-400", label: "Satisfactory Security Controls", percent: percentage };
    if (percentage >= 50) return { grade: "C", color: "text-amber-400", label: "Warning: Missing Critical Controls", percent: percentage };
    return { grade: "D-", color: "text-rose-500", label: "Critical Exposures Detected", percent: percentage };
  };

  const rating = calculateSecurityRating();

  // Nodes metadata for rendering details panel
  const nodeDetails: Record<ArchNodeId, ArchNodeDetails> = {
    frontend: {
      title: "Frontend Layer (React SPA)",
      subtitle: "Vite Applet & Core User Interface",
      exposedPorts: "443 (HTTPS)",
      protocol: "TLS 1.3 / HTTPS",
      spec: "React 18 Container, Tailwind CSS, Local Storage OAuth State, Client side routing, Strict Content Security Policy (CSP).",
      controls: [
        "Content Security Policy (CSP) Enforced",
        "XSS Mitigation & React JSX Context Escaping",
        "Secure cookie headers with SameSite=Strict",
        "Subresource Integrity (SRI) on vendor scripts"
      ],
      connectedAssets: ["Client Web browsers", "Ingress Cloud Run Proxy"],
      vulnerabilityStatus: "Hardened"
    },
    backend: {
      title: "Backend Layer (FastAPI / Express Gateway)",
      subtitle: "Microservices & Core Control Plane",
      exposedPorts: "3000 (Internal proxy)",
      protocol: "gRPC & HTTPS / JSON",
      spec: "High Performance FastAPI Endpoint routers, Token validators, CORS request handlers, tenant segregation middleware.",
      controls: [
        "JWT Signature Validation & Expiry Checking",
        "Strict Rate Limiting per IP and Client Tenant",
        "Parametrized query validation against injection",
        "CORS policy limited to verified domains"
      ],
      connectedAssets: ["Database Layer", "Gemini AI API Wrapper", "SIEM Syslog Forwarder"],
      vulnerabilityStatus: "Audited"
    },
    auth: {
      title: "Authentication Layer",
      subtitle: "Firebase Identity Platform & RBAC System",
      exposedPorts: "443 (External API)",
      protocol: "OAuth 2.0 / OpenID Connect",
      spec: "Federated Secure Tokens, cryptographically signed payload claims, custom metadata tenant tagging, multi-factor credential store.",
      controls: [
        "Multifactor Authentication (MFA) enforce option",
        "Cryptographic PBKDF2 credential hashing",
        "Role-Based Access Control (RBAC) scopes checks",
        "OAuth Token Revocation endpoint"
      ],
      connectedAssets: ["Frontend Client View", "Backend REST Middleware"],
      vulnerabilityStatus: "Secure"
    },
    ai: {
      title: "AI Processing Layer (Gemini Pro/Flash Integration)",
      subtitle: "Server-Side Secured AI Investigation Gateway",
      exposedPorts: "443 (Outbound SSL proxy)",
      protocol: "HTTPS / Google AI SDK",
      spec: "Lazy initialization clients, process.env secure storage variables, sanitized prompt templates, output validation schemas.",
      controls: [
        "Server-side prompt shielding & prompt injection protection",
        "Removal of Personally Identifiable Information (PII) before LLM transmit",
        "Outbound telemetry anonymization filters",
        "Structured JSON model response schema forcing"
      ],
      connectedAssets: ["FastAPI Application Server", "SecAssistAI Client Core Panel"],
      vulnerabilityStatus: "Hardened"
    },
    database: {
      title: "Database Layer (PostgreSQL with Drizzle ORM)",
      subtitle: "Relational & Structured Storage Engine",
      exposedPorts: "5432 (Logical SSL Enforce)",
      protocol: "PostgreSQL Native TCP with TLS",
      spec: "Cloud SQL Multi-AZ PostgreSQL instance, database connection pool, automatic backups, micro-segmentation schemas.",
      controls: [
        "Row-Level Security (RLS) policies by Tenant ID",
        "Data Encryption at Rest via Google Managed KMS Keys",
        "Strict Least Privilege Database user credentials",
        "Dynamic Connection pool rate throttling"
      ],
      connectedAssets: ["FastAPI Application Server", "Backup Storage Bucket"],
      vulnerabilityStatus: "Secure"
    },
    intel: {
      title: "Threat Intelligence Layer",
      subtitle: "External Feeds Proxy & IOC Correlation Matrix",
      exposedPorts: "443 (Outbound SSL)",
      protocol: "STIX / TAXII over HTTPS",
      spec: "Dynamic ingestion of verified blacklists, IP reputation caches, Mitre ATT&CK technique catalog mapping.",
      controls: [
        "DNS filtering proxy block list cache",
        "Frequent cron-updates of bad-actor signatures",
        "Dynamic matching of client network logs with IOC registry",
        "Sanitized proxying of external lookup APIs"
      ],
      connectedAssets: ["FastAPI Application Server", "Alert Triage Core Engine"],
      vulnerabilityStatus: "Audited"
    }
  };

  // Pipeline execution simulation
  const runPipelineSimulation = () => {
    if (isPipelineRunning) return;
    setIsPipelineRunning(true);
    setPipelineStep(1);

    const interval = setInterval(() => {
      setPipelineStep(prev => {
        if (prev >= 4) {
          clearInterval(interval);
          setIsPipelineRunning(false);
          return 4;
        }
        return prev + 1;
      });
    }, 2500);
  };

  // AI Pipeline Simulator
  const runAiPipelineTest = () => {
    if (isAiSimulating) return;
    setIsAiSimulating(true);
    setAiSimulationStep(1);
    setAiLogs(["[06:34:17] Initiating AI Investigation Protocol...", "[06:34:17] Fetching telemetry data for Target Asset."]);

    setTimeout(() => {
      setAiSimulationStep(2);
      setAiLogs(prev => [
        ...prev,
        "[06:34:19] Parsing raw logs for unauthorized credential utilization.",
        "[06:34:20] Match found: SSH Brute force attack pattern identified.",
        "[06:34:20] Tactic identified: T1110 (Brute Force)."
      ]);
    }, 2000);

    setTimeout(() => {
      setAiSimulationStep(3);
      setAiLogs(prev => [
        ...prev,
        "[06:34:22] Executing Risk-Scoring calculation matrix.",
        "[06:34:23] Asset Criticality: HIGH. Source IP Reputation: SUSPICIOUS.",
        "[06:34:23] Combined threat metric evaluated: 88/100 (HIGH RISK STATUS)."
      ]);
    }, 4000);

    setTimeout(() => {
      setAiSimulationStep(4);
      setAiLogs(prev => [
        ...prev,
        "[06:34:25] Opening secure stream to Gemini AI Services...",
        "[06:34:26] Constructing contextualized forensic prompt wrapper.",
        "[06:34:27] Gemini AI completed analysis: Root-cause detected as unauthorized key reuse."
      ]);
    }, 6000);

    setTimeout(() => {
      setAiSimulationStep(5);
      setAiLogs(prev => [
        ...prev,
        "[06:34:29] Compiling comprehensive mitigation playbook.",
        "[06:34:30] Board-ready security impact report successfully completed.",
        "[06:34:30] AI Investigation pipeline concluded successfully."
      ]);
      setIsAiSimulating(false);
    }, 8500);
  };

  return (
    <div className="space-y-6">
      {/* Overview Cards row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Architecture rating card */}
        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-[#00E5FF]/5 rounded-full filter blur-xl"></div>
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Architecture Security Posture</span>
          <div className="flex items-baseline gap-2">
            <span className={`text-4xl font-extrabold tracking-tight ${rating.color}`}>{rating.grade}</span>
            <span className="text-xs text-slate-400">({rating.percent.toFixed(0)}% controls enabled)</span>
          </div>
          <span className="text-xs text-slate-300 font-medium block mt-2">{rating.label}</span>
        </div>

        {/* Dynamic Topology status card */}
        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Infrastructure Health</span>
          <div className="flex items-center gap-2 mt-1 text-emerald-400 font-mono text-lg font-bold">
            <Activity size={16} className="animate-pulse" />
            <span>ALL SYSTEMS OPERATIONAL</span>
          </div>
          <p className="text-xs text-slate-400 mt-2">API Gateway latency: <span className="text-slate-200">22ms</span> | Database Pool load: <span className="text-slate-200">14%</span></p>
        </div>

        {/* AI Processing Metrics */}
        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">AI Pipeline Status</span>
          <div className="flex items-center gap-2 mt-1 text-[#00E5FF] font-mono text-lg font-bold">
            <Sparkles size={16} />
            <span>STANDBY / ACTIVE</span>
          </div>
          <p className="text-xs text-slate-400 mt-2">Active Agent: <span className="text-slate-200">Gemini Pro 2.5</span> • Tokens Cache: <span className="text-slate-200">Warm</span></p>
        </div>

        {/* Active controls count */}
        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Security Guards Logged</span>
          <div className="text-white text-lg font-bold mt-1">
            {Object.values(controlsState).filter(Boolean).length} of {Object.keys(controlsState).length} Enabled
          </div>
          <div className="w-full bg-white/5 h-1.5 rounded-full mt-2 overflow-hidden">
            <div
              className="bg-[#00E5FF] h-1.5 rounded-full transition-all duration-500"
              style={{ width: `${rating.percent}%` }}
            ></div>
          </div>
        </div>
      </div>

      {/* Main Grid: Architecture Diagram & Interactive Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Cols: Interactive Diagram */}
        <div className="lg:col-span-2 p-6 rounded-2xl bg-white/[0.02] border border-white/5 flex flex-col space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <Network size={18} className="text-[#00E5FF]" />
                Interactive System Architecture Diagram
              </h2>
              <p className="text-xs text-slate-400">Click on any core layer below to examine its internal engineering specifications and controls.</p>
            </div>
            <div className="px-2.5 py-1 rounded-full bg-[#00E5FF]/10 text-[#00E5FF] font-mono text-[10px] font-bold border border-[#00E5FF]/20">
              Interactive Topology Map
            </div>
          </div>

          {/* SVG Diagram Canvas */}
          <div className="w-full h-[380px] bg-[#050507] rounded-xl border border-white/5 relative overflow-hidden flex items-center justify-center p-4">
            {/* Grid Overlay background */}
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,229,255,0.02),transparent_70%)]"></div>
            <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.01)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.01)_1px,transparent_1px)] bg-[size:20px_20px]"></div>

            {/* SVG Elements with nodes */}
            <svg className="w-full h-full max-w-2xl" viewBox="0 0 600 350">
              {/* Connecting lines with glow */}
              <defs>
                <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
              </defs>

              {/* Connecting Paths */}
              {/* Frontend to Auth */}
              <path d="M 120 175 L 240 105" stroke={selectedNode === "frontend" || selectedNode === "auth" ? "#00E5FF" : "#334155"} strokeWidth="1.5" fill="none" strokeDasharray="4" className="transition-all" />
              {/* Frontend to Backend */}
              <path d="M 120 175 L 240 175" stroke={selectedNode === "frontend" || selectedNode === "backend" ? "#00E5FF" : "#334155"} strokeWidth="1.5" fill="none" strokeDasharray="4" className="transition-all" />
              {/* Auth to Backend */}
              <path d="M 280 105 L 280 145" stroke={selectedNode === "auth" || selectedNode === "backend" ? "#00E5FF" : "#334155"} strokeWidth="1.5" fill="none" strokeDasharray="4" className="transition-all" />
              {/* Backend to Database */}
              <path d="M 320 175 L 440 105" stroke={selectedNode === "backend" || selectedNode === "database" ? "#00E5FF" : "#334155"} strokeWidth="1.5" fill="none" strokeDasharray="4" className="transition-all" />
              {/* Backend to AI Layer */}
              <path d="M 320 175 L 440 175" stroke={selectedNode === "backend" || selectedNode === "ai" ? "#00E5FF" : "#334155"} strokeWidth="1.5" fill="none" strokeDasharray="4" className="transition-all" />
              {/* Backend to Threat Intel */}
              <path d="M 320 175 L 440 245" stroke={selectedNode === "backend" || selectedNode === "intel" ? "#00E5FF" : "#334155"} strokeWidth="1.5" fill="none" strokeDasharray="4" className="transition-all" />

              {/* Node 1: FRONTEND LAYER */}
              <g className="cursor-pointer group" onClick={() => setSelectedNode("frontend")}>
                <rect x="20" y="145" width="100" height="60" rx="8" 
                  fill={selectedNode === "frontend" ? "#00E5FF1A" : "#1E293B33"} 
                  stroke={selectedNode === "frontend" ? "#00E5FF" : "#475569"} 
                  strokeWidth={selectedNode === "frontend" ? "2" : "1"} 
                  className="transition-all duration-200"
                />
                <text x="70" y="173" fill="white" fontSize="11" fontWeight="bold" textAnchor="middle" fontFamily="sans-serif">Frontend</text>
                <text x="70" y="188" fill="#94A3B8" fontSize="9" textAnchor="middle" fontFamily="monospace">React / Vite</text>
                <circle cx="70" cy="135" r="4" fill="#00E5FF" filter={selectedNode === "frontend" ? "url(#glow)" : ""} />
              </g>

              {/* Node 2: AUTH LAYER */}
              <g className="cursor-pointer group" onClick={() => setSelectedNode("auth")}>
                <rect x="220" y="75" width="120" height="60" rx="8" 
                  fill={selectedNode === "auth" ? "#00E5FF1A" : "#1E293B33"} 
                  stroke={selectedNode === "auth" ? "#00E5FF" : "#475569"} 
                  strokeWidth={selectedNode === "auth" ? "2" : "1"} 
                  className="transition-all duration-200"
                />
                <text x="280" y="103" fill="white" fontSize="11" fontWeight="bold" textAnchor="middle" fontFamily="sans-serif">Authentication</text>
                <text x="280" y="118" fill="#94A3B8" fontSize="9" textAnchor="middle" fontFamily="monospace">Firebase / RBAC</text>
                <circle cx="280" cy="65" r="4" fill="#10B981" filter={selectedNode === "auth" ? "url(#glow)" : ""} />
              </g>

              {/* Node 3: BACKEND API GATEWAY */}
              <g className="cursor-pointer group" onClick={() => setSelectedNode("backend")}>
                <rect x="220" y="145" width="120" height="60" rx="8" 
                  fill={selectedNode === "backend" ? "#00E5FF1A" : "#1E293B33"} 
                  stroke={selectedNode === "backend" ? "#00E5FF" : "#475569"} 
                  strokeWidth={selectedNode === "backend" ? "2" : "1"} 
                  className="transition-all duration-200"
                />
                <text x="280" y="173" fill="white" fontSize="11" fontWeight="bold" textAnchor="middle" fontFamily="sans-serif">FastAPI Backend</text>
                <text x="280" y="188" fill="#94A3B8" fontSize="9" textAnchor="middle" fontFamily="monospace">API Server Gateway</text>
                <circle cx="280" cy="135" r="4" fill="#00E5FF" filter={selectedNode === "backend" ? "url(#glow)" : ""} />
              </g>

              {/* Node 4: DATABASE LAYER */}
              <g className="cursor-pointer group" onClick={() => setSelectedNode("database")}>
                <rect x="440" y="75" width="120" height="60" rx="8" 
                  fill={selectedNode === "database" ? "#00E5FF1A" : "#1E293B33"} 
                  stroke={selectedNode === "database" ? "#00E5FF" : "#475569"} 
                  strokeWidth={selectedNode === "database" ? "2" : "1"} 
                  className="transition-all duration-200"
                />
                <text x="500" y="103" fill="white" fontSize="11" fontWeight="bold" textAnchor="middle" fontFamily="sans-serif">Database</text>
                <text x="500" y="118" fill="#94A3B8" fontSize="9" textAnchor="middle" fontFamily="monospace">PostgreSQL / Drizzle</text>
                <circle cx="500" cy="65" r="4" fill="#10B981" filter={selectedNode === "database" ? "url(#glow)" : ""} />
              </g>

              {/* Node 5: AI PROCESSING LAYER */}
              <g className="cursor-pointer group" onClick={() => setSelectedNode("ai")}>
                <rect x="440" y="145" width="120" height="60" rx="8" 
                  fill={selectedNode === "ai" ? "#00E5FF1A" : "#1E293B33"} 
                  stroke={selectedNode === "ai" ? "#00E5FF" : "#475569"} 
                  strokeWidth={selectedNode === "ai" ? "2" : "1"} 
                  className="transition-all duration-200"
                />
                <text x="500" y="173" fill="white" fontSize="11" fontWeight="bold" textAnchor="middle" fontFamily="sans-serif">Gemini AI Engine</text>
                <text x="500" y="188" fill="#94A3B8" fontSize="9" textAnchor="middle" fontFamily="monospace">Google AI SDK Wrapper</text>
                <circle cx="500" cy="135" r="4" fill="#8B5CF6" filter={selectedNode === "ai" ? "url(#glow)" : ""} />
              </g>

              {/* Node 6: THREAT INTEL feeds */}
              <g className="cursor-pointer group" onClick={() => setSelectedNode("intel")}>
                <rect x="440" y="215" width="120" height="60" rx="8" 
                  fill={selectedNode === "intel" ? "#00E5FF1A" : "#1E293B33"} 
                  stroke={selectedNode === "intel" ? "#00E5FF" : "#475569"} 
                  strokeWidth={selectedNode === "intel" ? "2" : "1"} 
                  className="transition-all duration-200"
                />
                <text x="500" y="243" fill="white" fontSize="11" fontWeight="bold" textAnchor="middle" fontFamily="sans-serif">Threat Intel</text>
                <text x="500" y="258" fill="#94A3B8" fontSize="9" textAnchor="middle" fontFamily="monospace">STIX / TAXII Proxy</text>
                <circle cx="500" cy="205" r="4" fill="#EF4444" filter={selectedNode === "intel" ? "url(#glow)" : ""} />
              </g>
            </svg>
          </div>

          {/* Infrastructure Topology Section */}
          <div className="pt-4 border-t border-white/5">
            <h3 className="text-sm font-semibold text-slate-200 mb-2 flex items-center gap-1.5">
              <Server size={14} className="text-[#00E5FF]" />
              Production Infrastructure Physical Topology
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
              {[
                { name: "UI Static", type: "Vite SPA", platform: "Cloud Run Container", status: "Healthy", lat: "12ms", ip: "10.120.0.4" },
                { name: "Express API", type: "Gate Proxy", platform: "Cloud Run Container", status: "Healthy", lat: "22ms", ip: "10.120.0.12" },
                { name: "Auth Svc", type: "OIDC Server", platform: "SaaS Managed Identity", status: "Healthy", lat: "8ms", ip: "Auth SaaS" },
                { name: "Cloud SQL", type: "PostgreSQL", platform: "Cloud SQL Multi-AZ", status: "Healthy", lat: "1.5ms", ip: "10.120.14.8" },
                { name: "Gemini SDK", type: "AI Engine", platform: "Google LLM Edge Gateway", status: "Healthy", lat: "185ms", ip: "AI Direct" },
                { name: "SIEM Syslog", type: "Forwarder", platform: "Managed PubSub Sink", status: "Healthy", lat: "4ms", ip: "10.120.5.25" }
              ].map((topo, idx) => (
                <div key={idx} className="p-2.5 rounded-xl bg-[#070709] border border-white/5 text-center flex flex-col justify-between">
                  <span className="text-[10px] font-bold text-slate-300 truncate">{topo.name}</span>
                  <span className="text-[9px] font-mono text-[#00E5FF] mt-0.5">{topo.type}</span>
                  <div className="mt-2 flex items-center justify-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                    <span className="text-[8px] font-mono text-slate-400">{topo.lat}</span>
                  </div>
                  <span className="text-[8px] font-mono text-slate-500 mt-1 truncate">{topo.ip}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right 1 Col: Dynamic details panel */}
        <div className="space-y-6">
          {/* Node Details Panel */}
          <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/5 space-y-4">
            <div className="flex justify-between items-start border-b border-white/5 pb-3">
              <div>
                <span className="text-[10px] font-mono text-[#00E5FF] font-bold uppercase tracking-wider block">Layer Specifications</span>
                <h3 className="text-base font-bold text-white mt-1">{nodeDetails[selectedNode].title}</h3>
              </div>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                nodeDetails[selectedNode].vulnerabilityStatus === "Secure" 
                  ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                  : nodeDetails[selectedNode].vulnerabilityStatus === "Hardened"
                  ? "bg-[#00E5FF]/10 text-[#00E5FF] border-[#00E5FF]/20"
                  : "bg-amber-500/10 text-amber-400 border-amber-500/20"
              }`}>
                {nodeDetails[selectedNode].vulnerabilityStatus}
              </span>
            </div>

            <div className="space-y-3.5 text-xs">
              <div>
                <span className="text-slate-500 font-mono text-[9px] block">COMMUNICATION PORT & PROTOCOL</span>
                <span className="text-slate-200 font-medium font-mono text-xs">{nodeDetails[selectedNode].exposedPorts} • {nodeDetails[selectedNode].protocol}</span>
              </div>

              <div>
                <span className="text-slate-500 font-mono text-[9px] block">ARCHITECTURE SUMMARY</span>
                <p className="text-slate-300 leading-relaxed font-sans text-xs mt-1">{nodeDetails[selectedNode].spec}</p>
              </div>

              <div>
                <span className="text-slate-500 font-mono text-[9px] block mb-1.5">MAPPED SECURITY GUARDS</span>
                <div className="space-y-1.5">
                  {nodeDetails[selectedNode].controls.map((ctrl, i) => (
                    <div key={i} className="flex items-start gap-2 bg-white/[0.01] p-1.5 rounded-lg border border-white/5">
                      <ShieldCheck size={14} className="text-emerald-400 mt-0.5 shrink-0" />
                      <span className="text-slate-300 text-[11px] font-medium">{ctrl}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-slate-500 font-mono text-[9px] block mb-1">CONNECTED SYSTEM ASSETS</span>
                <div className="flex flex-wrap gap-1.5">
                  {nodeDetails[selectedNode].connectedAssets.map((asset, i) => (
                    <span key={i} className="px-2 py-0.5 rounded-md bg-[#0F172A]/80 border border-[#38BDF8]/20 text-[#38BDF8] text-[9px] font-mono font-bold">
                      {asset}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Controls Config Center */}
          <div className="p-5 rounded-2xl bg-[#09090C] border border-white/5 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-1.5">
                <Lock size={15} className="text-[#00E5FF]" />
                Security Controls Dashboard
              </h3>
              <p className="text-[11px] text-slate-400">Toggle defensive modules to simulate security rating shifts in real time.</p>
            </div>

            <div className="space-y-2.5">
              {[
                { label: "MFA Token Forced Enforce", desc: "Authenticates client panel login via double check verification", state: "mfaEnabled", icon: Key },
                { label: "Least Privilege RBAC Enforced", desc: "Locks Viewer role from triggering server payloads simulations", state: "rbacEnforced", icon: Shield },
                { label: "TLS 1.3 Transport Encryption", desc: "Enforce perfect forward secrecy cipher suites on API endpoints", state: "tlsForced", icon: Network },
                { label: "AES-256 Storage Crypto", desc: "Encrypt database tables at rest in multi-AZ storage cells", state: "aesRestEnabled", icon: Database },
                { label: "PII Shielding Data Filter", desc: "Filters social security numbers and credentials from AI telemetry", state: "piiEncrypted", icon: Sparkles },
                { label: "Syslog Write-Once Storage", desc: "Enforces log immutability blocks for audits", state: "writeOnceLogs", icon: FileText },
                { label: "SIEM Real-Time Sync Forwarding", desc: "Streams logs to centralized audit data lakes", state: "siemIntegrated", icon: Workflow },
                { label: "Multi-Tenant RLS Policy", desc: "Locks Postgres row levels by tenant schema id", state: "tenantIsolation", icon: Layers }
              ].map((ctrl, i) => {
                const Icon = ctrl.icon;
                const active = controlsState[ctrl.state as keyof typeof controlsState];
                return (
                  <div key={i} className="flex items-center justify-between p-2 rounded-xl bg-white/[0.01] border border-white/5 hover:bg-white/[0.02] transition-colors">
                    <div className="flex items-start gap-2 max-w-[78%]">
                      <Icon size={14} className={`mt-0.5 ${active ? "text-[#00E5FF]" : "text-slate-500"}`} />
                      <div>
                        <span className="text-[11px] font-bold text-slate-200 block leading-tight">{ctrl.label}</span>
                        <span className="text-[9px] text-slate-400 block leading-normal mt-0.5">{ctrl.desc}</span>
                      </div>
                    </div>
                    <button 
                      type="button"
                      onClick={() => toggleControl(ctrl.state as keyof typeof controlsState)}
                      className="text-slate-400 hover:text-white transition-colors cursor-pointer"
                    >
                      {active ? (
                        <ToggleRight size={26} className="text-[#00E5FF]" />
                      ) : (
                        <ToggleLeft size={26} className="text-slate-600" />
                      )}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Data Flow Visualizer */}
      <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/5 space-y-4">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Workflow size={18} className="text-[#00E5FF]" />
              Interactive Data Flow Pipelines
            </h2>
            <p className="text-xs text-slate-400">Review sequence maps of live SOC transactions across components.</p>
          </div>
          <button
            onClick={runPipelineSimulation}
            disabled={isPipelineRunning}
            className="px-4 py-2 bg-[#00E5FF]/10 text-[#00E5FF] hover:bg-[#00E5FF]/20 border border-[#00E5FF]/30 hover:border-[#00E5FF]/50 rounded-xl text-xs font-mono font-bold flex items-center gap-2 transition-all cursor-pointer disabled:opacity-50"
          >
            {isPipelineRunning ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />}
            <span>{isPipelineRunning ? "Simulating Execution..." : "Simulate Flow Execution"}</span>
          </button>
        </div>

        {/* Pipelines Selectors */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
          {[
            { id: "ingestion", label: "Log Ingestion Pipeline", desc: "Collector to structured store" },
            { id: "threat", label: "Threat Detection Pipeline", desc: "IOC identification matches" },
            { id: "ai", label: "AI Investigation Pipeline", desc: "Gemini forensics compilation" },
            { id: "incident", label: "Incident Response Pipeline", desc: "Mitigation, lock & alerts" },
            { id: "report", label: "Report Generation Pipeline", desc: "GRC audit compiler engine" }
          ].map((pipe) => (
            <button
              key={pipe.id}
              onClick={() => {
                setActivePipeline(pipe.id as any);
                setPipelineStep(0);
              }}
              className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                activePipeline === pipe.id
                  ? "bg-[#00E5FF]/5 text-[#00E5FF] border-[#00E5FF]/30 shadow-[0_0_12px_rgba(0,229,255,0.08)]"
                  : "bg-[#060608]/40 text-slate-400 border-white/5 hover:border-white/10 hover:text-slate-200"
              }`}
            >
              <span className="text-xs font-bold block">{pipe.label}</span>
              <span className="text-[10px] text-slate-500 mt-0.5 block leading-tight">{pipe.desc}</span>
            </button>
          ))}
        </div>

        {/* Pipeline steps render */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 bg-[#050507] p-5 rounded-xl border border-white/5 relative">
          {activePipeline === "ingestion" && [
            { title: "1. Log Source Collector", tech: "Syslog Agent", desc: "Reads firewalls, endpoint events, and auth server journals in real-time." },
            { title: "2. Parser & Normalizer", tech: "FastAPI JSON Schema", desc: "Ingests raw log blocks and maps fields to compliant security schemas." },
            { title: "3. Database Store", tech: "PostgreSQL / Drizzle", desc: "Inserts records safely with dedicated multi-tenant RLS keys." },
            { title: "4. Alert Rule Engine", tech: "STIX IOC Matcher", desc: "Evaluates new rows against blacklists to trigger anomalies." }
          ].map((step, idx) => {
            const isCompleted = pipelineStep > idx;
            const isCurrent = pipelineStep === idx;
            return (
              <div 
                key={idx} 
                className={`p-4 rounded-xl border transition-all duration-300 relative ${
                  isCompleted 
                    ? "bg-emerald-500/[0.02] border-emerald-500/30 text-emerald-400" 
                    : isCurrent 
                    ? "bg-[#00E5FF]/5 border-[#00E5FF] text-[#00E5FF] shadow-[0_0_15px_rgba(0,229,255,0.1)]" 
                    : "bg-[#0A0A0E] border-white/5 text-slate-400"
                }`}
              >
                {/* Visual arrow connector */}
                {idx < 3 && (
                  <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10">
                    <ArrowRight size={14} className={isCompleted ? "text-emerald-500" : "text-slate-600"} />
                  </div>
                )}
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[10px] font-mono font-bold tracking-wider">{step.title}</span>
                  {isCompleted && <CheckCircle size={12} className="text-emerald-400" />}
                </div>
                <span className="text-xs font-bold block text-white">{step.tech}</span>
                <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{step.desc}</p>
              </div>
            );
          })}

          {activePipeline === "threat" && [
            { title: "1. Ingest Log Streams", tech: "Ingress Router", desc: "Unparsed firewall connection data incoming from port 3000." },
            { title: "2. IOC Registry Scan", tech: "Threat Intel Cache", desc: "Matches source IP parameters with known malicious ransomware nodes." },
            { title: "3. Risk Score Matrix", tech: "Evaluation Block", desc: "Evaluates incident severity based on target asset critical ratings." },
            { title: "4. Alert Triage Notify", tech: "Webhook Dispatcher", desc: "Alert generated and active state written to user panel screen." }
          ].map((step, idx) => {
            const isCompleted = pipelineStep > idx;
            const isCurrent = pipelineStep === idx;
            return (
              <div 
                key={idx} 
                className={`p-4 rounded-xl border transition-all duration-300 relative ${
                  isCompleted 
                    ? "bg-emerald-500/[0.02] border-emerald-500/30 text-emerald-400" 
                    : isCurrent 
                    ? "bg-[#00E5FF]/5 border-[#00E5FF] text-[#00E5FF] shadow-[0_0_15px_rgba(0,229,255,0.1)]" 
                    : "bg-[#0A0A0E] border-white/5 text-slate-400"
                }`}
              >
                {idx < 3 && (
                  <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10">
                    <ArrowRight size={14} className={isCompleted ? "text-emerald-500" : "text-slate-600"} />
                  </div>
                )}
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[10px] font-mono font-bold tracking-wider">{step.title}</span>
                  {isCompleted && <CheckCircle size={12} className="text-emerald-400" />}
                </div>
                <span className="text-xs font-bold block text-white">{step.tech}</span>
                <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{step.desc}</p>
              </div>
            );
          })}

          {activePipeline === "ai" && [
            { title: "1. Prompt Context Load", tech: "Data Extractor", desc: "Bundles alert history, node specs, and network traces into metadata structure." },
            { title: "2. Gemini Gateway Stream", tech: "Google Generative AI", desc: "Transmits context server-side with strict API shielding safeguards." },
            { title: "3. Threat Classification", tech: "LLM Reasoning Chain", desc: "Analyzes system traces, maps MITRE tactics, and isolates root-causes." },
            { title: "4. Remediation Dispatch", tech: "Playbook Synthesizer", desc: "Returns highly reliable technical playbooks and forensic records." }
          ].map((step, idx) => {
            const isCompleted = pipelineStep > idx;
            const isCurrent = pipelineStep === idx;
            return (
              <div 
                key={idx} 
                className={`p-4 rounded-xl border transition-all duration-300 relative ${
                  isCompleted 
                    ? "bg-emerald-500/[0.02] border-emerald-500/30 text-emerald-400" 
                    : isCurrent 
                    ? "bg-[#00E5FF]/5 border-[#00E5FF] text-[#00E5FF] shadow-[0_0_15px_rgba(0,229,255,0.1)]" 
                    : "bg-[#0A0A0E] border-white/5 text-slate-400"
                }`}
              >
                {idx < 3 && (
                  <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10">
                    <ArrowRight size={14} className={isCompleted ? "text-emerald-500" : "text-slate-600"} />
                  </div>
                )}
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[10px] font-mono font-bold tracking-wider">{step.title}</span>
                  {isCompleted && <CheckCircle size={12} className="text-emerald-400" />}
                </div>
                <span className="text-xs font-bold block text-white">{step.tech}</span>
                <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{step.desc}</p>
              </div>
            );
          })}

          {activePipeline === "incident" && [
            { title: "1. Incident Log Trigger", tech: "Drizzle Core Schema", desc: "Persists an active alert as a full forensic incident investigation." },
            { title: "2. Tenant Alert Dispatch", tech: "Firebase Auth Group", desc: "Pushes warnings to local administrators with correct RBAC level permissions." },
            { title: "3. Automated Lock Lock", tech: "Cloud API Wrapper", desc: "Issues isolated routing rules to lock infected servers dynamically." },
            { title: "4. Mitigation Review", tech: "Analyst Sign-Off", desc: "Ensures patches are in place before allowing server unlock tokens." }
          ].map((step, idx) => {
            const isCompleted = pipelineStep > idx;
            const isCurrent = pipelineStep === idx;
            return (
              <div 
                key={idx} 
                className={`p-4 rounded-xl border transition-all duration-300 relative ${
                  isCompleted 
                    ? "bg-emerald-500/[0.02] border-emerald-500/30 text-emerald-400" 
                    : isCurrent 
                    ? "bg-[#00E5FF]/5 border-[#00E5FF] text-[#00E5FF] shadow-[0_0_15px_rgba(0,229,255,0.1)]" 
                    : "bg-[#0A0A0E] border-white/5 text-slate-400"
                }`}
              >
                {idx < 3 && (
                  <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10">
                    <ArrowRight size={14} className={isCompleted ? "text-emerald-500" : "text-slate-600"} />
                  </div>
                )}
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[10px] font-mono font-bold tracking-wider">{step.title}</span>
                  {isCompleted && <CheckCircle size={12} className="text-emerald-400" />}
                </div>
                <span className="text-xs font-bold block text-white">{step.tech}</span>
                <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{step.desc}</p>
              </div>
            );
          })}

          {activePipeline === "report" && [
            { title: "1. DB Analytics Fetch", tech: "SQL Metrics compiler", desc: "Gathers system threat level numbers, vulnerability scores, and remediation trends." },
            { title: "2. GRC Framework Map", tech: "SOC2 / NIST Compiler", desc: "Pairs audit records with compliance checklists and evidence files." },
            { title: "3. Board-Level Render", tech: "Markdown Builder", desc: "Constructs beautifully formatted executive summaries for board reviews." },
            { title: "4. Compliance Ledger Write", tech: "Audit DB Table", desc: "Writes permanent log records of evidence compilation for external certifiers." }
          ].map((step, idx) => {
            const isCompleted = pipelineStep > idx;
            const isCurrent = pipelineStep === idx;
            return (
              <div 
                key={idx} 
                className={`p-4 rounded-xl border transition-all duration-300 relative ${
                  isCompleted 
                    ? "bg-emerald-500/[0.02] border-emerald-500/30 text-emerald-400" 
                    : isCurrent 
                    ? "bg-[#00E5FF]/5 border-[#00E5FF] text-[#00E5FF] shadow-[0_0_15px_rgba(0,229,255,0.1)]" 
                    : "bg-[#0A0A0E] border-white/5 text-slate-400"
                }`}
              >
                {idx < 3 && (
                  <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10">
                    <ArrowRight size={14} className={isCompleted ? "text-emerald-500" : "text-slate-600"} />
                  </div>
                )}
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[10px] font-mono font-bold tracking-wider">{step.title}</span>
                  {isCompleted && <CheckCircle size={12} className="text-emerald-400" />}
                </div>
                <span className="text-xs font-bold block text-white">{step.tech}</span>
                <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{step.desc}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* AI Pipeline Visualization Section */}
      <div className="p-6 rounded-2xl bg-[#09090C] border border-white/5 space-y-6">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Sparkles size={18} className="text-[#8B5CF6]" />
              Generative AI Pipeline Visualization & Core Playground
            </h2>
            <p className="text-xs text-slate-400 font-sans">Debug the step-by-step telemetry as Gemini orchestrates threat telemetry into structured logs.</p>
          </div>
          <button
            onClick={runAiPipelineTest}
            disabled={isAiSimulating}
            className="px-4 py-2 bg-[#8B5CF6]/10 text-[#C084FC] hover:bg-[#8B5CF6]/20 border border-[#8B5CF6]/30 hover:border-[#8B5CF6]/50 rounded-xl text-xs font-mono font-bold flex items-center gap-2 transition-all cursor-pointer disabled:opacity-50"
          >
            {isAiSimulating ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />}
            <span>{isAiSimulating ? "Running AI Test Cycle..." : "Execute AI pipeline Simulation"}</span>
          </button>
        </div>

        {/* AI Step Progression */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {[
            { step: 1, title: "1. Security Log Collect", engine: "Forwarder Agent", activeColor: "border-[#8B5CF6] text-white bg-[#8B5CF6]/5" },
            { step: 2, title: "2. Threat Detection Match", engine: "MITRE Parser", activeColor: "border-[#8B5CF6] text-white bg-[#8B5CF6]/5" },
            { step: 3, title: "3. Combined Risk Score", engine: "Weighted Alg", activeColor: "border-[#8B5CF6] text-white bg-[#8B5CF6]/5" },
            { step: 4, title: "4. Gemini Investigation", engine: "Gemini Pro 2.5", activeColor: "border-[#8B5CF6] text-white bg-[#8B5CF6]/5" },
            { step: 5, title: "5. Report Generation", engine: "GRC Structurer", activeColor: "border-[#8B5CF6] text-white bg-[#8B5CF6]/5" },
          ].map((item) => {
            const isCompleted = aiSimulationStep > item.step;
            const isCurrent = aiSimulationStep === item.step;
            return (
              <div 
                key={item.step}
                className={`p-3 rounded-xl border text-center transition-all ${
                  isCompleted 
                    ? "border-emerald-500/30 text-emerald-400 bg-emerald-500/[0.01]" 
                    : isCurrent 
                    ? "border-[#8B5CF6] text-[#C084FC] bg-[#8B5CF6]/10 shadow-[0_0_12px_rgba(139,92,246,0.15)]" 
                    : "border-white/5 text-slate-500 bg-transparent"
                }`}
              >
                <span className="text-xs font-bold block">{item.title}</span>
                <span className={`text-[10px] font-mono mt-1 block ${isCurrent ? "text-white" : isCompleted ? "text-emerald-500/80" : "text-slate-600"}`}>
                  {item.engine}
                </span>
                <div className="mt-2 flex justify-center">
                  <span className={`w-2 h-2 rounded-full ${isCurrent ? "bg-[#8B5CF6] animate-ping" : isCompleted ? "bg-emerald-400" : "bg-slate-700"}`}></span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Console / Playback logger */}
        <div className="bg-[#050507] rounded-xl border border-white/5 p-4 font-mono text-xs text-slate-300">
          <div className="flex justify-between items-center border-b border-white/5 pb-2 mb-2">
            <span className="text-slate-500 text-[10px] font-bold tracking-widest uppercase">System Forensics Logging Console</span>
            <span className="text-slate-500 text-[10px]">64-BIT VM SEC_CORE</span>
          </div>
          <div className="space-y-1.5 max-h-[150px] overflow-y-auto">
            {aiLogs.length === 0 ? (
              <span className="text-slate-600 block">Console idle. Awaiting simulation execute trigger...</span>
            ) : (
              aiLogs.map((log, i) => (
                <div key={i} className="flex gap-2 leading-relaxed">
                  <span className="text-slate-500">[{i+1}]</span>
                  <span className={log.includes("completed") || log.includes("successfully") ? "text-emerald-400" : log.includes("Error") ? "text-rose-400" : "text-slate-300"}>
                    {log}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
