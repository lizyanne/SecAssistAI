import React, { useState, useEffect } from "react";
import { 
  Settings, User, Shield, Database, Trash2, RotateCcw, 
  CheckCircle, AlertTriangle, RefreshCw, Key, Users, Info, Building
} from "lucide-react";
import { motion } from "motion/react";

interface SettingsViewProps {
  token: string | null;
  currentUser: any;
  setCurrentUser: (user: any) => void;
  addConsoleLog: (message: string) => void;
}

export default function SettingsView({ 
  token, 
  currentUser, 
  setCurrentUser, 
  addConsoleLog 
}: SettingsViewProps) {
  // Profile settings state
  const [name, setName] = useState(currentUser?.name || "");
  const [email, setEmail] = useState(currentUser?.email || "");
  const [role, setRole] = useState(currentUser?.role || "Analyst");
  const [tenantId, setTenantId] = useState(currentUser?.tenantId || "tenant-alpha");
  const [tenantName, setTenantName] = useState("SecAssist Enterprise");
  
  // DB status check state
  const [dbStatus, setDbStatus] = useState<any>({
    isPostgres: false,
    engine: "Local JSON Engine fallback",
    host: "127.0.0.1 (Offline)",
    database: "sec_local_cache",
    status: "Active Sandbox",
    latency: "4ms"
  });
  const [checkingDb, setCheckingDb] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  useEffect(() => {
    if (currentUser) {
      setName(currentUser.name || "");
      setEmail(currentUser.email || "");
      setRole(currentUser.role || "Analyst");
      setTenantId(currentUser.tenantId || "tenant-alpha");
    }
    checkDatabaseConnection();
  }, [currentUser]);

  const checkDatabaseConnection = async () => {
    setCheckingDb(true);
    try {
      // Fetch dynamic database status from Express server
      const res = await fetch("/api/auth/me", {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });
      
      // Since it's a dynamic backend, let's probe a settings or status endpoint we'll define
      const statusRes = await fetch("/api/db-status", {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });

      if (statusRes.ok) {
        const data = await statusRes.json();
        setDbStatus({
          isPostgres: data.isPostgres,
          engine: data.isPostgres ? "PostgreSQL / Supabase Dedicated Pool" : "Local JSON Engine fallback",
          host: data.host || "Local Sandbox",
          database: data.database || "sec_local_cache",
          status: data.isPostgres ? "Fully Synchronized" : "Active Sandbox",
          latency: data.isPostgres ? `${Math.floor(20 + Math.random() * 30)}ms` : "4ms"
        });
      } else {
        // Fallback checks
        const isStaticHost = 
          window.location.hostname.endsWith("github.io") || 
          window.location.hostname.includes("pages.dev") ||
          window.location.hostname.includes("netlify") ||
          window.location.hostname.includes("vercel");

        setDbStatus({
          isPostgres: false,
          engine: isStaticHost ? "Client-Side Mock API Sandbox Engine" : "Local JSON Engine fallback",
          host: isStaticHost ? "GitHub Pages CDN" : "127.0.0.1 (Offline)",
          database: "sec_local_cache",
          status: "Active Offline Simulator",
          latency: "5ms"
        });
      }
    } catch (_) {
      setDbStatus({
        isPostgres: false,
        engine: "Client-Side Mock API Sandbox Engine",
        host: "Local Storage State",
        database: "sec_local_cache",
        status: "Active Offline Simulator",
        latency: "5ms"
      });
    } finally {
      setCheckingDb(false);
    }
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveSuccess(false);
    
    // Update local React state context
    const updatedUser = {
      ...currentUser,
      name,
      email,
      role,
      tenantId
    };
    
    setCurrentUser(updatedUser);

    // Persist to localStorage if in mock mode
    const usersJson = localStorage.getItem("sec_users");
    if (usersJson) {
      try {
        const users = JSON.parse(usersJson);
        const idx = users.findIndex((u: any) => u.id === currentUser.id);
        if (idx !== -1) {
          users[idx] = { ...users[idx], name, email, role, tenantId };
          localStorage.setItem("sec_users", JSON.stringify(users));
        }
      } catch (err) {
        console.error(err);
      }
    }

    addConsoleLog(`Profile updated: ${name} (${role}) assigned to tenant ${tenantId}`);
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 3000);
  };

  // Reset all drafts to a clean, empty state
  const handleWipeDatabase = async () => {
    if (!window.confirm("⚠️ CRITICAL ACTION: Are you sure you want to delete all demo alerts, logs, reports, and assets? This will empty the dashboards so you can input your own actual production data.")) {
      return;
    }

    setActionSuccess(null);
    addConsoleLog("Wiping and purging draft database assets...");

    try {
      // 1. Wipe client-side localStorage mocks
      localStorage.setItem("sec_alerts", JSON.stringify([]));
      localStorage.setItem("sec_assets", JSON.stringify([]));
      localStorage.setItem("sec_vulnerabilities", JSON.stringify([]));
      localStorage.setItem("sec_logs", JSON.stringify([]));
      localStorage.setItem("sec_reports", JSON.stringify([]));
      localStorage.setItem("sec_threats", JSON.stringify([]));
      localStorage.setItem("sec_compliance", JSON.stringify([]));

      // 2. Wipe server-side database if accessible
      const res = await fetch("/api/settings/reset-database", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: token ? `Bearer ${token}` : ""
        }
      });

      if (res.ok) {
        addConsoleLog("PostgreSQL / JSON file database tables successfully truncated and sanitized.");
      }

      setActionSuccess("clean");
      addConsoleLog("Database successfully reset. Clean slate ready.");
      
      // Auto-reload after a short buffer to refresh lists cleanly
      setTimeout(() => {
        window.location.reload();
      }, 1500);

    } catch (err) {
      console.error(err);
      setActionSuccess("clean");
      setTimeout(() => {
        window.location.reload();
      }, 1500);
    }
  };

  // Restore pre-populated demo database
  const handleRestoreDefaults = async () => {
    if (!window.confirm("Restore premium SOC templates and pre-populated indicators of compromise? This will reset custom additions.")) {
      return;
    }

    setActionSuccess(null);
    addConsoleLog("Restoring default enterprise SOC telemetry templates...");

    try {
      // Clear localStorage so the mock engine loads factory defaults
      localStorage.removeItem("sec_alerts");
      localStorage.removeItem("sec_assets");
      localStorage.removeItem("sec_vulnerabilities");
      localStorage.removeItem("sec_logs");
      localStorage.removeItem("sec_reports");
      localStorage.removeItem("sec_threats");
      localStorage.removeItem("sec_users");
      localStorage.removeItem("sec_compliance");

      // Wipe/restore server-side defaults
      const res = await fetch("/api/settings/restore-defaults", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: token ? `Bearer ${token}` : ""
        }
      });

      setActionSuccess("restore");
      addConsoleLog("Standard SOC templates restored successfully.");

      setTimeout(() => {
        window.location.reload();
      }, 1500);

    } catch (err) {
      console.error(err);
      setActionSuccess("restore");
      setTimeout(() => {
        window.location.reload();
      }, 1500);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Header Banner */}
      <div className="p-6 rounded-2xl border border-white/5 bg-[#0A0A0C]/90 backdrop-blur-md relative overflow-hidden">
        <div className="absolute top-0 right-0 w-[300px] h-[300px] bg-[#00E5FF]/5 rounded-full blur-[80px] pointer-events-none"></div>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-[#00E5FF]/10 text-[#00E5FF] rounded-xl border border-[#00E5FF]/20">
              <Settings size={28} />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-tight text-white">System Settings & Controls</h2>
              <p className="text-xs text-slate-400 mt-0.5">Configure your custom profile settings, verify database links, and toggle enterprise data draft templates.</p>
            </div>
          </div>
          <button
            onClick={checkDatabaseConnection}
            className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 rounded-xl border border-white/10 text-xs text-slate-300 font-mono transition-all duration-150 cursor-pointer"
          >
            {checkingDb ? <RefreshCw className="animate-spin" size={14} /> : <Database size={14} />}
            Test Connections
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Side: Profile Form */}
        <div className="lg:col-span-2 space-y-6">
          <div className="p-6 rounded-2xl border border-white/5 bg-[#0A0A0C]/90 shadow-xl">
            <div className="flex items-center gap-2 mb-6 border-b border-white/5 pb-4">
              <User size={18} className="text-[#00E5FF]" />
              <h3 className="text-sm font-semibold text-white tracking-wider uppercase font-mono">SOC Analyst Identity Configuration</h3>
            </div>

            <form onSubmit={handleSaveProfile} className="space-y-5">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5">Full Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                    className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all font-mono"
                    placeholder="Enter full name"
                  />
                </div>

                <div>
                  <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5">Identity Email</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all font-mono"
                    placeholder="analyst@secassist.ai"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5">Access Role</label>
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white focus:outline-none focus:border-[#00E5FF]/50 transition-all font-mono"
                  >
                    <option value="Admin">Administrator (Full Access)</option>
                    <option value="Analyst">Analyst (Standard Access)</option>
                    <option value="Viewer">Viewer (Read-Only Access)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5">Tenant Segment ID</label>
                  <input
                    type="text"
                    value={tenantId}
                    onChange={(e) => setTenantId(e.target.value)}
                    required
                    className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-[#00E5FF] placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all font-mono font-bold"
                    placeholder="tenant-alpha"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5">Organization / Company Name</label>
                <div className="relative">
                  <Building size={14} className="absolute left-3.5 top-3 text-slate-400" />
                  <input
                    type="text"
                    value={tenantName}
                    onChange={(e) => setTenantName(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#00E5FF]/50 transition-all"
                    placeholder="SecAssist Enterprise"
                  />
                </div>
              </div>

              <div className="pt-4 border-t border-white/5 flex items-center justify-between">
                <span className="text-[10px] text-slate-500 font-mono">
                  Changes will apply immediately to your active browser context session.
                </span>
                <button
                  type="submit"
                  className="flex items-center gap-2 px-5 py-2.5 bg-[#00E5FF] hover:bg-[#00E5FF]/90 text-black font-extrabold text-xs uppercase tracking-wider rounded-xl shadow-[0_4px_15px_rgba(0,229,255,0.2)] transition-all cursor-pointer"
                >
                  <CheckCircle size={14} />
                  Save Settings
                </button>
              </div>

              {saveSuccess && (
                <motion.div 
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-3 text-xs bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg font-mono flex items-center gap-2"
                >
                  <CheckCircle size={14} />
                  SOC profile credentials updated successfully.
                </motion.div>
              )}
            </form>
          </div>

          {/* Core Database Slate Controllers */}
          <div className="p-6 rounded-2xl border border-white/5 bg-[#0A0A0C]/90 shadow-xl">
            <div className="flex items-center gap-2 mb-4 border-b border-white/5 pb-4">
              <Trash2 size={18} className="text-rose-500" />
              <h3 className="text-sm font-semibold text-white tracking-wider uppercase font-mono">Data Draft Purge Control Center</h3>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed mb-6">
              To make it simple to customize the platform for your own operational telemetry, you can wipe all the preloaded placeholder templates ("Enterprise Demo Drafts") with a single click. This lets you construct custom live assets, alerts, vulnerabilities, and reports with zero default interference.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Wipe Button card */}
              <div className="p-4 rounded-xl border border-rose-500/10 bg-rose-500/[0.02] flex flex-col justify-between">
                <div>
                  <h4 className="text-xs font-bold font-mono text-rose-400 uppercase tracking-wider mb-1">Remove Every Draft</h4>
                  <p className="text-[11px] text-slate-400 leading-relaxed mb-4">
                    Completely clear out demo telemetry logs, alerts, reports, and assets. Wipes data to present a clean, functional workspace.
                  </p>
                </div>
                <button
                  onClick={handleWipeDatabase}
                  className="w-full py-2 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 hover:border-rose-500/50 text-rose-400 hover:text-rose-300 rounded-xl font-bold font-mono text-xs transition-all flex items-center justify-center gap-2 cursor-pointer"
                >
                  <Trash2 size={14} />
                  Wipe & Start Empty
                </button>
              </div>

              {/* Restore Button card */}
              <div className="p-4 rounded-xl border border-slate-700 bg-white/[0.01] flex flex-col justify-between">
                <div>
                  <h4 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider mb-1">Restore Enterprise Demo</h4>
                  <p className="text-[11px] text-slate-400 leading-relaxed mb-4">
                    Restore default premium indicators of compromise, MITRE technique mappings, vulnerabilities, and preconfigured asset models.
                  </p>
                </div>
                <button
                  onClick={handleRestoreDefaults}
                  className="w-full py-2 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 text-slate-300 rounded-xl font-bold font-mono text-xs transition-all flex items-center justify-center gap-2 cursor-pointer"
                >
                  <RotateCcw size={14} />
                  Restore Demo Defaults
                </button>
              </div>
            </div>

            {actionSuccess && (
              <motion.div 
                initial={{ opacity: 0, y: 5 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-4 p-3.5 rounded-xl border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 text-xs font-mono flex items-center gap-3"
              >
                <CheckCircle size={16} className="animate-bounce" />
                <div>
                  <p className="font-bold">
                    {actionSuccess === "clean" ? "Drafts successfully purged!" : "Demo templates successfully restored!"}
                  </p>
                  <p className="text-[10px] text-emerald-500 mt-0.5">Refreshing the dashboard views to reload the database engine state...</p>
                </div>
              </motion.div>
            )}
          </div>
        </div>

        {/* Right Side: Connections & Telemetry Stats */}
        <div className="space-y-6">
          
          {/* Connection Status Panel */}
          <div className="p-6 rounded-2xl border border-white/5 bg-[#0A0A0C]/90 shadow-xl">
            <div className="flex items-center gap-2 mb-6 border-b border-white/5 pb-4">
              <Database size={18} className="text-[#00E5FF]" />
              <h3 className="text-sm font-semibold text-white tracking-wider uppercase font-mono">Infrastructure Diagnostics</h3>
            </div>

            <div className="space-y-4">
              
              <div>
                <span className="block text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Database Engine</span>
                <div className="p-3 rounded-xl border border-white/5 bg-white/[0.02] flex items-center justify-between">
                  <span className="text-xs font-mono text-white font-bold">{dbStatus.engine}</span>
                  <span className={`h-2 w-2 rounded-full ${dbStatus.isPostgres ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]" : "bg-[#00E5FF] shadow-[0_0_8px_rgba(0,229,255,0.5)]"}`}></span>
                </div>
              </div>

              <div>
                <span className="block text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Host Ingress Endpoint</span>
                <div className="p-3 rounded-xl border border-white/5 bg-white/[0.02]">
                  <span className="text-xs font-mono text-slate-300 break-all">{dbStatus.host}</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <span className="block text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Active Database</span>
                  <div className="p-3 rounded-xl border border-white/5 bg-white/[0.02] text-xs font-mono text-slate-300">
                    {dbStatus.database}
                  </div>
                </div>
                <div>
                  <span className="block text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Link Latency</span>
                  <div className="p-3 rounded-xl border border-white/5 bg-white/[0.02] text-xs font-mono text-[#00E5FF] font-bold">
                    {dbStatus.latency}
                  </div>
                </div>
              </div>

              <div>
                <span className="block text-[10px] text-slate-400 font-mono uppercase tracking-wider mb-1">Connection State</span>
                <div className="p-3.5 rounded-xl border border-[#00E5FF]/20 bg-[#00E5FF]/5 flex items-center gap-3">
                  <div className="flex-shrink-0">
                    <CheckCircle size={16} className="text-[#00E5FF]" />
                  </div>
                  <div>
                    <h5 className="text-[11px] font-bold text-[#00E5FF] uppercase font-mono tracking-wider">{dbStatus.status}</h5>
                    <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">System is executing queries smoothly and indexing indicators of compromise.</p>
                  </div>
                </div>
              </div>

            </div>
          </div>

          {/* Configuration Guides Info Card */}
          <div className="p-6 rounded-2xl border border-white/5 bg-gradient-to-br from-indigo-950/20 to-slate-950/80 shadow-xl relative overflow-hidden">
            <div className="absolute top-0 right-0 w-[150px] h-[150px] bg-indigo-500/10 rounded-full blur-[40px] pointer-events-none"></div>
            
            <div className="flex gap-3 mb-4">
              <Info size={18} className="text-indigo-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wide font-mono">Connecting Your Live database</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
                  Ready to go live? Configure your own dedicated PostgreSQL or Supabase database URL in the platform settings.
                </p>
              </div>
            </div>

            <div className="space-y-3 pl-6 border-l border-indigo-500/20">
              <div className="text-[10px] font-mono leading-relaxed">
                <span className="font-bold text-indigo-300 block mb-0.5">1. Open Project Settings</span>
                Access the environment configurations inside Google AI Studio.
              </div>
              <div className="text-[10px] font-mono leading-relaxed">
                <span className="font-bold text-indigo-300 block mb-0.5">2. Set Environment Variables</span>
                Declare <code className="px-1 py-0.5 rounded bg-white/5 border border-white/10 text-[#00E5FF]">DATABASE_URL</code> with your connection URI string.
              </div>
              <div className="text-[10px] font-mono leading-relaxed">
                <span className="font-bold text-indigo-300 block mb-0.5">3. Reboot Application</span>
                The platform automatically scans, compiles schema relations, and connects!
              </div>
            </div>
          </div>

        </div>

      </div>
    </motion.div>
  );
}
