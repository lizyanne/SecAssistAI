import React, { useState } from "react";
import { 
  Search, ShieldAlert, Cpu, Terminal, Clock, Server, 
  User, AlertTriangle, Link, Info, HelpCircle, CheckCircle, ArrowRight
} from "lucide-react";
import { motion } from "motion/react";
import { Asset, SecurityAlert } from "../types";

interface SearchResults {
  hosts: Asset[];
  users: any[];
  alerts: SecurityAlert[];
  timeline: {
    timestamp: string;
    type: string;
    title: string;
    description: string;
    severity: string;
  }[];
  correlation: {
    score: string;
    description: string;
  };
}

interface ThreatHuntingProps {
  token: string;
  onNavigateToAlerts?: (alertId: string) => void;
}

export default function ThreatHunting({ token, onNavigateToAlerts }: ThreatHuntingProps) {
  const [query, setQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [results, setResults] = useState<SearchResults | null>(null);
  const [selectedResultTab, setSelectedResultTab] = useState<"summary" | "timeline" | "hosts" | "users">("summary");

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setIsSearching(true);
    try {
      const response = await fetch(`/api/threat-hunting/search?query=${encodeURIComponent(query)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setResults(data);
        setSelectedResultTab("summary");
      }
    } catch (err) {
      console.error("Threat hunting failed:", err);
    } finally {
      setIsSearching(false);
    }
  };

  const handleQuickHunt = (ioc: string) => {
    setQuery(ioc);
    // Submit search instantly
    setIsSearching(true);
    fetch(`/api/threat-hunting/search?query=${encodeURIComponent(ioc)}`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => {
        setResults(data);
        setSelectedResultTab("summary");
      })
      .catch(err => console.error(err))
      .finally(() => setIsSearching(false));
  };

  return (
    <div className="space-y-6" id="threat-hunting-workbench">
      {/* Top Banner and Description */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-6 rounded-2xl bg-[#0D0E12] border border-white/5 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-40 bg-[#00E5FF]/5 rounded-full blur-[100px] pointer-events-none" />
        <div className="space-y-1 z-10">
          <h2 className="text-xl font-bold font-sans tracking-tight text-white flex items-center gap-2">
            <Terminal className="text-[#00E5FF]" size={20} />
            Threat Hunting Workbench
          </h2>
          <p className="text-xs text-slate-400 max-w-2xl">
            Audit indicators of compromise (IOCs), map suspicious internal hosts, query user accounts, and reconstruct multi-stage attack timelines. Powered by the SecAssist correlation engine.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 z-10">
          <button 
            onClick={() => handleQuickHunt("10.100.12.45")}
            className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 hover:border-[#00E5FF]/40 text-slate-300 font-mono text-[10px] cursor-pointer transition-all"
          >
            Hunt IP: 10.100.12.45
          </button>
          <button 
            onClick={() => handleQuickHunt("lockbit")}
            className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 hover:border-[#00E5FF]/40 text-slate-300 font-mono text-[10px] cursor-pointer transition-all"
          >
            Hunt Threat: LockBit
          </button>
          <button 
            onClick={() => handleQuickHunt("Administrator")}
            className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 hover:border-[#00E5FF]/40 text-slate-300 font-mono text-[10px] cursor-pointer transition-all"
          >
            Hunt User: Administrator
          </button>
        </div>
      </div>

      {/* Main Hunting Search Bar */}
      <div className="p-6 rounded-2xl bg-[#0D0E12] border border-white/5">
        <form onSubmit={handleSearch} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search IP address, CVE ID, host, account owner, ransomware keyword or file hash..."
              className="w-full pl-11 pr-4 py-3 bg-[#050507] border border-white/10 rounded-xl text-sm text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-[#00E5FF]/50 focus:shadow-[0_0_15px_rgba(0,229,255,0.05)] transition-all"
            />
          </div>
          <button
            type="submit"
            disabled={isSearching}
            className="px-6 bg-[#00E5FF] text-black hover:bg-[#00B8D4] disabled:opacity-50 transition-all text-sm font-semibold rounded-xl flex items-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(0,229,255,0.2)] hover:shadow-[0_0_20px_rgba(0,229,255,0.3)] font-mono"
          >
            {isSearching ? "Searching..." : "HUNT"}
          </button>
        </form>
      </div>

      {isSearching && (
        <div className="flex flex-col items-center justify-center py-20 space-y-3">
          <div className="w-10 h-10 border-2 border-t-[#00E5FF] border-white/10 rounded-full animate-spin" />
          <p className="text-xs text-slate-400 font-mono">Running cross-correlation query against telemetry stores...</p>
        </div>
      )}

      {/* Results Workspace */}
      {results && !isSearching && (
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-1 lg:grid-cols-4 gap-6"
        >
          {/* Correlation Score Widget & Sidebar */}
          <div className="lg:col-span-1 space-y-6">
            {/* Correlation Engine Box */}
            <div className="p-5 rounded-2xl bg-[#0D0E12] border border-white/5 space-y-4 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">CORRELATION RATIO</span>
                <span className="px-2 py-0.5 rounded-full text-[9px] bg-white/5 text-[#00E5FF] font-mono font-bold">SECASSIST AI</span>
              </div>

              <div className="flex flex-col items-center py-4 space-y-1 bg-[#050507] rounded-xl border border-white/5 relative">
                <span className="text-[10px] font-mono text-slate-400">CORRELATION SCORE</span>
                <span className={`text-3xl font-extrabold font-mono tracking-wider ${
                  results.correlation.score === "Critical" ? "text-red-500 shadow-red-500/20" :
                  results.correlation.score === "High" ? "text-orange-500 shadow-orange-500/20" :
                  results.correlation.score === "Medium" ? "text-yellow-500 shadow-yellow-500/20" : "text-green-500"
                }`}>
                  {results.correlation.score.toUpperCase()}
                </span>
                <div className="absolute top-2 right-2 flex h-2 w-2">
                  <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                    results.correlation.score === "Critical" ? "bg-red-500" :
                    results.correlation.score === "High" ? "bg-orange-500" : "bg-green-500"
                  }`}></span>
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${
                    results.correlation.score === "Critical" ? "bg-red-500" :
                    results.correlation.score === "High" ? "bg-orange-500" : "bg-green-500"
                  }`}></span>
                </div>
              </div>

              <p className="text-xs text-slate-300 font-mono leading-relaxed bg-[#050507]/40 p-3 rounded-lg border border-white/5">
                {results.correlation.description}
              </p>
            </div>

            {/* Quick Result Summaries */}
            <div className="p-4 rounded-2xl bg-[#0D0E12] border border-white/5 space-y-3">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block px-1">MATCH STATS</span>
              <div className="grid grid-cols-2 gap-2 text-center">
                <div className="p-2.5 bg-[#050507] rounded-xl border border-white/5">
                  <div className="text-base font-extrabold text-white font-mono">{results.hosts.length}</div>
                  <div className="text-[9px] text-slate-500">Hosts Matched</div>
                </div>
                <div className="p-2.5 bg-[#050507] rounded-xl border border-white/5">
                  <div className="text-base font-extrabold text-white font-mono">{results.users.length}</div>
                  <div className="text-[9px] text-slate-500">Users Matched</div>
                </div>
                <div className="p-2.5 bg-[#050507] rounded-xl border border-white/5">
                  <div className="text-base font-extrabold text-white font-mono">{results.alerts.length}</div>
                  <div className="text-[9px] text-slate-500">Alerts Linked</div>
                </div>
                <div className="p-2.5 bg-[#050507] rounded-xl border border-white/5">
                  <div className="text-base font-extrabold text-white font-mono">{results.timeline.length}</div>
                  <div className="text-[9px] text-slate-500">Events Mapped</div>
                </div>
              </div>
            </div>
          </div>

          {/* Results Tab View */}
          <div className="lg:col-span-3 space-y-4">
            <div className="flex border-b border-white/5 gap-2 pb-px">
              <button
                onClick={() => setSelectedResultTab("summary")}
                className={`px-4 py-2 text-xs font-semibold cursor-pointer border-b-2 transition-all ${
                  selectedResultTab === "summary"
                    ? "border-[#00E5FF] text-[#00E5FF]"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                HUNT SUMMARY
              </button>
              <button
                onClick={() => setSelectedResultTab("timeline")}
                className={`px-4 py-2 text-xs font-semibold cursor-pointer border-b-2 transition-all ${
                  selectedResultTab === "timeline"
                    ? "border-[#00E5FF] text-[#00E5FF]"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                TIMELINE RECONSTRUCTION ({results.timeline.length})
              </button>
              <button
                onClick={() => setSelectedResultTab("hosts")}
                className={`px-4 py-2 text-xs font-semibold cursor-pointer border-b-2 transition-all ${
                  selectedResultTab === "hosts"
                    ? "border-[#00E5FF] text-[#00E5FF]"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                MATCHED ASSETS ({results.hosts.length})
              </button>
              <button
                onClick={() => setSelectedResultTab("users")}
                className={`px-4 py-2 text-xs font-semibold cursor-pointer border-b-2 transition-all ${
                  selectedResultTab === "users"
                    ? "border-[#00E5FF] text-[#00E5FF]"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                MATCHED USERS ({results.users.length})
              </button>
            </div>

            {/* TAB CONTENT: HUNT SUMMARY */}
            {selectedResultTab === "summary" && (
              <div className="space-y-4">
                {results.alerts.length === 0 && results.hosts.length === 0 && results.users.length === 0 && (
                  <div className="p-8 bg-[#0D0E12] border border-white/5 rounded-2xl text-center space-y-2">
                    <Info className="text-slate-500 mx-auto" size={24} />
                    <p className="text-sm font-semibold text-slate-300">No Direct Database Alerts Triggered</p>
                    <p className="text-xs text-slate-500">Indicators did not match active threat registries. However, review forensic logs for structural patterns.</p>
                  </div>
                )}

                {/* Primary Alert Matches */}
                {results.alerts.length > 0 && (
                  <div className="space-y-3">
                    <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider">ACTIVE ALERTS CORRELATED</h3>
                    <div className="grid grid-cols-1 gap-3">
                      {results.alerts.map(al => (
                        <div key={al.id} className="p-4 bg-[#0D0E12] hover:bg-[#121319] border border-white/5 rounded-2xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 transition-all">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-0.5 rounded-md text-[9px] font-bold font-mono ${
                                al.severity === "Critical" ? "bg-red-500/10 text-red-400 border border-red-500/20" :
                                al.severity === "High" ? "bg-orange-500/10 text-orange-400 border border-orange-500/20" :
                                "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
                              }`}>
                                {al.severity}
                              </span>
                              <span className="text-xs font-semibold text-[#00E5FF] font-mono">{al.id}</span>
                              <span className="text-[10px] text-slate-500 font-mono">{new Date(al.timestamp).toLocaleString()}</span>
                            </div>
                            <h4 className="text-sm font-bold text-white leading-snug">{al.title}</h4>
                            <p className="text-xs text-slate-400 line-clamp-1">{al.description}</p>
                          </div>
                          <div className="flex items-center gap-3">
                            <div className="text-right">
                              <div className="text-[10px] text-slate-500 font-mono">SOURCE -&gt; DEST</div>
                              <div className="text-xs font-semibold text-slate-300 font-mono">{al.sourceIp} -&gt; {al.destIp}</div>
                            </div>
                            {onNavigateToAlerts && (
                              <button
                                onClick={() => onNavigateToAlerts(al.id)}
                                className="px-3 py-1.5 bg-white/5 hover:bg-white/10 rounded-xl text-xs text-[#00E5FF] border border-[#00E5FF]/20 flex items-center gap-1 cursor-pointer transition-all"
                              >
                                Review <ArrowRight size={12} />
                              </button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Search Diagnostics */}
                <div className="p-4 rounded-2xl bg-[#0D0E12]/40 border border-white/5 space-y-3">
                  <h4 className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
                    <ShieldAlert size={14} className="text-[#00E5FF]" />
                    Hunt Indicators Evaluated
                  </h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Correlation search parsed through tenant network configurations, firewalls, threat bulletins, vulnerability reports, and raw SSH/daemon console uploads. Correlation index highlights multi-tier tactics associated with the query.
                  </p>
                </div>
              </div>
            )}

            {/* TAB CONTENT: FORENSIC TIMELINE */}
            {selectedResultTab === "timeline" && (
              <div className="space-y-6 relative pl-6 before:absolute before:left-3 before:top-2 before:bottom-2 before:w-px before:bg-white/10">
                {results.timeline.length === 0 ? (
                  <div className="p-8 bg-[#0D0E12] border border-white/5 rounded-2xl text-center">
                    <p className="text-xs text-slate-500 font-mono">No chronological timeline mapping indicators matched the search query.</p>
                  </div>
                ) : (
                  results.timeline.map((item, idx) => (
                    <motion.div 
                      key={idx}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="relative space-y-1.5"
                    >
                      {/* Timeline Dot Indicator */}
                      <div className={`absolute -left-[23px] top-1.5 h-3 w-3 rounded-full border-2 bg-black ${
                        item.severity === "Critical" ? "border-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]" :
                        item.severity === "High" ? "border-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.5)]" :
                        "border-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.5)]"
                      }`} />

                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                          <Clock size={11} />
                          {new Date(item.timestamp).toLocaleString()}
                        </span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded-md font-mono bg-white/5 text-slate-400">
                          {item.type.toUpperCase()}
                        </span>
                      </div>

                      <div className="p-4 bg-[#0D0E12] border border-white/5 rounded-xl space-y-1 hover:border-white/10 transition-all">
                        <h4 className="text-sm font-bold text-white flex items-center justify-between">
                          {item.title}
                          <span className={`text-[10px] font-mono font-bold ${
                            item.severity === "Critical" ? "text-red-400" :
                            item.severity === "High" ? "text-orange-400" : "text-yellow-400"
                          }`}>
                            {item.severity} Risk
                          </span>
                        </h4>
                        <p className="text-xs text-slate-400 leading-relaxed font-mono">
                          {item.description}
                        </p>
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            )}

            {/* TAB CONTENT: MATCHED HOSTS */}
            {selectedResultTab === "hosts" && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {results.hosts.length === 0 ? (
                  <div className="col-span-2 p-8 bg-[#0D0E12] border border-white/5 rounded-2xl text-center text-slate-500 font-mono text-xs">
                    No active internal host assets correlated with the query.
                  </div>
                ) : (
                  results.hosts.map(host => (
                    <div key={host.id} className="p-4 bg-[#0D0E12] border border-white/5 rounded-xl flex items-start gap-3">
                      <div className="p-2.5 bg-white/5 rounded-xl border border-white/5 text-[#00E5FF]">
                        <Server size={18} />
                      </div>
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-white">{host.name}</span>
                          <span className={`px-2 py-0.5 rounded-full text-[8px] font-extrabold font-mono ${
                            host.criticality === "Critical" ? "bg-red-500/10 text-red-400" :
                            host.criticality === "High" ? "bg-orange-500/10 text-orange-400" : "bg-green-500/10 text-green-400"
                          }`}>
                            {host.criticality} Priority
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono">{host.os} • {host.ipAddress}</div>
                        <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1 border-t border-white/5">
                          <span>Owner: {host.owner}</span>
                          <span className="text-[#00E676]">● {host.status}</span>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* TAB CONTENT: MATCHED USERS */}
            {selectedResultTab === "users" && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {results.users.length === 0 ? (
                  <div className="col-span-2 p-8 bg-[#0D0E12] border border-white/5 rounded-2xl text-center text-slate-500 font-mono text-xs">
                    No directory user logs correlated with the query.
                  </div>
                ) : (
                  results.users.map(u => (
                    <div key={u.id} className="p-4 bg-[#0D0E12] border border-white/5 rounded-xl flex items-center gap-3">
                      <div className="p-2.5 bg-white/5 rounded-xl border border-white/5 text-[#00E5FF]">
                        <User size={18} />
                      </div>
                      <div className="space-y-0.5">
                        <h4 className="text-xs font-bold text-white">{u.name}</h4>
                        <div className="text-[10px] text-slate-400 font-mono">{u.email}</div>
                        <div className="text-[9px] font-mono bg-white/5 inline-block px-1.5 py-0.5 rounded text-[#00E5FF]">
                          Tenant Role: {u.role}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </motion.div>
      )}

      {/* Default Prompting Guidelines */}
      {!results && !isSearching && (
        <div className="p-8 bg-[#0D0E12] border border-white/5 rounded-2xl flex flex-col items-center justify-center text-center space-y-3">
          <Cpu className="text-slate-600 animate-pulse" size={32} />
          <h3 className="text-sm font-semibold text-slate-300">Ready to Hunt Indicators</h3>
          <p className="text-xs text-slate-500 max-w-lg leading-relaxed">
            Specify a suspicious system file, IP address range, credential username, or ransomware tag above to trace lateral movements and consolidate cross-correlation timelines.
          </p>
        </div>
      )}
    </div>
  );
}
