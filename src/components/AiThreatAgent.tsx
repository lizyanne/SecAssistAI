import React, { useState, useEffect } from "react";
import { 
  Bot, ShieldAlert, Cpu, Terminal, CheckSquare, Square, CheckCircle, 
  AlertTriangle, Play, FileText, Server, Network, User, ShieldCheck, HelpCircle
} from "lucide-react";
import { motion } from "motion/react";
import { SecurityAlert, AiInvestigation } from "../types";

interface AiThreatAgentProps {
  token: string;
  alerts: SecurityAlert[];
  onRefreshAlerts?: () => void;
}

export default function AiThreatAgent({ token, alerts, onRefreshAlerts }: AiThreatAgentProps) {
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [currentInvestigation, setCurrentInvestigation] = useState<AiInvestigation | null>(null);
  
  // Streaming log steps state for interactive cyber feeling
  const [streamingLogs, setStreamingLogs] = useState<string[]>([]);
  const [logIndex, setLogIndex] = useState(0);
  const [investigationData, setInvestigationData] = useState<any | null>(null);

  // Remediation checkbox state
  const [completedRemediations, setCompletedRemediations] = useState<Record<string, boolean>>({});

  useEffect(() => {
    // Select the first uninvestigated / open alert by default if available
    const openAlerts = alerts.filter(a => a.status === "Active" || a.status === "Investigating");
    if (openAlerts.length > 0 && !selectedAlertId) {
      setSelectedAlertId(openAlerts[0].id);
    } else if (alerts.length > 0 && !selectedAlertId) {
      setSelectedAlertId(alerts[0].id);
    }
  }, [alerts]);

  const triggerInvestigation = async () => {
    if (!selectedAlertId) return;

    setIsInvestigating(true);
    setStreamingLogs([]);
    setLogIndex(0);
    setCurrentInvestigation(null);
    setInvestigationData(null);
    setCompletedRemediations({});

    try {
      const res = await fetch("/api/ai-agent/investigate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ alertId: selectedAlertId })
      });

      if (res.ok) {
        const data = await res.json();
        setInvestigationData(data);
        
        // Start timed streaming of logs to mimic real-time analysis
        if (data.logs && data.logs.length > 0) {
          let currentLogIdx = 0;
          const interval = setInterval(() => {
            if (currentLogIdx < data.logs.length) {
              setStreamingLogs(prev => [...prev, data.logs[currentLogIdx]]);
              currentLogIdx++;
            } else {
              clearInterval(interval);
              setIsInvestigating(false);
              setCurrentInvestigation(data);
              if (onRefreshAlerts) onRefreshAlerts();
            }
          }, 900); // Speed of simulated execution steps
        } else {
          setIsInvestigating(false);
          setCurrentInvestigation(data);
          if (onRefreshAlerts) onRefreshAlerts();
        }
      } else {
        setIsInvestigating(false);
      }
    } catch (err) {
      console.error(err);
      setIsInvestigating(false);
    }
  };

  const getEvidenceIcon = (type: string) => {
    if (type === "process") return <Cpu className="text-[#00E5FF]" size={14} />;
    if (type === "network") return <Network className="text-pink-500" size={14} />;
    if (type === "user") return <User className="text-[#00E676]" size={14} />;
    return <FileText className="text-amber-400" size={14} />;
  };

  const toggleRemediation = (step: string) => {
    setCompletedRemediations(prev => ({
      ...prev,
      [step]: !prev[step]
    }));
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6" id="ai-threat-investigation-agent">
      {/* Sidebar: Deploy Agent HUD */}
      <div className="lg:col-span-1 bg-[#0D0E12] border border-white/5 rounded-2xl p-5 h-fit space-y-5">
        <div className="flex items-center gap-2 border-b border-white/5 pb-3">
          <Bot className="text-[#00E5FF] animate-pulse" size={20} />
          <h3 className="text-xs font-mono font-bold text-white uppercase">Autonomous Threat Agent</h3>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed font-mono">
          Deploy SecAssist Tier-3 AI Investigation Agent to trace lateral traversals, scrape system memory artifacts, verify hash signatures, and deliver instant playbooks.
        </p>

        {/* Alert Selector dropdown */}
        <div className="space-y-1.5">
          <label className="text-[10px] font-mono text-slate-400 block uppercase">Select Alert for Investigation</label>
          <select
            value={selectedAlertId}
            onChange={e => setSelectedAlertId(e.target.value)}
            disabled={isInvestigating}
            className="w-full px-3 py-2.5 bg-[#050507] border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/50"
          >
            <option value="">-- Choose Target Alert --</option>
            {alerts.map(al => (
              <option key={al.id} value={al.id}>
                [{al.id}] {al.title} ({al.severity})
              </option>
            ))}
          </select>
        </div>

        {/* Action Deploy Button */}
        <button
          onClick={triggerInvestigation}
          disabled={isInvestigating || !selectedAlertId}
          className="w-full py-3 bg-[#00E5FF] text-black hover:bg-[#00B8D4] disabled:opacity-40 transition-all text-xs font-extrabold font-mono rounded-xl flex items-center justify-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(0,229,255,0.2)] hover:shadow-[0_0_20px_rgba(0,229,255,0.3)]"
        >
          {isInvestigating ? "AGENT EXECUTING..." : "DEPLOY FORENSIC AGENT"}
          <Play size={12} className="fill-black" />
        </button>

        {/* Live streaming/progress console logs block */}
        {(isInvestigating || streamingLogs.length > 0) && (
          <div className="bg-black/80 rounded-xl p-4 border border-white/15 h-64 flex flex-col justify-between">
            <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-2">
              <span className="text-[9px] font-mono text-slate-400 uppercase flex items-center gap-1.5">
                <Terminal size={12} className="text-[#00E5FF]" />
                FORENSIC ACTIVITY CONSOLE
              </span>
              <span className="h-1.5 w-1.5 rounded-full bg-[#00E5FF] animate-ping" />
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 font-mono text-[10px] text-slate-300">
              {streamingLogs.map((log, idx) => (
                <div key={idx} className="flex gap-2">
                  <span className="text-[#00E5FF] shrink-0">~</span>
                  <span className="leading-normal">{log}</span>
                </div>
              ))}
              {isInvestigating && (
                <div className="flex gap-2 items-center text-slate-500 italic">
                  <span className="animate-pulse">_</span>
                  <span>Executing next forensic probe...</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Main Panel: Investigation Dossier */}
      <div className="lg:col-span-2 h-[650px] overflow-y-auto bg-[#0D0E12] border border-white/5 rounded-2xl flex flex-col">
        {isInvestigating && !currentInvestigation ? (
          <div className="flex-1 flex flex-col items-center justify-center space-y-3">
            <div className="w-12 h-12 border-4 border-t-[#00E5FF] border-white/10 rounded-full animate-spin" />
            <p className="text-xs font-mono text-slate-400">Forensics in progress. Acquiring server execution memory dumps...</p>
          </div>
        ) : currentInvestigation ? (
          <div className="p-6 space-y-6">
            {/* Dossier Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/5 pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Bot className="text-[#00E5FF]" size={16} />
                  <span className="text-xs font-mono font-bold text-slate-400 uppercase">AI FORENSICS REPORT: {currentInvestigation.id}</span>
                </div>
                <h2 className="text-base font-extrabold text-white leading-snug">
                  Investigation Docket: {currentInvestigation.alertTitle}
                </h2>
                <div className="text-[10px] text-slate-500 font-mono">
                  Triggered Alert Reference: {currentInvestigation.alertId} • Completed {new Date(currentInvestigation.timestamp).toLocaleTimeString()}
                </div>
              </div>

              <span className="px-2.5 py-1 rounded-full bg-[#00E676]/10 text-[#00E676] border border-[#00E676]/20 text-[10px] font-bold font-mono">
                INVESTIGATED
              </span>
            </div>

            {/* Evidence catalog list */}
            <div className="space-y-3">
              <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider">COLLECTED THREAT EVIDENCE</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {currentInvestigation.evidence.map((ev, idx) => (
                  <div key={idx} className="p-3 bg-[#050507] border border-white/5 rounded-xl space-y-2 hover:border-white/10 transition-all flex flex-col justify-between">
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] font-mono text-slate-500 uppercase">{ev.type}</span>
                        <span className={`text-[8px] font-extrabold font-mono px-1.5 py-0.2 rounded ${
                          ev.severity === "Malicious" ? "bg-red-500/15 text-red-400" :
                          ev.severity === "Suspicious" ? "bg-amber-500/15 text-amber-400" : "bg-green-500/15 text-green-400"
                        }`}>
                          {ev.severity}
                        </span>
                      </div>
                      <h4 className="text-xs font-bold text-slate-200 line-clamp-1 flex items-center gap-1.5">
                        {getEvidenceIcon(ev.type)}
                        {ev.name}
                      </h4>
                      <p className="text-[10px] text-slate-400 leading-normal font-mono">
                        {ev.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Cyber Findings bullets */}
            <div className="space-y-3">
              <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider">SOC FORENSIC FINDINGS</h3>
              <div className="p-4 bg-[#050507] border border-white/5 rounded-xl space-y-3">
                {currentInvestigation.findings.map((finding, idx) => (
                  <div key={idx} className="flex gap-2.5 text-xs text-slate-300 font-mono leading-relaxed">
                    <span className="text-[#00E5FF] font-bold">0{idx + 1}.</span>
                    <p>{finding}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Actionable remediations with checkboxes */}
            <div className="space-y-3">
              <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider">TARGETED REMEDIATION WORKFLOW</h3>
              <div className="p-4 bg-[#050507] border border-white/5 rounded-xl divide-y divide-white/5 space-y-3">
                {currentInvestigation.reremediationSteps ? (
                  currentInvestigation.reremediationSteps.map((step: string, idx: number) => {
                    const isChecked = !!completedRemediations[step];
                    return (
                      <div key={idx} className="flex items-start gap-3 pt-3 first:pt-0">
                        <button
                          onClick={() => toggleRemediation(step)}
                          className="mt-0.5 text-slate-400 hover:text-white transition-colors cursor-pointer shrink-0"
                        >
                          {isChecked ? (
                            <CheckSquare size={16} className="text-[#00E676]" />
                          ) : (
                            <Square size={16} />
                          )}
                        </button>
                        <span className={`text-xs font-mono leading-relaxed ${
                          isChecked ? "line-through text-slate-500" : "text-slate-300"
                        }`}>
                          {step}
                        </span>
                      </div>
                    );
                  })
                ) : (
                  currentInvestigation.remediationSteps.map((step, idx) => {
                    const isChecked = !!completedRemediations[step];
                    return (
                      <div key={idx} className="flex items-start gap-3 pt-3 first:pt-0">
                        <button
                          onClick={() => toggleRemediation(step)}
                          className="mt-0.5 text-slate-400 hover:text-white transition-colors cursor-pointer shrink-0"
                        >
                          {isChecked ? (
                            <CheckSquare size={16} className="text-[#00E676]" />
                          ) : (
                            <Square size={16} />
                          )}
                        </button>
                        <span className={`text-xs font-mono leading-relaxed ${
                          isChecked ? "line-through text-slate-500" : "text-slate-300"
                        }`}>
                          {step}
                        </span>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center space-y-2 text-slate-500 font-mono text-xs">
            <Cpu size={24} className="text-slate-600 animate-pulse" />
            <p>Select any active alert on the left sidebar to deploy the AI Threat Agent.</p>
          </div>
        )}
      </div>
    </div>
  );
}
