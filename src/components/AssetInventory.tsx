import React, { useState, useEffect } from "react";
import { 
  Server, Shield, Plus, RefreshCw, Layers, ShieldCheck, 
  HelpCircle, User, Globe, AlertTriangle, Cloud, HardDrive, Laptop
} from "lucide-react";
import { motion } from "motion/react";
import { Asset, SeverityLevel } from "../types";

interface AssetInventoryProps {
  token: string;
}

export default function AssetInventory({ token }: AssetInventoryProps) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeFilterTab, setActiveFilterTab] = useState<"All" | "Server" | "Endpoint" | "Cloud">("All");

  // Add Asset Form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [name, setName] = useState("");
  const [type, setType] = useState<"Server" | "Endpoint" | "Cloud">("Server");
  const [ipAddress, setIpAddress] = useState("");
  const [os, setOs] = useState("");
  const [criticality, setCriticality] = useState<SeverityLevel>("High");
  const [owner, setOwner] = useState("");
  const [cloudProvider, setCloudProvider] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const fetchAssets = async () => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/assets", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setAssets(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, [token]);

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !ipAddress || !os) {
      setErrorMsg("Please fill out all required parameters.");
      return;
    }

    setIsSubmitting(true);
    setErrorMsg("");

    try {
      const res = await fetch("/api/assets", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          name,
          type,
          ipAddress,
          os,
          criticality,
          owner,
          cloudProvider: type === "Cloud" ? cloudProvider || "AWS" : undefined
        })
      });

      if (res.ok) {
        await fetchAssets();
        // Reset form
        setName("");
        setIpAddress("");
        setOs("");
        setOwner("");
        setCloudProvider("");
        setShowAddForm(false);
      } else {
        const errData = await res.json();
        setErrorMsg(errData.error || "Failed to create asset.");
      }
    } catch (err) {
      setErrorMsg("Network failure.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUpdateStatus = async (assetId: string, currentStatus: string) => {
    const nextStatus = currentStatus === "Online" ? "Offline" : "Online";
    try {
      const res = await fetch(`/api/assets/${assetId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ status: nextStatus })
      });
      if (res.ok) {
        setAssets(prev => prev.map(a => a.id === assetId ? { ...a, status: nextStatus as any } : a));
      }
    } catch (err) {
      console.error(err);
    }
  };

  const filteredAssets = assets.filter(a => activeFilterTab === "All" || a.type === activeFilterTab);

  return (
    <div className="space-y-6" id="assets-telemetry">
      {/* Upper Metrics Dashboard */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-[#0D0E12] border border-white/5 space-y-1.5">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">TOTAL INVENTORY</span>
          <div className="flex items-center gap-2.5">
            <Layers className="text-[#00E5FF]" size={20} />
            <span className="text-2xl font-bold font-mono text-white">{assets.length}</span>
          </div>
          <p className="text-[10px] text-slate-500">Active managed endpoints and clouds</p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0D0E12] border border-white/5 space-y-1.5">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">SERVERS</span>
          <div className="flex items-center gap-2.5">
            <HardDrive className="text-[#00E676]" size={20} />
            <span className="text-2xl font-bold font-mono text-white">
              {assets.filter(a => a.type === "Server").length}
            </span>
          </div>
          <p className="text-[10px] text-slate-500">Domain, database, and proxies</p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0D0E12] border border-white/5 space-y-1.5">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">USER ENDPOINTS</span>
          <div className="flex items-center gap-2.5">
            <Laptop className="text-amber-400" size={20} />
            <span className="text-2xl font-bold font-mono text-white">
              {assets.filter(a => a.type === "Endpoint").length}
            </span>
          </div>
          <p className="text-[10px] text-slate-500">Workstations, laptops and remote nodes</p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0D0E12] border border-white/5 space-y-1.5">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">CLOUD HOSTS</span>
          <div className="flex items-center gap-2.5">
            <Cloud className="text-pink-500" size={20} />
            <span className="text-2xl font-bold font-mono text-white">
              {assets.filter(a => a.type === "Cloud").length}
            </span>
          </div>
          <p className="text-[10px] text-slate-500">AWS clusters, GCP and storage containers</p>
        </div>
      </div>

      {/* Asset Controls Toolbar */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        {/* Type Filter Buttons */}
        <div className="flex bg-[#050507] p-1 rounded-xl border border-white/5">
          {(["All", "Server", "Endpoint", "Cloud"] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveFilterTab(tab)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-lg cursor-pointer transition-all ${
                activeFilterTab === tab
                  ? "bg-white/5 text-[#00E5FF] font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {tab.toUpperCase()}S
            </button>
          ))}
        </div>

        {/* Register Asset Toggle */}
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="px-4 py-2 bg-[#00E5FF]/10 text-[#00E5FF] hover:bg-[#00E5FF]/20 border border-[#00E5FF]/20 text-xs font-bold font-mono rounded-xl flex items-center gap-2 cursor-pointer shadow-[0_0_10px_rgba(0,229,255,0.1)] transition-all"
        >
          <Plus size={14} />
          DECLARE SECURITY ASSET
        </button>
      </div>

      {/* Asset Creation Form Overlay / Section */}
      {showAddForm && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          className="p-6 bg-[#0D0E12] border border-white/5 rounded-2xl space-y-4"
        >
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <ShieldCheck className="text-[#00E5FF]" size={16} />
            Asset Declaration Form
          </h3>

          <form onSubmit={handleCreateAsset} className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-1">
              <label className="text-[10px] font-mono text-slate-400 block uppercase">Asset Name *</label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Finance-Database-Prod"
                className="w-full px-3 py-2 bg-[#050507] border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/50"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-mono text-slate-400 block uppercase">Infrastructure Type</label>
              <select
                value={type}
                onChange={e => setType(e.target.value as any)}
                className="w-full px-3 py-2 bg-[#050507] border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/50"
              >
                <option value="Server">Server</option>
                <option value="Endpoint">User Endpoint</option>
                <option value="Cloud">Cloud Container / Instance</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-mono text-slate-400 block uppercase">IP / DNS Address *</label>
              <input
                type="text"
                value={ipAddress}
                onChange={e => setIpAddress(e.target.value)}
                placeholder="e.g. 10.100.12.80"
                className="w-full px-3 py-2 bg-[#050507] border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/50"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-mono text-slate-400 block uppercase">Operating System / Platform *</label>
              <input
                type="text"
                value={os}
                onChange={e => setOs(e.target.value)}
                placeholder="e.g. RedHat Linux 9 / AWS IAM"
                className="w-full px-3 py-2 bg-[#050507] border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/50"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-mono text-slate-400 block uppercase">Criticality Tier</label>
              <select
                value={criticality}
                onChange={e => setCriticality(e.target.value as any)}
                className="w-full px-3 py-2 bg-[#050507] border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/50"
              >
                <option value="Critical">Critical (DC, Prod Databases)</option>
                <option value="High">High (Public Web Server, Jenkins)</option>
                <option value="Medium">Medium (Developer Workstation)</option>
                <option value="Low">Low (Viewer/Guest Nodes)</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-mono text-slate-400 block uppercase">Administrative Owner Email</label>
              <input
                type="email"
                value={owner}
                onChange={e => setOwner(e.target.value)}
                placeholder="e.g. admin@secassist.ai"
                className="w-full px-3 py-2 bg-[#050507] border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/50"
              />
            </div>

            {type === "Cloud" && (
              <div className="space-y-1 col-span-3">
                <label className="text-[10px] font-mono text-slate-400 block uppercase">Cloud Provider Network</label>
                <input
                  type="text"
                  value={cloudProvider}
                  onChange={e => setCloudProvider(e.target.value)}
                  placeholder="e.g. AWS (Oregon Subnet Alpha) / Google Cloud Platform"
                  className="w-full px-3 py-2 bg-[#050507] border border-white/10 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-[#00E5FF]/50"
                />
              </div>
            )}

            <div className="col-span-3 pt-3 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="px-4 py-2 bg-white/5 hover:bg-white/10 text-slate-400 text-xs font-semibold rounded-xl cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-5 py-2 bg-[#00E5FF] hover:bg-[#00B8D4] text-black text-xs font-bold rounded-xl cursor-pointer"
              >
                {isSubmitting ? "Registering..." : "Add to Inventory"}
              </button>
            </div>

            {errorMsg && <p className="col-span-3 text-red-400 text-xs font-mono">{errorMsg}</p>}
          </form>
        </motion.div>
      )}

      {/* Asset Inventory Table Display */}
      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-t-[#00E5FF] border-white/10 rounded-full animate-spin" />
        </div>
      ) : (
        <div className="bg-[#0D0E12] border border-white/5 rounded-2xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/5 bg-[#050507] text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                  <th className="py-3.5 px-4 font-semibold">ASSET ID</th>
                  <th className="py-3.5 px-4 font-semibold">NAME & TYPE</th>
                  <th className="py-3.5 px-4 font-semibold">IP ADDRESS</th>
                  <th className="py-3.5 px-4 font-semibold">PLATFORM / OS</th>
                  <th className="py-3.5 px-4 font-semibold">CRITICALITY</th>
                  <th className="py-3.5 px-4 font-semibold">ACTIVE ALERTS</th>
                  <th className="py-3.5 px-4 font-semibold">STATUS</th>
                  <th className="py-3.5 px-4 font-semibold text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-xs">
                {filteredAssets.map(asset => (
                  <tr key={asset.id} className="hover:bg-white/[0.01] transition-all">
                    {/* ASSET ID */}
                    <td className="py-4 px-4 font-mono text-slate-500 font-semibold">{asset.id}</td>

                    {/* NAME & TYPE */}
                    <td className="py-4 px-4 font-semibold text-white">
                      <div className="flex items-center gap-2">
                        {asset.type === "Server" ? <Server className="text-[#00E676]" size={14} /> :
                         asset.type === "Endpoint" ? <Laptop className="text-amber-400" size={14} /> :
                         <Cloud className="text-pink-400" size={14} />}
                        <div>
                          <span>{asset.name}</span>
                          {asset.cloudProvider && (
                            <span className="block text-[9px] font-mono text-pink-500">{asset.cloudProvider} Instance</span>
                          )}
                        </div>
                      </div>
                    </td>

                    {/* IP ADDRESS */}
                    <td className="py-4 px-4 font-mono text-slate-300">{asset.ipAddress}</td>

                    {/* PLATFORM / OS */}
                    <td className="py-4 px-4 text-slate-400 font-mono">{asset.os}</td>

                    {/* CRITICALITY */}
                    <td className="py-4 px-4">
                      <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold font-mono ${
                        asset.criticality === "Critical" ? "bg-red-500/10 text-red-400 border border-red-500/20" :
                        asset.criticality === "High" ? "bg-orange-500/10 text-orange-400 border border-orange-500/20" :
                        asset.criticality === "Medium" ? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20" :
                        "bg-green-500/10 text-green-400 border border-green-500/20"
                      }`}>
                        {asset.criticality}
                      </span>
                    </td>

                    {/* ACTIVE ALERTS */}
                    <td className="py-4 px-4 font-mono text-center">
                      {asset.activeAlertsCount > 0 ? (
                        <span className="px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 font-bold border border-red-500/30 animate-pulse">
                          {asset.activeAlertsCount} Alert(s)
                        </span>
                      ) : (
                        <span className="text-slate-500 font-mono">0</span>
                      )}
                    </td>

                    {/* STATUS */}
                    <td className="py-4 px-4 font-mono">
                      <span className={`flex items-center gap-1.5 ${
                        asset.status === "Online" ? "text-[#00E676]" :
                        asset.status === "Offline" ? "text-slate-500" : "text-amber-400"
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${
                          asset.status === "Online" ? "bg-[#00E676]" :
                          asset.status === "Offline" ? "bg-slate-500" : "bg-amber-400 animate-ping"
                        }`} />
                        {asset.status}
                      </span>
                    </td>

                    {/* ACTION */}
                    <td className="py-4 px-4 text-right">
                      <button
                        onClick={() => handleUpdateStatus(asset.id, asset.status)}
                        className="text-[10px] px-2 py-1 bg-white/5 hover:bg-white/10 rounded-md font-mono text-slate-300 border border-white/10 cursor-pointer"
                      >
                        Toggle Status
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
