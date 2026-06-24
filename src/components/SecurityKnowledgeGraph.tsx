import React, { useState, useEffect, useRef } from "react";
import { 
  Network, HelpCircle, User, Server, AlertTriangle, 
  FileText, Shield, Info, Layers, RefreshCw, ZoomIn, ZoomOut
} from "lucide-react";
import { motion } from "motion/react";
import { GraphNode, GraphLink } from "../types";

interface SecurityKnowledgeGraphProps {
  token: string;
}

export default function SecurityKnowledgeGraph({ token }: SecurityKnowledgeGraphProps) {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [links, setLinks] = useState<GraphLink[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState<string>("All");

  const stageRef = useRef<SVGSVGElement>(null);

  const fetchGraphData = async () => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/knowledge-graph", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        
        // Let's compute stable coordinate layouts on the client side based on entity types.
        // Group nodes by type to compute elegant structured distributions (bento columns)
        const typeColumns: Record<string, number> = {
          "user": 100,
          "device": 280,
          "alert": 460,
          "threat": 640,
          "incident": 820
        };

        const counts: Record<string, number> = {};
        const positionedNodes = data.nodes.map((node: any) => {
          const type = node.type;
          counts[type] = (counts[type] || 0) + 1;
          
          const x = typeColumns[type] || 100;
          // Distribute Y values down the column based on index
          const y = 80 + (counts[type] * 90);

          return { ...node, x, y };
        });

        setNodes(positionedNodes);
        setLinks(data.links);
        
        // Select first alert node or general node if available
        if (positionedNodes.length > 0) {
          const firstAlert = positionedNodes.find((n: any) => n.type === "alert") || positionedNodes[0];
          setSelectedNode(firstAlert);
        }
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchGraphData();
  }, [token]);

  // Determine if a link or node is highlighted
  const isLinkConnected = (link: GraphLink, nodeId: string) => {
    return link.source === nodeId || link.target === nodeId;
  };

  const getConnectedNodeIds = (nodeId: string) => {
    const connected = new Set<string>();
    connected.add(nodeId);
    links.forEach(l => {
      if (l.source === nodeId) connected.add(l.target);
      if (l.target === nodeId) connected.add(l.source);
    });
    return connected;
  };

  const activeHighlightedNodeIds = selectedNode ? getConnectedNodeIds(selectedNode.id) : new Set<string>();

  const getNodeColor = (type: string, severity?: string) => {
    if (type === "user") return "#00E5FF"; // Cyan
    if (type === "device") return "#00E676"; // Green
    if (type === "threat") return "#E040FB"; // Purple
    if (type === "incident") return "#FFD600"; // Yellow
    // Alert node color depending on severity
    if (severity === "Critical") return "#FF3D00"; // Red
    if (severity === "High") return "#FF9100"; // Orange
    return "#EA7B00";
  };

  const getNodeIcon = (type: string) => {
    if (type === "user") return <User size={13} />;
    if (type === "device") return <Server size={13} />;
    if (type === "alert") return <AlertTriangle size={13} />;
    if (type === "incident") return <FileText size={13} />;
    return <Shield size={13} />;
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6" id="security-knowledge-graph">
      {/* Dynamic Graph Canvas Frame */}
      <div className="lg:col-span-3 bg-[#0D0E12] border border-white/5 rounded-2xl p-4 flex flex-col h-[650px] relative overflow-hidden">
        
        {/* Graph Header HUD controls */}
        <div className="flex items-center justify-between border-b border-white/5 pb-3 bg-[#0A0A0C]/40 px-2 rounded-xl mb-4 relative z-10">
          <div className="flex items-center gap-2">
            <Network className="text-[#00E5FF] animate-pulse" size={16} />
            <span className="text-xs font-bold text-white font-sans uppercase">Topology Knowledge Graph</span>
          </div>

          <div className="flex items-center gap-2">
            {/* Filter buttons */}
            <span className="text-[10px] font-mono text-slate-500 uppercase">Focus:</span>
            <select
              value={filterType}
              onChange={e => setFilterType(e.target.value)}
              className="px-2 py-1 bg-[#050507] border border-white/10 rounded-lg text-[10px] text-slate-300 font-mono focus:outline-none"
            >
              <option value="All">All Entities</option>
              <option value="user">Users only</option>
              <option value="device">Hosts only</option>
              <option value="alert">Alerts only</option>
              <option value="incident">Incidents only</option>
            </select>

            <button
              onClick={fetchGraphData}
              title="Resync Graph Data"
              className="p-1.5 bg-white/5 hover:bg-white/10 text-slate-400 rounded-lg border border-white/5 cursor-pointer"
            >
              <RefreshCw size={12} />
            </button>
          </div>
        </div>

        {/* Dynamic Interactive SVG Stage */}
        {isLoading ? (
          <div className="flex-1 flex flex-col items-center justify-center space-y-2">
            <div className="w-8 h-8 border-2 border-t-[#00E5FF] border-white/10 rounded-full animate-spin" />
            <p className="text-[10px] text-slate-500 font-mono">Tracing graph database nodes...</p>
          </div>
        ) : (
          <div className="flex-1 relative bg-[#050507]/40 rounded-xl border border-white/5">
            <svg
              ref={stageRef}
              className="w-full h-full min-h-[480px]"
              viewBox="0 0 950 500"
              preserveAspectRatio="xMidYMid meet"
            >
              {/* SVG Arrow Marker definitions for link vectors */}
              <defs>
                <marker
                  id="arrow"
                  viewBox="0 0 10 10"
                  refX="16"
                  refY="5"
                  markerWidth="5"
                  markerHeight="5"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#334155" opacity="0.6" />
                </marker>
                <marker
                  id="arrow-active"
                  viewBox="0 0 10 10"
                  refX="16"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#00E5FF" />
                </marker>
              </defs>

              {/* DRAW CONNECTIONS (LINKS) */}
              <g>
                {links.map((link, idx) => {
                  const sourceNode = nodes.find(n => n.id === link.source);
                  const targetNode = nodes.find(n => n.id === link.target);

                  if (!sourceNode || !targetNode) return null;

                  const isHighlighted = selectedNode && isLinkConnected(link, selectedNode.id);
                  const hasFaded = selectedNode && !isHighlighted;

                  return (
                    <g key={idx}>
                      <line
                        x1={sourceNode.x}
                        y1={sourceNode.y}
                        x2={targetNode.x}
                        y2={targetNode.y}
                        stroke={isHighlighted ? "#00E5FF" : "#334155"}
                        strokeWidth={isHighlighted ? 2.5 : 1}
                        strokeDasharray={isHighlighted ? "none" : "3 3"}
                        opacity={hasFaded ? 0.15 : 0.7}
                        markerEnd={isHighlighted ? "url(#arrow-active)" : "url(#arrow)"}
                        className="transition-all duration-200"
                      />
                      {isHighlighted && (
                        <text
                          x={((sourceNode.x || 0) + (targetNode.x || 0)) / 2}
                          y={((sourceNode.y || 0) + (targetNode.y || 0)) / 2 - 5}
                          fill="#00E5FF"
                          fontSize="9"
                          fontFamily="monospace"
                          textAnchor="middle"
                          opacity={0.85}
                        >
                          {link.label}
                        </text>
                      )}
                    </g>
                  );
                })}
              </g>

              {/* DRAW ENTITIES (NODES) */}
              <g>
                {nodes
                  .filter(node => filterType === "All" || node.type === filterType)
                  .map(node => {
                    const isSelected = selectedNode?.id === node.id;
                    const isHovered = hoveredNode?.id === node.id;
                    const isHighlighted = selectedNode && activeHighlightedNodeIds.has(node.id);
                    const hasFaded = selectedNode && !isHighlighted;

                    const color = getNodeColor(node.type, node.severity);

                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.x}, ${node.y})`}
                        onClick={() => setSelectedNode(node)}
                        onMouseEnter={() => setHoveredNode(node)}
                        onMouseLeave={() => setHoveredNode(null)}
                        className="cursor-pointer group"
                      >
                        {/* Selected background glow halo */}
                        <circle
                          r={isSelected ? 18 : isHovered ? 14 : 10}
                          fill="transparent"
                          stroke={color}
                          strokeWidth={2}
                          className="transition-all duration-200"
                          opacity={isSelected ? 0.9 : isHovered ? 0.6 : 0}
                          style={{ filter: isSelected || isHovered ? `drop-shadow(0 0 8px ${color})` : "none" }}
                        />

                        {/* Core circle */}
                        <circle
                          r={10}
                          fill="#0D0E12"
                          stroke={color}
                          strokeWidth={isSelected ? 2.5 : 1.5}
                          opacity={hasFaded ? 0.3 : 1}
                          className="transition-all duration-200"
                        />

                        {/* Little central emblem */}
                        <g opacity={hasFaded ? 0.3 : 1} transform="translate(-6.5, -6.5)" className="text-slate-400 group-hover:text-white transition-colors pointer-events-none">
                          {getNodeIcon(node.type)}
                        </g>

                        {/* Text Label offset */}
                        <text
                          y={20}
                          fill={isSelected ? "#ffffff" : isHovered ? color : "#94a3b8"}
                          fontSize="9"
                          fontFamily="monospace"
                          fontWeight={isSelected ? "bold" : "normal"}
                          textAnchor="middle"
                          opacity={hasFaded ? 0.2 : 1}
                          className="select-none pointer-events-none transition-all"
                        >
                          {node.label}
                        </text>
                      </g>
                    );
                  })}
              </g>
            </svg>

            {/* Custom SVG Column Labels */}
            <div className="absolute top-4 left-0 right-0 flex justify-between px-14 pointer-events-none">
              <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest bg-black/40 px-1.5 py-0.5 rounded border border-white/5">USERS</span>
              <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest bg-black/40 px-1.5 py-0.5 rounded border border-white/5">HOSTS</span>
              <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest bg-black/40 px-1.5 py-0.5 rounded border border-white/5">ALERTS</span>
              <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest bg-black/40 px-1.5 py-0.5 rounded border border-white/5">THREAT INTEL</span>
              <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest bg-black/40 px-1.5 py-0.5 rounded border border-white/5">INCIDENTS</span>
            </div>
          </div>
        )}
      </div>

      {/* Side HUD Panel: Selected Node Inspector */}
      <div className="lg:col-span-1 bg-[#0D0E12] border border-white/5 rounded-2xl p-5 h-[650px] overflow-y-auto flex flex-col justify-between">
        {selectedNode ? (
          <div className="space-y-6 flex-1 flex flex-col justify-between">
            <div className="space-y-5">
              <div className="flex items-center justify-between border-b border-white/5 pb-3">
                <span className="text-[10px] font-mono text-slate-500 uppercase">Entity Inspector</span>
                <span className="text-[9px] font-mono bg-white/5 text-[#00E5FF] px-1.5 py-0.5 rounded">
                  {selectedNode.type.toUpperCase()}
                </span>
              </div>

              {/* Visual Entity Icon Header */}
              <div className="flex items-center gap-3">
                <div 
                  className="p-3 bg-[#050507] rounded-xl border border-white/10"
                  style={{ color: getNodeColor(selectedNode.type, selectedNode.severity), boxShadow: `0 0 15px ${getNodeColor(selectedNode.type, selectedNode.severity)}20` }}
                >
                  {selectedNode.type === "user" ? <User size={22} /> :
                   selectedNode.type === "device" ? <Server size={22} /> :
                   selectedNode.type === "alert" ? <AlertTriangle size={22} /> :
                   selectedNode.type === "incident" ? <FileText size={22} /> :
                   <Shield size={22} />}
                </div>
                <div>
                  <h3 className="text-sm font-extrabold text-white leading-tight">{selectedNode.label}</h3>
                  <span className="text-[10px] font-mono text-slate-500">ID: {selectedNode.id}</span>
                </div>
              </div>

              {/* Metadata Attributes depending on Node Type */}
              <div className="space-y-3 pt-2">
                <h4 className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">ENTITY SPECIFICATION</h4>
                
                <div className="bg-[#050507] rounded-xl p-3 border border-white/5 space-y-2 text-xs font-mono">
                  {selectedNode.type === "user" && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Email Address:</span>
                        <span className="text-slate-300">{selectedNode.details?.email}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Tenant Privilege:</span>
                        <span className="text-[#00E5FF] font-bold">{selectedNode.details?.role}</span>
                      </div>
                    </>
                  )}

                  {selectedNode.type === "device" && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-slate-500">IP Address:</span>
                        <span className="text-slate-300">{selectedNode.details?.ip}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Operating System:</span>
                        <span className="text-slate-300">{selectedNode.details?.os}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Criticality Score:</span>
                        <span className={`font-bold ${
                          selectedNode.severity === "Critical" ? "text-red-400" : "text-green-400"
                        }`}>{selectedNode.severity}</span>
                      </div>
                    </>
                  )}

                  {selectedNode.type === "alert" && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Severity Tier:</span>
                        <span className="text-red-400 font-bold">{selectedNode.severity}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Attack Taxonomy:</span>
                        <span className="text-slate-300">{selectedNode.details?.category}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Incident Status:</span>
                        <span className="text-amber-400">{selectedNode.details?.status}</span>
                      </div>
                    </>
                  )}

                  {selectedNode.type === "incident" && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Incident Severity:</span>
                        <span className="text-red-400 font-bold">{selectedNode.severity}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Lead Investigator:</span>
                        <span className="text-slate-300 text-right overflow-hidden text-ellipsis max-w-[120px]">{selectedNode.details?.generatedBy}</span>
                      </div>
                    </>
                  )}

                  {selectedNode.type === "threat" && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-slate-500">MITRE Code:</span>
                        <span className="text-[#00E5FF] font-bold">{selectedNode.details?.code || "T1000"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Severity Metric:</span>
                        <span className="text-red-400">{selectedNode.severity}</span>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Connections summary list */}
              <div className="space-y-2.5">
                <h4 className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">CONNECTED RELATIONS</h4>
                <div className="space-y-1.5 max-h-[160px] overflow-y-auto">
                  {links
                    .filter(l => l.source === selectedNode.id || l.target === selectedNode.id)
                    .map((l, idx) => {
                      const oppositeId = l.source === selectedNode.id ? l.target : l.source;
                      const matchedNode = nodes.find(n => n.id === oppositeId);
                      return (
                        <div key={idx} className="p-2 bg-[#050507] rounded-lg border border-white/5 flex items-center justify-between text-[11px] font-mono">
                          <span className="text-slate-400">{l.label.toUpperCase()}</span>
                          <span className="text-slate-300 font-bold">{matchedNode?.label || oppositeId}</span>
                        </div>
                      );
                    })}
                </div>
              </div>
            </div>

            <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl flex items-start gap-2 pt-4 mt-4">
              <Info size={14} className="text-[#00E5FF] shrink-0" />
              <p className="text-[10px] text-slate-400 leading-relaxed font-mono">
                Interact with the graph by clicking on any system node. This traces active multi-stage correlation relationships and highlights adjacent entity linkages.
              </p>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center space-y-2 text-slate-500 font-mono text-xs">
            <Info size={20} />
            <p>Select a node in the graph workspace to invoke the Cyber Inspector.</p>
          </div>
        )}
      </div>
    </div>
  );
}
