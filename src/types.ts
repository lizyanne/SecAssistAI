export type UserRole = 'Admin' | 'Analyst' | 'Viewer';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  tenantId: string;
}

export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';
export type AlertStatus = 'Active' | 'Investigating' | 'Resolved';

export interface SecurityAlert {
  id: string;
  title: string;
  severity: SeverityLevel;
  category: string;
  timestamp: string;
  sourceIp: string;
  destIp: string;
  status: AlertStatus;
  description: string;
  mitreAttack?: {
    tactic: string;
    technique: string;
    id: string;
  };
  assignedTo?: string;
  tenantId: string;
}

export interface SecurityLog {
  id: string;
  filename: string;
  uploadedBy: string;
  timestamp: string;
  parsedCount: number;
  status: 'Parsed' | 'Analyzing' | 'Analyzed' | 'Failed';
  rawContent: string;
  analysis?: LogAnalysis;
}

export interface LogAnalysis {
  threatLevel: SeverityLevel;
  threatName: string;
  explanation: string;
  remediationSteps: string[];
  mitreMapping: {
    tactic: string;
    technique: string;
    id: string;
  };
  suspiciousIndicators: string[];
}

export interface ThreatIntel {
  id: string;
  name: string;
  severity: SeverityLevel;
  mitreMapping: {
    tactic: string;
    technique: string;
    id: string;
  };
  explanation: string;
  remediation: string;
  detectionSignature: string;
  affectedAssets: string[];
}

export interface IncidentReport {
  id: string;
  title: string;
  alertId?: string;
  threatName: string;
  severity: SeverityLevel;
  mitreMapping: {
    tactic: string;
    technique: string;
    id: string;
  };
  executiveSummary: string;
  technicalDetails: string;
  remediationPlan: string;
  generatedBy: string;
  timestamp: string;
  rootCauseAssessment?: string;
  riskRating?: string;
}

export interface DashboardStats {
  riskScore: number;
  totalAlerts: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  activeIncidents: number;
  resolvedIncidents: number;
  timelineData: {
    time: string;
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
  }[];
  mitreHeatmap: {
    tactic: string;
    count: number;
    color: string;
  }[];
  categoryDistribution: {
    name: string;
    value: number;
  }[];
}

export interface Asset {
  id: string;
  name: string;
  type: 'Server' | 'Endpoint' | 'Cloud';
  ipAddress: string;
  os: string;
  criticality: SeverityLevel;
  status: 'Online' | 'Offline' | 'Investigating';
  owner: string;
  cloudProvider?: string;
  activeAlertsCount: number;
  lastSeen: string;
}

export interface Vulnerability {
  id: string;
  title: string;
  score: number;
  severity: SeverityLevel;
  affectedAssetId: string;
  affectedAssetName: string;
  status: 'Open' | 'In Progress' | 'Patched' | 'Ignored';
  patchRecommendation: string;
  publishedDate: string;
  description: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'user' | 'device' | 'alert' | 'incident' | 'threat';
  severity?: SeverityLevel;
  details?: Record<string, any>;
  x?: number;
  y?: number;
}

export interface GraphLink {
  source: string;
  target: string;
  label: string;
}

export interface AiInvestigation {
  id: string;
  alertId: string;
  alertTitle: string;
  status: 'Completed' | 'In Progress' | 'Failed';
  evidence: {
    type: 'process' | 'network' | 'user' | 'file';
    name: string;
    description: string;
    severity: 'Suspicious' | 'Malicious' | 'Benign';
  }[];
  findings: string[];
  remediationSteps: string[];
  timestamp: string;
  logs: string[];
}

