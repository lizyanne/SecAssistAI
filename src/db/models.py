from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, relationship
import datetime

Base = declarative_base()

class Organization(Base):
    __tablename__ = 'organizations'

    id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    domain = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    users = relationship("User", back_populates="organization")


class User(Base):
    __tablename__ = 'users'

    id = Column(String(50), primary_key=True)  # Can support external/firebase uid or auto-increment serial
    name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    role = Column(String(50), default="Analyst")  # Admin, Analyst, Viewer
    tenant_id = Column(String(50), ForeignKey('organizations.id'), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="users")
    assigned_alerts = relationship("Alert", back_populates="assignee")
    assigned_incidents = relationship("Incident", back_populates="assignee")


class Alert(Base):
    __tablename__ = 'alerts'

    id = Column(String(50), primary_key=True)
    title = Column(String(200), nullable=False)
    severity = Column(String(20), default="Low")  # Critical, High, Medium, Low
    category = Column(String(50), nullable=False)  # Malware, Initial Access, Exfiltration, etc.
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    source_ip = Column(String(50), nullable=True)
    dest_ip = Column(String(50), nullable=True)
    status = Column(String(30), default="Active")  # Active, Investigating, Resolved
    description = Column(Text, nullable=True)
    assigned_to = Column(String(100), ForeignKey('users.email'), nullable=True)
    tenant_id = Column(String(50), ForeignKey('organizations.id'), nullable=True)

    # Relationships
    assignee = relationship("User", back_populates="assigned_alerts", foreign_keys=[assigned_to])
    reports = relationship("Report", back_populates="alert")


class Incident(Base):
    __tablename__ = 'incidents'

    id = Column(String(50), primary_key=True)
    title = Column(String(200), nullable=False)
    severity = Column(String(20), default="Low")
    status = Column(String(30), default="Open")  # Open, Investigating, Resolved
    description = Column(Text, nullable=True)
    assigned_to = Column(String(100), ForeignKey('users.email'), nullable=True)
    tenant_id = Column(String(50), ForeignKey('organizations.id'), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    assignee = relationship("User", back_populates="assigned_incidents", foreign_keys=[assigned_to])


class Asset(Base):
    __tablename__ = 'assets'

    id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    type = Column(String(50), nullable=False)  # Server, Endpoint, Cloud
    ip_address = Column(String(50), nullable=False)
    os = Column(String(100), nullable=True)
    criticality = Column(String(20), default="Medium")  # Critical, High, Medium, Low
    status = Column(String(20), default="Online")  # Online, Offline, Investigating
    owner = Column(String(100), ForeignKey('users.email'), nullable=True)
    active_alerts_count = Column(Integer, default=0)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'

    id = Column(String(50), primary_key=True)  # e.g., CVE-2024-3094
    title = Column(String(200), nullable=False)
    score = Column(Float, default=0.0)
    severity = Column(String(20), default="Low")  # Critical, High, Medium, Low
    affected_asset_id = Column(String(50), ForeignKey('assets.id'), nullable=True)
    affected_asset_name = Column(String(100), nullable=True)
    status = Column(String(20), default="Open")  # Open, In Progress, Patched
    patch_recommendation = Column(Text, nullable=True)
    published_date = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)


class ThreatIntelligence(Base):
    __tablename__ = 'threat_intelligence'

    id = Column(String(50), primary_key=True)
    name = Column(String(200), nullable=False)
    severity = Column(String(20), default="Low")
    explanation = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    detection_signature = Column(Text, nullable=True)
    affected_assets = Column(JSON, nullable=True)  # List of string assets


class Report(Base):
    __tablename__ = 'reports'

    id = Column(String(50), primary_key=True)
    title = Column(String(200), nullable=False)
    alert_id = Column(String(50), ForeignKey('alerts.id'), nullable=True)
    threat_name = Column(String(100), nullable=True)
    severity = Column(String(20), default="Low")
    executive_summary = Column(Text, nullable=True)
    technical_details = Column(Text, nullable=True)
    remediation_plan = Column(Text, nullable=True)
    generated_by = Column(String(100), ForeignKey('users.email'), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    alert = relationship("Alert", back_populates="reports")


class AuditLog(Base):
    __tablename__ = 'audit_logs'

    id = Column(String(50), primary_key=True)
    filename = Column(String(255), nullable=False)
    uploaded_by = Column(String(100), ForeignKey('users.email'), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    parsed_count = Column(Integer, default=0)
    status = Column(String(30), default="Analyzed")  # Pending, Analyzed, Failed
    raw_content = Column(Text, nullable=True)
    analysis = Column(JSON, nullable=True)  # Full AI analysis response


class ComplianceRecord(Base):
    __tablename__ = 'compliance_records'

    id = Column(String(50), primary_key=True)
    framework = Column(String(50), nullable=False)  # SOC2, ISO27001, NIST, HIPAA
    control_id = Column(String(50), nullable=False)
    control_name = Column(String(200), nullable=False)
    status = Column(String(30), default="Compliant")  # Compliant, Non-Compliant, In Progress
    maturity_score = Column(Integer, default=0)  # out of 100
    evidence = Column(Text, nullable=True)
    last_audited = Column(DateTime, default=datetime.datetime.utcnow)


class MitreMapping(Base):
    __tablename__ = 'mitre_mappings'

    id = Column(String(50), primary_key=True)  # e.g., mm-101
    tactic = Column(String(100), nullable=False)
    technique = Column(String(100), nullable=False)
    technique_id = Column(String(50), nullable=False)  # e.g., T1071.001
    entity_type = Column(String(50), nullable=False)  # alert, threat, log
    entity_id = Column(String(50), nullable=False)
