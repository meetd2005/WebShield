from app import db
from flask_login import UserMixin
from datetime import datetime
import bcrypt
import json

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy=True)

    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        if isinstance(self.password, str):
            self.password = self.password.encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), self.password)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default="pending")
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    configuration = db.Column(db.JSON)
    reports = db.relationship('Report', backref='scan', lazy=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    summary = db.Column(db.JSON, nullable=False)
    vulnerabilities = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_format = db.Column(db.String(20), default='html')
    request_details = db.Column(db.JSON)  # Store HTTP request details
    response_details = db.Column(db.JSON)  # Store HTTP response details
    ai_analysis = db.Column(db.JSON)  # Store AI-generated analysis
    threat_intel = db.Column(db.JSON)  # Store threat intelligence data

    def get_severity_counts(self):
        counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def get_request_details(self):
        return self.request_details if self.request_details else {}

    def get_response_details(self):
        return self.response_details if self.response_details else {}

    def get_ai_analysis(self):
        return self.ai_analysis if self.ai_analysis else {}

    def get_threat_intel(self):
        return self.threat_intel if self.threat_intel else {}

# New models for threat intelligence
class ThreatIntelligence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), unique=True, nullable=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    cvss_score = db.Column(db.Float)
    published_date = db.Column(db.DateTime, nullable=False)
    last_modified = db.Column(db.DateTime, nullable=False)
    affected_products = db.Column(db.JSON)
    references = db.Column(db.JSON)
    mitigations = db.Column(db.Text)
    source = db.Column(db.String(50), nullable=False)  # e.g., 'MITRE', 'OTX', 'NVD'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ThreatIndicator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(50), nullable=False)  # e.g., 'IP', 'domain', 'hash'
    value = db.Column(db.String(255), nullable=False)
    confidence_score = db.Column(db.Float, nullable=False)
    threat_type = db.Column(db.String(50), nullable=False)  # e.g., 'malware', 'phishing', 'c2'
    first_seen = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False)
    source = db.Column(db.String(50), nullable=False)
    additional_data = db.Column(db.JSON)  # Renamed from metadata to avoid SQLAlchemy conflicts
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_indicator_value', 'value'),  # Index for faster lookups
        db.Index('idx_indicator_type_value', 'indicator_type', 'value'),  # Composite index
    )