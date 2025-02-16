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