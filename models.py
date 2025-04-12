from datetime import datetime
from app import db
from flask_login import UserMixin
import json


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # ensure password hash field has length of at least 256
    password_hash = db.Column(db.String(256))
    scans = db.relationship('Scan', backref='user', lazy='dynamic')
    reports = db.relationship('Report', backref='user', lazy='dynamic')


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="pending")  # pending, in_progress, completed, failed
    modules_run = db.Column(db.String(255))  # comma-separated list of modules
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=True)
    
    def set_modules(self, modules_list):
        self.modules_run = ','.join(modules_list)
        
    def get_modules(self):
        return self.modules_run.split(',') if self.modules_run else []


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'))
    type = db.Column(db.String(50), nullable=False)  # SQL Injection, XSS, etc.
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low, Info
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)  # URL or component affected
    proof = db.Column(db.Text)  # Evidence of vulnerability
    remediation = db.Column(db.Text)  # Suggested fix
    
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'severity': self.severity,
            'description': self.description,
            'location': self.location,
            'proof': self.proof,
            'remediation': self.remediation
        }


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    summary = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    vulnerabilities = db.relationship('Vulnerability', backref='report', lazy='dynamic')
    scans = db.relationship('Scan', backref='report', lazy='dynamic')
    
    def get_vulnerability_count_by_severity(self):
        counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in self.vulnerabilities:
            if vuln.severity in counts:
                counts[vuln.severity] += 1
                
        return counts
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self.summary,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'vulnerability_counts': self.get_vulnerability_count_by_severity()
        }
