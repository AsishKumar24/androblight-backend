"""
Database Models
================
SQLAlchemy models for User and ScanRecord.
Used for authentication and cloud-synced scan history.
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    """User account model"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    scan_records = db.relationship('ScanRecord', backref='user', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'display_name': self.display_name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ScanRecord(db.Model):
    """Scan history record — stored per-user for cloud sync"""
    __tablename__ = 'scan_records'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    file_hash = db.Column(db.String(64), nullable=True, index=True)
    scan_type = db.Column(db.String(20), nullable=False, default='apk')  # 'apk' or 'playstore'
    identifier = db.Column(db.String(255), nullable=False)  # filename or package name
    file_name = db.Column(db.String(255), nullable=True)
    package_name = db.Column(db.String(255), nullable=True, index=True)
    file_size = db.Column(db.Integer, nullable=True)
    label = db.Column(db.String(20), nullable=False)  # 'Malware' or 'Benign'
    confidence = db.Column(db.Float, nullable=False, default=0.0)
    overall_score = db.Column(db.Integer, nullable=True)
    threat_level = db.Column(db.String(20), nullable=True)
    result_json = db.Column(db.Text, nullable=True)  # Full scan result as JSON
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'file_hash': self.file_hash,
            'scan_type': self.scan_type,
            'identifier': self.identifier,
            'file_name': self.file_name,
            'package_name': self.package_name,
            'file_size': self.file_size,
            'label': self.label,
            'confidence': self.confidence,
            'overall_score': self.overall_score,
            'threat_level': self.threat_level,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
