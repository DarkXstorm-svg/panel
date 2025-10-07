from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Integer, default=0)
    is_owner = db.Column(db.Integer, default=0)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login_time = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Device(db.Model):
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(255), unique=True, nullable=False)
    user_name = db.Column(db.String(255), nullable=False)
    approved = db.Column(db.Integer, default=0)
    expiration_date = db.Column(db.Date)
    registration_date = db.Column(db.Date, default=datetime.utcnow().date())

class DeviceLog(db.Model):
    __tablename__ = 'device_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    old_status = db.Column(db.String(50))
    new_status = db.Column(db.String(50))
    expiration_change = db.Column(db.String(255))
    action_by = db.Column(db.String(255))
    action_date = db.Column(db.DateTime, default=datetime.utcnow)

class UserLog(db.Model):
    __tablename__ = 'user_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    action_date = db.Column(db.DateTime, default=datetime.utcnow)

class Setting(db.Model):
    __tablename__ = 'settings'
    
    setting_key = db.Column(db.String(100), primary_key=True)
    setting_value = db.Column(db.Text)

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info')
    read_status = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    attempt_time = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Integer, default=0)
