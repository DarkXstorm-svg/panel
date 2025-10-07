from app import db
from models import User, Setting, Notification, DeviceLog, UserLog, LoginAttempt
from config import ADMIN_USERNAME, ADMIN_PASSWORD, DEFAULT_SETTINGS
from datetime import datetime
from flask import request
import logging

def initialize_default_data():
    """Initialize default admin user and settings"""
    # Check if admin user exists
    admin_user = User.query.filter_by(username=ADMIN_USERNAME).first()
    if not admin_user:
        admin_user = User()
        admin_user.username = ADMIN_USERNAME
        admin_user.is_admin = 1
        admin_user.is_owner = 1
        admin_user.set_password(ADMIN_PASSWORD)
        db.session.add(admin_user)
        logging.info(f"Created admin user: {ADMIN_USERNAME}")
    else:
        # Ensure existing admin is marked as owner
        if not admin_user.is_owner:
            admin_user.is_owner = 1
            logging.info(f"Updated admin user {ADMIN_USERNAME} to owner status")
    
    # Initialize default settings
    for key, value in DEFAULT_SETTINGS.items():
        setting = Setting.query.filter_by(setting_key=key).first()
        if not setting:
            setting = Setting()
            setting.setting_key = key
            setting.setting_value = value
            db.session.add(setting)
    
    db.session.commit()

def get_setting(key, default_value=None):
    """Get a setting value from database"""
    setting = Setting.query.filter_by(setting_key=key).first()
    return setting.setting_value if setting else default_value

def set_setting(key, value):
    """Set a setting value in database"""
    setting = Setting.query.filter_by(setting_key=key).first()
    if setting:
        setting.setting_value = value
    else:
        setting = Setting()
        setting.setting_key = key
        setting.setting_value = value
        db.session.add(setting)
    db.session.commit()

def log_device_action(device_id, action, old_status, new_status, expiration_change, action_by):
    """Log device actions"""
    try:
        log_entry = DeviceLog()
        log_entry.device_id = device_id
        log_entry.action = action
        log_entry.old_status = old_status
        log_entry.new_status = new_status
        log_entry.expiration_change = expiration_change
        log_entry.action_by = action_by
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error logging device action: {e}")
        db.session.rollback()

def log_user_action(user_id, username, action, details=''):
    """Log user actions"""
    try:
        log_entry = UserLog()
        log_entry.user_id = user_id
        log_entry.username = username
        log_entry.action = action
        log_entry.details = details
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error logging user action: {e}")
        db.session.rollback()

def add_notification(user_id, message, type='info'):
    """Add a notification"""
    try:
        notification = Notification()
        notification.user_id = user_id
        notification.message = message
        notification.type = type
        db.session.add(notification)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error adding notification: {e}")
        db.session.rollback()

def log_login_attempt(username, ip_address, success):
    """Log login attempts"""
    try:
        attempt = LoginAttempt()
        attempt.username = username
        attempt.ip_address = ip_address
        attempt.success = 1 if success else 0
        db.session.add(attempt)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error logging login attempt: {e}")
        db.session.rollback()

def get_client_ip():
    """Get client IP address"""
    ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    return ip.split(',')[0].strip() if ip else '127.0.0.1'
