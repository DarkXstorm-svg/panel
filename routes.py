from flask import render_template, request, redirect, url_for, session, jsonify, flash
from app import app, db
from models import User, Device, DeviceLog, UserLog, Setting, Notification, LoginAttempt
from utils import (get_setting, set_setting, log_device_action, log_user_action, 
                   add_notification, log_login_attempt, get_client_ip)
from datetime import datetime, timedelta, date
import secrets

# Add date utility to templates
@app.template_global()
def today():
    return date.today()

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token():
    token = session.pop('csrf_token', None)
    return token and token == request.form.get('csrf_token')

# Add CSRF token and common variables to all templates
@app.context_processor
def inject_csrf_token():
    context = dict(csrf_token=generate_csrf_token())
    
    # Add common variables for logged-in users
    if 'user_id' in session:
        # Get unread notification count
        unread_count = Notification.query.filter(
            (Notification.user_id == session['user_id']) | (Notification.user_id.is_(None)),
            Notification.read_status == 0
        ).count()
        
        context.update({
            'unread_count': unread_count,
            'site_name': get_setting('site_name', 'AshxDeath Panel')
        })
    
    return context

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        ip_address = get_client_ip()
        
        max_attempts = int(get_setting('max_login_attempts', 5))
        lockout_minutes = int(get_setting('login_lockout_time_minutes', 15))
        
        if user:
            # Check for lockout
            if user.failed_login_attempts >= max_attempts:
                if user.last_failed_login_time:
                    unlock_time = user.last_failed_login_time + timedelta(minutes=lockout_minutes)
                    if datetime.utcnow() < unlock_time:
                        time_remaining = int((unlock_time - datetime.utcnow()).total_seconds() / 60) + 1
                        flash(f'Too many failed login attempts. Please try again in {time_remaining} minutes.', 'error')
                        log_login_attempt(username, ip_address, False)
                        return render_template('login.html')
                    else:
                        # Reset attempts after lockout period
                        user.failed_login_attempts = 0
                        user.last_failed_login_time = None
                        db.session.commit()
            
            if user.check_password(password) and user.is_admin:
                # Reset failed attempts on successful login
                user.failed_login_attempts = 0
                user.last_failed_login_time = None
                db.session.commit()
                
                session['user_id'] = user.id
                session['username'] = user.username
                session['is_admin'] = True
                session['is_owner'] = bool(user.is_owner)
                
                log_login_attempt(username, ip_address, True)
                return redirect(url_for('dashboard'))
            else:
                # Increment failed attempts
                user.failed_login_attempts += 1
                user.last_failed_login_time = datetime.utcnow()
                db.session.commit()
                log_login_attempt(username, ip_address, False)
                flash('Invalid username or password.', 'error')
        else:
            log_login_attempt(username, ip_address, False)
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get dashboard statistics
    total_devices = Device.query.count()
    approved_devices = Device.query.filter_by(approved=1).count()
    pending_devices = Device.query.filter_by(approved=0).count()
    
    # Get expired devices
    today = date.today()
    expired_devices = Device.query.filter(
        Device.approved == 1,
        Device.expiration_date < today
    ).count()
    
    # Get recent notifications
    notifications = Notification.query.filter(
        (Notification.user_id == session['user_id']) | (Notification.user_id.is_(None))
    ).order_by(Notification.created_at.desc()).limit(10).all()
    
    # Get unread notification count
    unread_count = Notification.query.filter(
        (Notification.user_id == session['user_id']) | (Notification.user_id.is_(None)),
        Notification.read_status == 0
    ).count()
    
    # Get recent devices
    recent_devices = Device.query.order_by(Device.registration_date.desc()).limit(5).all()
    
    return render_template('dashboard.html',
                         total_devices=total_devices,
                         approved_devices=approved_devices,
                         pending_devices=pending_devices,
                         expired_devices=expired_devices,
                         notifications=notifications,
                         unread_count=unread_count,
                         recent_devices=recent_devices,
                         site_name=get_setting('site_name', 'AshxDeath Panel'))

@app.route('/devices')
def devices():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    search = request.args.get('search', '').strip()
    
    query = Device.query
    
    if status_filter == 'approved':
        query = query.filter_by(approved=1)
    elif status_filter == 'pending':
        query = query.filter_by(approved=0)
    elif status_filter == 'expired':
        today = date.today()
        query = query.filter(Device.approved == 1, Device.expiration_date < today)
    
    if search:
        query = query.filter(
            (Device.device_id.contains(search)) |
            (Device.user_name.contains(search))
        )
    
    devices_list = query.order_by(Device.registration_date.desc()).all()
    
    return render_template('devices.html', devices=devices_list, 
                         status_filter=status_filter, search=search)

@app.route('/device_action', methods=['POST'])
def device_action():
    if 'user_id' not in session or not validate_csrf_token():
        flash('Invalid request.', 'error')
        return redirect(url_for('devices'))
    
    action = request.form.get('action')
    device_id = request.form.get('device_id')
    
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        flash('Device not found.', 'error')
        return redirect(url_for('devices'))
    
    username = session['username']
    
    if action == 'approve':
        old_status = 'Pending' if not device.approved else 'Approved'
        device.approved = 1
        
        # Set expiration date
        expiration_days = int(get_setting('default_expiration_days', 30))
        device.expiration_date = date.today() + timedelta(days=expiration_days)
        
        log_device_action(device_id, 'approved', old_status, 'Approved',
                         f'Set to expire on {device.expiration_date}', username)
        flash(f'Device {device_id} approved successfully.', 'success')
        
    elif action == 'deny':
        old_status = 'Approved' if device.approved else 'Pending'
        device.approved = 0
        device.expiration_date = None
        
        log_device_action(device_id, 'denied', old_status, 'Denied', 'Expiration removed', username)
        flash(f'Device {device_id} denied.', 'warning')
        
    elif action == 'delete':
        old_status = 'Approved' if device.approved else 'Pending'
        log_device_action(device_id, 'deleted', old_status, 'Deleted', 'N/A', username)
        db.session.delete(device)
        flash(f'Device {device_id} deleted.', 'info')
        
    elif action == 'extend':
        if not device.approved:
            flash(f'Cannot extend device {device_id}. Device must be approved first.', 'error')
            return redirect(url_for('devices'))
        
        try:
            extension_days = int(request.form.get('extension_days', 30))
            if extension_days < 1 or extension_days > 365:
                flash('Extension days must be between 1 and 365.', 'error')
                return redirect(url_for('devices'))
        except (ValueError, TypeError):
            flash('Invalid extension days value.', 'error')
            return redirect(url_for('devices'))
        
        old_expiration = device.expiration_date
        
        # Extend from current expiration if it's still in the future, otherwise from today
        if device.expiration_date and device.expiration_date > date.today():
            device.expiration_date = device.expiration_date + timedelta(days=extension_days)
        else:
            device.expiration_date = date.today() + timedelta(days=extension_days)
        
        expiration_change = f'Extended from {old_expiration} to {device.expiration_date}'
        log_device_action(device_id, 'extended', 'Approved', 'Approved', 
                         expiration_change, username)
        
        # Add notification for admins
        add_notification(None, f'Device {device_id} extended by {username} until {device.expiration_date}.', 'info')
        
        flash(f'Device {device_id} extended successfully until {device.expiration_date}.', 'success')
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing device action: {str(e)}', 'error')
        return redirect(url_for('devices'))
    
    return redirect(url_for('devices'))

@app.route('/users')
def users():
    if 'user_id' not in session or not session.get('is_owner'):
        flash('Access denied. Owner privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    users_list = User.query.all()
    
    return render_template('users.html', users=users_list)

@app.route('/user_action', methods=['POST'])
def user_action():
    if 'user_id' not in session or not session.get('is_owner') or not validate_csrf_token():
        flash('Access denied or invalid request.', 'error')
        return redirect(url_for('users'))
    
    action = request.form.get('action')
    user_id_to_act = request.form.get('user_id')
    
    target_user = None
    if user_id_to_act:
        target_user = User.query.get(user_id_to_act)
        if not target_user and action != 'add_user':
            flash('User not found.', 'error')
            return redirect(url_for('users'))
        
        # Prevent self-modification for critical actions
        if int(user_id_to_act) == session['user_id'] and action in ['toggle_admin', 'delete_user']:
            flash('You cannot modify your own account status.', 'error')
            return redirect(url_for('users'))
    
    username = session['username']
    
    if action == 'add_user':
        new_username = request.form.get('new_username', '').strip()
        new_password = request.form.get('new_password', '')
        
        if not new_username or not new_password:
            flash('Username and password are required.', 'error')
        elif User.query.filter_by(username=new_username).first():
            flash(f'Username {new_username} already exists.', 'error')
        else:
            new_user = User()
            new_user.username = new_username
            new_user.is_admin = 1
            new_user.is_owner = 0
            new_user.set_password(new_password)
            db.session.add(new_user)
            db.session.commit()
            
            log_user_action(session['user_id'], username, 'added_admin', 
                           f'Added new admin: {new_username}')
            add_notification(None, f'New admin user {new_username} added by {username}.', 'success')
            flash(f'Admin user {new_username} added successfully.', 'success')
    
    elif action == 'toggle_admin' and target_user:
        new_admin_status = 1 - target_user.is_admin
        target_user.is_admin = new_admin_status
        status_change = 'Promoted to Admin' if new_admin_status else 'Demoted from Admin'
        
        log_user_action(session['user_id'], username, 'toggled_admin_status',
                       f'User: {target_user.username} to {status_change}')
        add_notification(target_user.id, f'Your admin status was changed to {status_change}.', 'warning')
        flash(f'User {target_user.username} {status_change.lower()}.', 'success')
        
    elif action == 'delete_user' and target_user:
        # Check if this is the last owner
        if target_user.is_owner:
            owner_count = User.query.filter_by(is_owner=1).count()
            if owner_count <= 1:
                flash('Cannot delete the last owner account.', 'error')
                return redirect(url_for('users'))
        
        username_to_delete = target_user.username
        log_user_action(session['user_id'], username, 'deleted_user',
                       f'Deleted user: {username_to_delete}')
        db.session.delete(target_user)
        add_notification(None, f'User {username_to_delete} deleted by {username}.', 'danger')
        flash(f'User {username_to_delete} deleted successfully.', 'info')
        
    elif action == 'reset_password' and target_user:
        new_password = request.form.get('new_password', '')
        if not new_password:
            flash('New password cannot be empty.', 'error')
        else:
            target_user.set_password(new_password)
            log_user_action(session['user_id'], username, 'reset_password',
                           f'Reset password for user: {target_user.username}')
            add_notification(target_user.id, f'Your password was reset by {username}.', 'warning')
            flash(f'Password for {target_user.username} reset successfully.', 'success')
    
    db.session.commit()
    return redirect(url_for('users'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST' and validate_csrf_token():
        new_expiration_days = request.form.get('default_expiration_days', '').strip()
        new_site_name = request.form.get('site_name', '').strip()
        
        if not new_expiration_days.isdigit() or int(new_expiration_days) < 1:
            flash('Default expiration days must be a positive number.', 'error')
        else:
            set_setting('default_expiration_days', new_expiration_days)
            set_setting('site_name', new_site_name)
            
            log_user_action(session['user_id'], session['username'], 'updated_settings',
                           f'Default exp: {new_expiration_days}, Site name: {new_site_name}')
            add_notification(None, f'Application settings updated by {session["username"]}.', 'primary')
            flash('Settings updated successfully.', 'success')
    
    current_settings = {
        'default_expiration_days': get_setting('default_expiration_days', 30),
        'site_name': get_setting('site_name', 'AshxDeath Panel'),
        'max_login_attempts': get_setting('max_login_attempts', 5),
        'login_lockout_time_minutes': get_setting('login_lockout_time_minutes', 15)
    }
    
    return render_template('settings.html', settings=current_settings)

@app.route('/logs')
def logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    log_type = request.args.get('type', 'device')
    
    if log_type == 'user':
        logs = UserLog.query.order_by(UserLog.action_date.desc()).limit(100).all()
    else:
        logs = DeviceLog.query.order_by(DeviceLog.action_date.desc()).limit(100).all()
    
    return render_template('logs.html', logs=logs, log_type=log_type)

@app.route('/mark_notification_read', methods=['POST'])
def mark_notification_read():
    if 'user_id' not in session or not validate_csrf_token():
        return jsonify({'error': 'Invalid request'}), 400
    
    notification_id = request.form.get('notification_id')
    if notification_id == 'all':
        Notification.query.filter(
            (Notification.user_id == session['user_id']) | (Notification.user_id.is_(None))
        ).update({'read_status': 1})
    else:
        notification = Notification.query.filter(
            Notification.id == notification_id,
            (Notification.user_id == session['user_id']) | (Notification.user_id.is_(None))
        ).first()
        if notification:
            notification.read_status = 1
    
    db.session.commit()
    return jsonify({'success': True})

# API endpoint for device checking (compatible with original PHP API)
@app.route('/api.php')
@app.route('/api')
def api_device_check():
    device_id = request.args.get('device_id', '').strip()
    user_name = request.args.get('user_name', '').strip()
    
    response = {'status': 'error', 'message': 'Invalid request'}
    
    if not device_id or not user_name:
        response = {'status': 'error', 'message': 'Missing device_id or user_name'}
    else:
        device = Device.query.filter_by(device_id=device_id).first()
        
        if device:
            if device.approved:
                if device.expiration_date and device.expiration_date < date.today():
                    response = {'status': 'expired', 'message': 'Your subscription has expired.'}
                    log_device_action(device_id, 'expired_checkin', 'Approved', 'Expired', 'N/A', 'System (API)')
                else:
                    response = {'status': 'active', 'message': 'Subscription active.'}
                    log_device_action(device_id, 'checked_in', 'N/A', 'Active', 'N/A', 'System (API)')
            else:
                response = {'status': 'pending', 'message': 'Your device is awaiting approval.'}
                log_device_action(device_id, 'pending_checkin', 'N/A', 'Pending', 'N/A', 'System (API)')
        else:
            # Register new device
            new_device = Device()
            new_device.device_id = device_id
            new_device.user_name = user_name
            new_device.approved = 0
            db.session.add(new_device)
            db.session.commit()
            
            response = {'status': 'registered_pending', 'message': 'Device registered. Awaiting approval.'}
            log_device_action(device_id, 'registered', 'N/A', 'Pending', 'N/A', 'System (API)')
            
            # Notify all admins
            admin_users = User.query.filter_by(is_admin=1).all()
            for admin in admin_users:
                add_notification(admin.id, f"New device '{device_id}' registered by '{user_name}'.", 'info')
    
    return jsonify(response)
