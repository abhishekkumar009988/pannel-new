import os
import sys
import json
import secrets
import hashlib
import time
import threading
from datetime import datetime, timedelta, timezone

_activation_lock = threading.Lock()
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, abort

# Set up paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('OWNER_DATA_DIR', str(BASE_DIR / 'data'))).expanduser().resolve()
KEYS_DIR = DATA_DIR / 'keys'
DATA_DIR.mkdir(parents=True, exist_ok=True)
KEYS_DIR.mkdir(parents=True, exist_ok=True)

from owner_services.crypto_signer import CryptoSigner
from owner_services.licensing_db import LicensingDB

app = Flask(__name__)

# Secret key for session management
_secret_path = DATA_DIR / '.secret_key'
if _secret_path.exists():
    app.secret_key = _secret_path.read_text(encoding='utf-8').strip()
else:
    app.secret_key = secrets.token_hex(32)
    _secret_path.write_text(app.secret_key, encoding='utf-8')

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
)

signer = CryptoSigner(KEYS_DIR)
db = LicensingDB(DATA_DIR / 'licensing.db')

# Setup default owner account if none exists
def setup_default_owner():
    if not db.get_admin('owner'):
        salt = secrets.token_bytes(32)
        initial_pwd = os.environ.get('OWNER_INITIAL_PASSWORD', '')
        if len(initial_pwd) < 12:
            raise RuntimeError('Set OWNER_INITIAL_PASSWORD to a strong password (at least 12 characters) before first startup.')
        key = hashlib.pbkdf2_hmac('sha256', initial_pwd.encode('utf-8'), salt, 600_000)
        db.create_admin('owner', key.hex(), salt.hex(), role='owner')
        print('[Owner Setup] Initial owner account created. Username: owner')

setup_default_owner()

def verify_pwd(password: str, stored_hash: str, stored_salt: str) -> bool:
    try:
        salt = bytes.fromhex(stored_salt)
        expected = bytes.fromhex(stored_hash)
        computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600_000)
        return secrets.compare_digest(computed, expected)
    except Exception:
        return False

# CSRF Protection
def generate_csrf_token() -> str:
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

@app.context_processor
def inject_globals():
    return {
        'csrf_token': generate_csrf_token,
        'current_admin': session.get('admin_user')
    }

@app.before_request
def csrf_and_auth_check():
    # Allow API endpoints and static assets without session CSRF
    if request.path.startswith('/api/') or request.path.startswith('/static/'):
        return None

    if request.method in ('POST', 'PUT', 'DELETE'):
        submitted = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        stored = session.get('csrf_token')
        if not submitted or not stored or not secrets.compare_digest(str(submitted), str(stored)):
            flash('Security check failed (CSRF expired). Please refresh.', 'error')
            abort(403)

    # Auth check for dashboard views
    if request.endpoint not in ('login', 'static') and not request.path.startswith('/api/'):
        if not session.get('admin_user'):
            return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method in ('GET', 'HEAD'):
        if session.get('admin_user'):
            return redirect(url_for('dashboard'))
        return render_template('login.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    admin = db.get_admin(username)

    if admin and verify_pwd(password, admin['password_hash'], admin['salt']):
        session['admin_user'] = {
            'id': admin['id'],
            'username': admin['username'],
            'role': admin['role']
        }
        session.permanent = True
        db.update_admin_login(admin['id'])
        flash('Welcome to Star Investigator License Control Center.', 'success')
        return redirect(url_for('dashboard'))

    flash('Invalid administrator credentials.', 'error')
    return render_template('login.html'), 401

@app.route('/logout')
def logout():
    session.clear()
    flash('Signed out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
def dashboard():
    metrics = db.get_dashboard_metrics()
    recent_licenses = db.list_licenses()[:6]
    recent_logs = db.get_activation_logs(limit=8)
    return render_template('dashboard.html', metrics=metrics, recent_licenses=recent_licenses, recent_logs=recent_logs)

@app.route('/generate', methods=['GET', 'POST'])
def generate_license():
    if request.method in ('GET', 'HEAD'):
        customers = db.list_customers()
        return render_template('generate.html', customers=customers)

    # Handle form submission
    customer_mode = request.form.get('customer_mode', 'existing')
    customer_id = None

    if customer_mode == 'new':
        cust_name = request.form.get('cust_name', '').strip()
        if not cust_name:
            flash('Customer name is required.', 'error')
            return redirect(url_for('generate_license'))
        customer_id = db.create_customer(
            name=cust_name,
            email=request.form.get('cust_email', ''),
            phone=request.form.get('cust_phone', ''),
            company=request.form.get('cust_company', ''),
            notes=request.form.get('cust_notes', '')
        )
    else:
        cid_val = request.form.get('existing_customer_id')
        if cid_val and cid_val.isdigit():
            customer_id = int(cid_val)

    license_type = request.form.get('license_type', 'Professional')
    device_selection = request.form.get('device_count', '1')
    if device_selection == 'custom':
        max_devices = int(request.form.get('custom_device_count', 1))
    else:
        max_devices = int(device_selection)

    duration_selection = request.form.get('duration', '30')
    is_permanent = (duration_selection == 'permanent')
    expiry_mode = 'on_first_activation'
    fixed_expiry_date = None
    duration_days = None

    if is_permanent:
        expiry_mode = 'permanent'
    elif duration_selection == 'custom_date':
        expiry_mode = 'fixed_date'
        fixed_expiry_date = request.form.get('custom_expiry_date')
    elif duration_selection == 'custom_days':
        duration_days = int(request.form.get('custom_days_val', 30))
        if request.form.get('start_timing') == 'today':
            expiry_mode = 'from_today'
        else:
            expiry_mode = 'on_first_activation'
    else:
        duration_days = int(duration_selection)
        if request.form.get('start_timing') == 'today':
            expiry_mode = 'from_today'
        else:
            expiry_mode = 'on_first_activation'

    notes = request.form.get('notes', '')

    new_lic = db.create_license(
        customer_id=customer_id,
        license_type=license_type,
        duration_days=duration_days,
        expiry_mode=expiry_mode,
        fixed_expiry_date=fixed_expiry_date,
        max_devices=max_devices,
        is_permanent=is_permanent,
        notes=notes
    )

    db.log_activation(
        license_key=new_lic['license_key'],
        license_id=new_lic['id'],
        event_type='generate',
        status='success',
        details=f"Generated {license_type} license with {max_devices} seats."
    )

    flash(f"License Key generated successfully: {new_lic['license_key']}", 'success')
    return redirect(url_for('licenses_list', highlight=new_lic['license_key']))

@app.route('/licenses')
def licenses_list():
    status_filter = request.args.get('status', 'all')
    search_term = request.args.get('search', '')
    licenses = db.list_licenses(status=status_filter, search=search_term)
    return render_template('licenses.html', licenses=licenses, status_filter=status_filter, search=search_term)

@app.route('/licenses/<int:lic_id>/status', methods=['POST'])
def change_license_status(lic_id: int):
    new_status = request.form.get('status')
    if new_status in ('active', 'suspended', 'revoked'):
        db.update_license_status(lic_id, new_status)
        lic = db.get_license_by_id(lic_id)
        db.log_activation(
            license_key=lic['license_key'] if lic else str(lic_id),
            license_id=lic_id,
            event_type=f'status_change_to_{new_status}',
            status='success',
            details=f"Admin set status to {new_status}"
        )
        flash(f"License status updated to {new_status.title()}.", 'success')
    return redirect(request.referrer or url_for('licenses_list'))

@app.route('/licenses/<int:lic_id>/renew', methods=['POST'])
def renew_license(lic_id: int):
    extra_days = int(request.form.get('extra_days', 30))
    custom_date = request.form.get('new_expiry_date')
    lic = db.renew_license(lic_id, extra_days=extra_days, new_expiry_date=custom_date if custom_date else None)
    db.log_activation(
        license_key=lic['license_key'],
        license_id=lic_id,
        event_type='renew',
        status='success',
        details=f"License renewed until {lic['expires_at']}"
    )
    flash(f"License renewed successfully. New Expiry: {lic['expires_at']}", 'success')
    return redirect(request.referrer or url_for('licenses_list'))

@app.route('/customers')
def customers_list():
    customers = db.list_customers()
    return render_template('customers.html', customers=customers)

@app.route('/devices')
def devices_list():
    devices = db.list_all_devices()
    return render_template('devices.html', devices=devices)

@app.route('/devices/<int:device_id>/deactivate', methods=['POST'])
def deactivate_device(device_id: int):
    reason = request.form.get('reason', 'Admin Transfer / Slot Reset')
    db.deactivate_device(device_id, reason=reason)
    flash('Device slot deactivated and reset. Seat is now available for new activation.', 'info')
    return redirect(request.referrer or url_for('devices_list'))

@app.route('/logs')
def logs():
    logs = db.get_activation_logs(limit=200)
    return render_template('logs.html', logs=logs)

@app.route('/security')
def security():
    events = db.get_security_events(limit=200)
    return render_template('security.html', events=events)

@app.route('/settings')
def settings():
    pub_pem = signer.get_public_key_pem()
    pub_b64 = signer.get_public_key_base64()
    return render_template('settings.html', pub_pem=pub_pem, pub_b64=pub_b64)

@app.route('/settings/backup/download')
def download_backup():
    db_path = DATA_DIR / 'licensing.db'
    if not db_path.exists():
        abort(404)
    return send_file(
        db_path,
        as_attachment=True,
        download_name=f"licensing_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db",
        mimetype='application/x-sqlite3'
    )

# =========================================================================
# PUBLIC REST APIs FOR CUSTOMER EDITION ACTIVATION & VALIDATION
# =========================================================================

def build_signed_entitlement(lic: dict, device_fingerprint: str) -> dict:
    now_iso = datetime.now(timezone.utc).isoformat()
    payload = {
        'license_key': lic['license_key'],
        'customer_name': lic.get('customer_name') or 'Valued Customer',
        'license_type': lic['license_type'],
        'device_fingerprint': device_fingerprint,
        'max_devices': lic['max_devices'],
        'status': lic['status'],
        'is_permanent': bool(lic['is_permanent']),
        'issued_at': now_iso,
        'expires_at': lic['expires_at'],
        'offline_grace_days': 14,
        'features': ['all_categories', 'full_ocr', 'pdf_reports', 'data_backup']
    }
    signature = signer.sign(payload)
    return {
        'entitlement': payload,
        'signature': signature,
        'server_time': now_iso
    }

@app.route('/api/v1/license/activate', methods=['POST'])
def api_activate():
    data = request.get_json(silent=True) or request.form.to_dict()
    key = (data.get('license_key') or '').strip().upper()
    fingerprint = (data.get('device_fingerprint') or '').strip()
    device_name = (data.get('device_name') or '').strip()
    os_version = (data.get('os_version') or '').strip()
    client_version = (data.get('client_version') or '1.0.0').strip()
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)

    if not key or not fingerprint:
        db.log_security_event('malformed_activation_request', severity='low', ip_address=ip_addr, details=f"Key: {key}, FP: {fingerprint}")
        return jsonify({'ok': False, 'error': 'Missing license key or device fingerprint.', 'code': 'BAD_REQUEST'}), 400

    lic = db.get_license_by_key(key)
    if not lic:
        db.log_activation(key, 'activate', 'denied', fingerprint, ip_addr, "License key not found.")
        return jsonify({'ok': False, 'error': 'Invalid License Key. Please check the key and try again.', 'code': 'INVALID_KEY'}), 404

    # Check status
    if lic['status'] == 'suspended':
        db.log_activation(key, 'activate', 'denied', fingerprint, ip_addr, "License is suspended.", license_id=lic['id'])
        return jsonify({'ok': False, 'error': 'This license is temporarily suspended. Please contact Star Investigators.', 'code': 'LICENSE_SUSPENDED'}), 403

    if lic['status'] == 'revoked':
        db.log_activation(key, 'activate', 'denied', fingerprint, ip_addr, "License is revoked.", license_id=lic['id'])
        return jsonify({'ok': False, 'error': 'This license has been revoked.', 'code': 'LICENSE_REVOKED'}), 403

    now = datetime.now(timezone.utc)

    # If first activation on on_first_activation mode, set first_activated_at and calculate expires_at
    if lic['expiry_mode'] == 'on_first_activation' and not lic['first_activated_at']:
        dur_days = lic['duration_days'] or 30
        first_act = now.isoformat()
        expires_at = (now + timedelta(days=dur_days)).isoformat()
        with db.get_conn() as c:
            c.execute('UPDATE licenses SET first_activated_at=?, expires_at=? WHERE id=?', (first_act, expires_at, lic['id']))
        lic = db.get_license_by_id(lic['id'])

    # Expiry Check
    if not lic['is_permanent'] and lic['expires_at']:
        try:
            exp_dt = datetime.fromisoformat(lic['expires_at'].replace('Z', '+00:00'))
            if now > exp_dt:
                db.update_license_status(lic['id'], 'expired')
                db.log_activation(key, 'activate', 'denied', fingerprint, ip_addr, "License has expired.", license_id=lic['id'])
                return jsonify({'ok': False, 'error': 'This license has expired. Please renew to continue.', 'code': 'LICENSE_EXPIRED'}), 403
        except Exception:
            pass

    # Device Allowance & Seat Enforcement (Thread-Safe Transaction)
    with _activation_lock:
        existing_devices = db.get_authorized_devices(lic['id'])
        is_already_registered = any(d['device_fingerprint'] == fingerprint and d['is_active'] == 1 for d in existing_devices)
        active_count = sum(1 for d in existing_devices if d['is_active'] == 1)

        if not is_already_registered:
            if active_count >= lic['max_devices']:
                msg = f"Maximum allowed devices ({lic['max_devices']}) reached for this license. Please contact the administrator to transfer device or upgrade seats."
                db.log_activation(key, 'activate', 'denied', fingerprint, ip_addr, msg, license_id=lic['id'])
                db.log_security_event('device_limit_exceeded', severity='medium', ip_address=ip_addr, details=f"License: {key}, Attempted FP: {fingerprint}, Seats: {lic['max_devices']}")
                return jsonify({'ok': False, 'error': msg, 'code': 'DEVICE_LIMIT_EXCEEDED', 'max_devices': lic['max_devices']}), 403

        # Register/Update device
        db.register_or_update_device(lic['id'], fingerprint, device_name, os_version, client_version)
        db.log_activation(key, 'activate', 'success', fingerprint, ip_addr, f"Activated on {device_name or fingerprint}", license_id=lic['id'])

    signed_data = build_signed_entitlement(lic, fingerprint)
    return jsonify({
        'ok': True,
        'message': 'License activated successfully.',
        'data': signed_data
    })

@app.route('/api/v1/license/validate', methods=['POST'])
def api_validate():
    data = request.get_json(silent=True) or request.form.to_dict()
    key = (data.get('license_key') or '').strip().upper()
    fingerprint = (data.get('device_fingerprint') or '').strip()
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)

    if not key or not fingerprint:
        return jsonify({'ok': False, 'error': 'Missing parameters.', 'code': 'BAD_REQUEST'}), 400

    lic = db.get_license_by_key(key)
    if not lic:
        return jsonify({'ok': False, 'error': 'License not found.', 'code': 'INVALID_KEY'}), 404

    # Check device authorization
    devices = db.get_authorized_devices(lic['id'])
    matched_device = next((d for d in devices if d['device_fingerprint'] == fingerprint), None)

    if not matched_device or matched_device['is_active'] != 1:
        return jsonify({
            'ok': False,
            'error': 'This device is no longer authorized for this license.',
            'code': 'DEVICE_DEACTIVATED'
        }), 403

    if lic['status'] in ('suspended', 'revoked'):
        return jsonify({
            'ok': False,
            'error': f"License is {lic['status']}.",
            'code': f"LICENSE_{lic['status'].upper()}"
        }), 403

    now = datetime.now(timezone.utc)
    if not lic['is_permanent'] and lic['expires_at']:
        exp_dt = datetime.fromisoformat(lic['expires_at'].replace('Z', '+00:00'))
        if now > exp_dt:
            db.update_license_status(lic['id'], 'expired')
            return jsonify({'ok': False, 'error': 'License expired.', 'code': 'LICENSE_EXPIRED'}), 403

    # Update last seen
    db.register_or_update_device(lic['id'], fingerprint)
    db.log_activation(key, 'validate', 'success', fingerprint, ip_addr, "Periodic validation OK", license_id=lic['id'])

    signed_data = build_signed_entitlement(lic, fingerprint)
    return jsonify({
        'ok': True,
        'message': 'License valid.',
        'data': signed_data
    })

@app.route('/api/v1/license/deactivate', methods=['POST'])
def api_deactivate():
    data = request.get_json(silent=True) or request.form.to_dict()
    key = (data.get('license_key') or '').strip().upper()
    fingerprint = (data.get('device_fingerprint') or '').strip()
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)

    lic = db.get_license_by_key(key)
    if not lic:
        return jsonify({'ok': False, 'error': 'License not found.'}), 404

    devices = db.get_authorized_devices(lic['id'])
    matched = next((d for d in devices if d['device_fingerprint'] == fingerprint and d['is_active'] == 1), None)
    if matched:
        db.deactivate_device(matched['id'], reason='Self-service transfer by client')
        db.log_activation(key, 'deactivate', 'success', fingerprint, ip_addr, "Client deactivated device", license_id=lic['id'])
        return jsonify({'ok': True, 'message': 'Device successfully deactivated and slot released.'})
    return jsonify({'ok': False, 'error': 'Device not found or already inactive.'}), 404

if __name__ == '__main__':
    port = int(os.environ.get('OWNER_PORT', 5050))
    print(f"\n=======================================================")
    print(f" STAR INVESTIGATOR — LICENSE CONTROL CENTER")
    print(f" Private Owner Dashboard running at: http://127.0.0.1:{port}")
    print(" Login username: owner | Password: configured at first setup")
    print(f"=======================================================\n")
    app.run(host='0.0.0.0', port=port, debug=False)
