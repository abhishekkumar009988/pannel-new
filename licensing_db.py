import sqlite3
import secrets
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

SAFE_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

def generate_key_chunk(length: int = 4) -> str:
    return ''.join(secrets.choice(SAFE_CHARSET) for _ in range(length))

def generate_license_key(license_type: str = 'Professional') -> str:
    """Generates human-readable, cryptographically random license key: STAR-PRO-XXXX-XXXX-XXXX-XXXX"""
    prefix_map = {
        'Trial': 'TRL',
        'Standard': 'STD',
        'Professional': 'PRO',
        'Enterprise': 'ENT'
    }
    type_code = prefix_map.get(license_type, 'PRO')
    c1 = generate_key_chunk(4)
    c2 = generate_key_chunk(4)
    c3 = generate_key_chunk(4)
    # 2-character checksum from SHA-256 of the body
    raw = f"STAR-{type_code}-{c1}-{c2}-{c3}".encode('utf-8')
    digest = hashlib.sha256(raw).hexdigest().upper()
    c4 = digest[:2] + generate_key_chunk(2)
    return f"STAR-{type_code}-{c1}-{c2}-{c3}-{c4}"

class LicensingDB:
    """Database repository for License Control Center."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=15.0)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('PRAGMA busy_timeout=15000')
        return con

    def init_db(self):
        with self.get_conn() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'owner',
                created_at TEXT NOT NULL,
                last_login TEXT
            );

            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                company TEXT,
                notes TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                customer_id INTEGER,
                license_type TEXT NOT NULL DEFAULT 'Professional',
                duration_days INTEGER,
                expiry_mode TEXT NOT NULL DEFAULT 'on_first_activation',
                fixed_expiry_date TEXT,
                max_devices INTEGER NOT NULL DEFAULT 1,
                is_permanent INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                first_activated_at TEXT,
                expires_at TEXT,
                notes TEXT,
                FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS authorized_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id INTEGER NOT NULL,
                device_fingerprint TEXT NOT NULL,
                device_name TEXT,
                os_version TEXT,
                client_version TEXT,
                first_activated_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                deactivation_reason TEXT,
                FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE,
                UNIQUE(license_id, device_fingerprint)
            );

            CREATE TABLE IF NOT EXISTS activation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id INTEGER,
                license_key TEXT NOT NULL,
                device_fingerprint TEXT,
                ip_address TEXT,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity TEXT NOT NULL DEFAULT 'medium',
                event_type TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_lic_key ON licenses(license_key);
            CREATE INDEX IF NOT EXISTS idx_dev_lic ON authorized_devices(license_id);
            CREATE INDEX IF NOT EXISTS idx_dev_fingerprint ON authorized_devices(device_fingerprint);
            ''')

    # Admin Management
    def create_admin(self, username: str, password_hash: str, salt: str, role: str = 'owner') -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.get_conn() as c:
            cur = c.execute(
                'INSERT INTO admins (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)',
                (username, password_hash, salt, role, now)
            )
            return cur.lastrowid

    def get_admin(self, username: str) -> Optional[Dict[str, Any]]:
        with self.get_conn() as c:
            row = c.execute('SELECT * FROM admins WHERE username=?', (username,)).fetchone()
            return dict(row) if row else None

    def update_admin_login(self, admin_id: int):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_conn() as c:
            c.execute('UPDATE admins SET last_login=? WHERE id=?', (now, admin_id))

    # Customer Management
    def create_customer(self, name: str, email: str = '', phone: str = '', company: str = '', notes: str = '') -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.get_conn() as c:
            cur = c.execute(
                'INSERT INTO customers (name, email, phone, company, notes, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (name.strip(), email.strip(), phone.strip(), company.strip(), notes.strip(), now)
            )
            return cur.lastrowid

    def get_customer(self, customer_id: int) -> Optional[Dict[str, Any]]:
        with self.get_conn() as c:
            row = c.execute('SELECT * FROM customers WHERE id=?', (customer_id,)).fetchone()
            return dict(row) if row else None

    def list_customers(self) -> List[Dict[str, Any]]:
        with self.get_conn() as c:
            rows = c.execute('''
                SELECT c.*, COUNT(l.id) as license_count
                FROM customers c
                LEFT JOIN licenses l ON c.id = l.customer_id
                GROUP BY c.id
                ORDER BY c.created_at DESC
            ''').fetchall()
            return [dict(r) for r in rows]

    # License Management
    def create_license(
        self,
        customer_id: Optional[int],
        license_type: str = 'Professional',
        duration_days: Optional[int] = 30,
        expiry_mode: str = 'on_first_activation',
        fixed_expiry_date: Optional[str] = None,
        max_devices: int = 1,
        is_permanent: bool = False,
        notes: str = ''
    ) -> Dict[str, Any]:
        license_key = generate_license_key(license_type)
        now = datetime.now(timezone.utc).isoformat()
        expires_at = None

        if is_permanent:
            expiry_mode = 'permanent'
            expires_at = None
        elif expiry_mode == 'fixed_date' and fixed_expiry_date:
            expires_at = fixed_expiry_date
        elif expiry_mode == 'from_today' and duration_days:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=duration_days)).isoformat()

        with self.get_conn() as c:
            cur = c.execute('''
                INSERT INTO licenses (
                    license_key, customer_id, license_type, duration_days, expiry_mode,
                    fixed_expiry_date, max_devices, is_permanent, status, created_at,
                    first_activated_at, expires_at, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
            ''', (
                license_key, customer_id, license_type, duration_days, expiry_mode,
                fixed_expiry_date, max_devices, 1 if is_permanent else 0, now,
                now if expiry_mode == 'from_today' else None,
                expires_at, notes
            ))
            lic_id = cur.lastrowid
            row = c.execute('SELECT * FROM licenses WHERE id=?', (lic_id,)).fetchone()
            return dict(row)

    def get_license_by_key(self, key: str) -> Optional[Dict[str, Any]]:
        with self.get_conn() as c:
            row = c.execute('''
                SELECT l.*, c.name as customer_name, c.email as customer_email, c.company as customer_company
                FROM licenses l
                LEFT JOIN customers c ON l.customer_id = c.id
                WHERE l.license_key=?
            ''', (key.strip(),)).fetchone()
            return dict(row) if row else None

    def get_license_by_id(self, lic_id: int) -> Optional[Dict[str, Any]]:
        with self.get_conn() as c:
            row = c.execute('''
                SELECT l.*, c.name as customer_name, c.email as customer_email, c.company as customer_company
                FROM licenses l
                LEFT JOIN customers c ON l.customer_id = c.id
                WHERE l.id=?
            ''', (lic_id,)).fetchone()
            return dict(row) if row else None

    def list_licenses(self, status: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        query = '''
            SELECT l.*, c.name as customer_name, c.email as customer_email,
                   (SELECT COUNT(*) FROM authorized_devices d WHERE d.license_id = l.id AND d.is_active = 1) as active_device_count
            FROM licenses l
            LEFT JOIN customers c ON l.customer_id = c.id
            WHERE 1=1
        '''
        params = []
        if status and status != 'all':
            query += ' AND l.status = ?'
            params.append(status)
        if search:
            query += ' AND (l.license_key LIKE ? OR c.name LIKE ? OR c.email LIKE ? OR l.notes LIKE ?)'
            term = f"%{search.strip()}%"
            params.extend([term, term, term, term])
        query += ' ORDER BY l.created_at DESC'

        with self.get_conn() as c:
            rows = c.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def update_license_status(self, lic_id: int, status: str, notes: Optional[str] = None):
        with self.get_conn() as c:
            if notes is not None:
                c.execute('UPDATE licenses SET status=?, notes=? WHERE id=?', (status, notes, lic_id))
            else:
                c.execute('UPDATE licenses SET status=? WHERE id=?', (status, lic_id))

    def renew_license(self, lic_id: int, extra_days: int = 30, new_expiry_date: Optional[str] = None) -> Dict[str, Any]:
        """Extends or renews a license without changing the key or deleting customer data."""
        lic = self.get_license_by_id(lic_id)
        if not lic:
            raise ValueError("License not found")

        now = datetime.now(timezone.utc)
        if new_expiry_date:
            calculated_expiry = new_expiry_date
        else:
            base_date = now
            if lic['expires_at']:
                try:
                    exp = datetime.fromisoformat(lic['expires_at'].replace('Z', '+00:00'))
                    if exp > now:
                        base_date = exp
                except Exception:
                    pass
            calculated_expiry = (base_date + timedelta(days=extra_days)).isoformat()

        with self.get_conn() as c:
            c.execute('''
                UPDATE licenses
                SET status='active', expires_at=?, duration_days = COALESCE(duration_days, 0) + ?
                WHERE id=?
            ''', (calculated_expiry, extra_days, lic_id))
        return self.get_license_by_id(lic_id)

    # Device Management
    def get_authorized_devices(self, license_id: int) -> List[Dict[str, Any]]:
        with self.get_conn() as c:
            rows = c.execute(
                'SELECT * FROM authorized_devices WHERE license_id=? ORDER BY first_activated_at ASC',
                (license_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def list_all_devices(self) -> List[Dict[str, Any]]:
        with self.get_conn() as c:
            rows = c.execute('''
                SELECT d.*, l.license_key, l.license_type, l.status as license_status, c.name as customer_name
                FROM authorized_devices d
                JOIN licenses l ON d.license_id = l.id
                LEFT JOIN customers c ON l.customer_id = c.id
                ORDER BY d.last_seen_at DESC
            ''').fetchall()
            return [dict(r) for r in rows]

    def register_or_update_device(
        self,
        license_id: int,
        fingerprint: str,
        device_name: str = '',
        os_version: str = '',
        client_version: str = ''
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self.get_conn() as c:
            dev = c.execute(
                'SELECT * FROM authorized_devices WHERE license_id=? AND device_fingerprint=?',
                (license_id, fingerprint)
            ).fetchone()

            if dev:
                c.execute('''
                    UPDATE authorized_devices
                    SET last_seen_at=?, is_active=1, device_name=COALESCE(NULLIF(?, ''), device_name),
                        os_version=COALESCE(NULLIF(?, ''), os_version),
                        client_version=COALESCE(NULLIF(?, ''), client_version)
                    WHERE id=?
                ''', (now, device_name, os_version, client_version, dev['id']))
                row = c.execute('SELECT * FROM authorized_devices WHERE id=?', (dev['id'],)).fetchone()
                return dict(row)
            else:
                cur = c.execute('''
                    INSERT INTO authorized_devices (
                        license_id, device_fingerprint, device_name, os_version,
                        client_version, first_activated_at, last_seen_at, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ''', (license_id, fingerprint, device_name, os_version, client_version, now, now))
                row = c.execute('SELECT * FROM authorized_devices WHERE id=?', (cur.lastrowid,)).fetchone()
                return dict(row)

    def deactivate_device(self, device_id: int, reason: str = 'Admin Transfer/Reset'):
        with self.get_conn() as c:
            c.execute(
                'UPDATE authorized_devices SET is_active=0, deactivation_reason=? WHERE id=?',
                (reason, device_id)
            )

    # Logging and Audit
    def log_activation(
        self,
        license_key: str,
        event_type: str,
        status: str,
        device_fingerprint: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[str] = None,
        license_id: Optional[int] = None
    ):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_conn() as c:
            c.execute('''
                INSERT INTO activation_logs (
                    license_id, license_key, device_fingerprint, ip_address,
                    event_type, status, details, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (license_id, license_key, device_fingerprint, ip_address, event_type, status, details, now))

    def log_security_event(self, event_type: str, severity: str = 'medium', ip_address: Optional[str] = None, details: Optional[str] = None):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_conn() as c:
            c.execute('''
                INSERT INTO security_events (severity, event_type, ip_address, details, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (severity, event_type, ip_address, details, now))

    def get_activation_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_conn() as c:
            rows = c.execute(
                'SELECT * FROM activation_logs ORDER BY created_at DESC LIMIT ?',
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_conn() as c:
            rows = c.execute(
                'SELECT * FROM security_events ORDER BY created_at DESC LIMIT ?',
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # Dashboard Metrics
    def get_dashboard_metrics(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        now_str = now.isoformat()
        soon_str = (now + timedelta(days=7)).isoformat()
        today_start_str = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

        with self.get_conn() as c:
            total_licenses = c.execute('SELECT COUNT(*) FROM licenses').fetchone()[0]
            active_licenses = c.execute("SELECT COUNT(*) FROM licenses WHERE status='active' AND (is_permanent=1 OR expires_at > ?)", (now_str,)).fetchone()[0]
            expired_licenses = c.execute("SELECT COUNT(*) FROM licenses WHERE status='expired' OR (is_permanent=0 AND expires_at <= ?)", (now_str,)).fetchone()[0]
            suspended_licenses = c.execute("SELECT COUNT(*) FROM licenses WHERE status='suspended'").fetchone()[0]
            revoked_licenses = c.execute("SELECT COUNT(*) FROM licenses WHERE status='revoked'").fetchone()[0]
            active_devices = c.execute('SELECT COUNT(*) FROM authorized_devices WHERE is_active=1').fetchone()[0]
            activations_today = c.execute("SELECT COUNT(*) FROM activation_logs WHERE event_type='activate' AND status='success' AND created_at >= ?", (today_start_str,)).fetchone()[0]
            expiring_soon = c.execute("SELECT COUNT(*) FROM licenses WHERE status='active' AND is_permanent=0 AND expires_at > ? AND expires_at <= ?", (now_str, soon_str)).fetchone()[0]

            return {
                'total_licenses': total_licenses,
                'active_licenses': active_licenses,
                'expired_licenses': expired_licenses,
                'suspended_licenses': suspended_licenses,
                'revoked_licenses': revoked_licenses,
                'active_devices': active_devices,
                'activations_today': activations_today,
                'expiring_soon': expiring_soon
            }
