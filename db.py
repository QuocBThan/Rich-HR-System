"""SQLite database layer for Attendance Management System."""
import sqlite3
from contextlib import contextmanager

DB_PATH = 'attendance.db'


def init_db():
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT DEFAULT '',
                role         TEXT DEFAULT 'viewer',
                department   TEXT DEFAULT '',
                employee_id  TEXT DEFAULT '',
                created_at   TEXT DEFAULT (datetime('now','localtime'))
            );

            CREATE TABLE IF NOT EXISTS employees (
                id               TEXT PRIMARY KEY,
                name             TEXT NOT NULL,
                role             TEXT DEFAULT '',
                department       TEXT DEFAULT '',
                start_time       TEXT DEFAULT '09:30',
                end_time         TEXT DEFAULT '18:30',
                break_hrs        REAL DEFAULT 1.0,
                max_hrs_day      REAL DEFAULT 8.0,
                work_days        TEXT DEFAULT '0,1,2,3,4',
                employment_type  TEXT DEFAULT 'full_time'
            );

            CREATE TABLE IF NOT EXISTS employee_aliases (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                lark_name   TEXT NOT NULL UNIQUE,
                employee_id TEXT NOT NULL,
                notes       TEXT DEFAULT '',
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER DEFAULT 0,
                username    TEXT DEFAULT '',
                action      TEXT NOT NULL,
                details     TEXT DEFAULT '',
                ip_address  TEXT DEFAULT '',
                created_at  TEXT DEFAULT (datetime('now','localtime'))
            );

            CREATE TABLE IF NOT EXISTS export_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT NOT NULL,
                filepath    TEXT NOT NULL,
                export_type TEXT DEFAULT '',
                date_from   TEXT DEFAULT '',
                date_to     TEXT DEFAULT '',
                exported_by TEXT DEFAULT '',
                file_size   INTEGER DEFAULT 0,
                created_at  TEXT DEFAULT (datetime('now','localtime'))
            );

            CREATE TABLE IF NOT EXISTS tickets (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id     TEXT NOT NULL UNIQUE,
                type          TEXT NOT NULL,
                employee_id   TEXT NOT NULL,
                employee_name TEXT DEFAULT '',
                leave_date    TEXT NOT NULL,
                leave_date_to TEXT DEFAULT '',
                days_count    INTEGER DEFAULT 1,
                reason        TEXT DEFAULT '',
                expected_time TEXT DEFAULT '',
                approved_by   TEXT DEFAULT '',
                created_at    TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS attendance (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                date          TEXT NOT NULL,
                employee_id   TEXT DEFAULT '',
                employee_name TEXT DEFAULT '',
                lark_name     TEXT DEFAULT '',
                department    TEXT DEFAULT '',
                role          TEXT DEFAULT '',
                clock_in      TEXT DEFAULT '',
                clock_out     TEXT DEFAULT '',
                actual_hrs    REAL,
                break_hrs     REAL DEFAULT 1.0,
                net_hrs       REAL,
                paid_hrs      REAL,
                status        TEXT DEFAULT '',
                notes         TEXT DEFAULT '',
                action_taken  TEXT DEFAULT '',
                approved_by   TEXT DEFAULT '',
                approved_at   TEXT DEFAULT '',
                created_at    TEXT DEFAULT (datetime('now', 'localtime')),
                UNIQUE(date, lark_name)
            );
        ''')
        # Migrations: add columns to existing databases
        existing = [r[1] for r in conn.execute("PRAGMA table_info(employees)").fetchall()]
        if 'work_days' not in existing:
            conn.execute("ALTER TABLE employees ADD COLUMN work_days TEXT DEFAULT '0,1,2,3,4'")
        if 'employment_type' not in existing:
            conn.execute("ALTER TABLE employees ADD COLUMN employment_type TEXT DEFAULT 'full_time'")
        user_cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if 'employee_id' not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN employee_id TEXT DEFAULT ''")

        user_cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if 'must_change_password' not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0")
        ticket_cols = [r[1] for r in conn.execute("PRAGMA table_info(tickets)").fetchall()]
        if 'leave_date_to' not in ticket_cols:
            conn.execute("ALTER TABLE tickets ADD COLUMN leave_date_to TEXT DEFAULT ''")
        if 'days_count' not in ticket_cols:
            conn.execute("ALTER TABLE tickets ADD COLUMN days_count INTEGER DEFAULT 1")
        user_cols2 = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if 'email' not in user_cols2:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
        conn.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token      TEXT NOT NULL UNIQUE,
                username   TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used       INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            )
        ''')
        emp_cols2 = [r[1] for r in conn.execute("PRAGMA table_info(employees)").fetchall()]
        if 'lark_user_id' not in emp_cols2:
            conn.execute("ALTER TABLE employees ADD COLUMN lark_user_id TEXT DEFAULT ''")
        conn.execute('''
            CREATE TABLE IF NOT EXISTS lark_sync_logs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                triggered_by  TEXT DEFAULT 'manual',
                date_from     TEXT DEFAULT '',
                date_to       TEXT DEFAULT '',
                records_count INTEGER DEFAULT 0,
                log_text      TEXT DEFAULT '',
                status        TEXT DEFAULT 'ok',
                created_at    TEXT DEFAULT (datetime('now','localtime'))
            )
        ''')

        # ── DELIVERY DEPARTMENT ───────────────────────────────────────
        # Inventory of machines/terminals — new & used stock.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS delivery_inventory (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_no   TEXT NOT NULL UNIQUE,
                model       TEXT DEFAULT '',
                condition   TEXT DEFAULT 'new',        -- 'new' | 'used'
                status      TEXT DEFAULT 'in_stock',   -- in_stock | assigned | delivered | returned | retired
                notes       TEXT DEFAULT '',
                created_at  TEXT DEFAULT (datetime('now','localtime'))
            )
        ''')
        # Delivery jobs — customer, assigned machine, location/time log, returns.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS deliveries (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_code     TEXT NOT NULL UNIQUE,
                customer_name     TEXT NOT NULL,
                customer_email    TEXT DEFAULT '',
                customer_phone    TEXT DEFAULT '',
                customer_address  TEXT DEFAULT '',
                machine_serial    TEXT DEFAULT '',
                machine_model     TEXT DEFAULT '',
                machine_condition TEXT DEFAULT '',
                status            TEXT DEFAULT 'scheduled',  -- scheduled | en_route | delivered | returned
                scheduled_date    TEXT DEFAULT '',
                depart_time       TEXT DEFAULT '',
                arrive_time       TEXT DEFAULT '',
                setup_time        TEXT DEFAULT '',
                location          TEXT DEFAULT '',
                assigned_to       TEXT DEFAULT '',
                label_sent        INTEGER DEFAULT 0,
                label_sent_at     TEXT DEFAULT '',
                returned_at       TEXT DEFAULT '',
                return_reason     TEXT DEFAULT '',
                notes             TEXT DEFAULT '',
                created_at        TEXT DEFAULT (datetime('now','localtime'))
            )
        ''')


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ------------------------------------------------------------------ #
# EMPLOYEES
# ------------------------------------------------------------------ #

def get_all_employees():
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM employees ORDER BY name').fetchall()
        return [dict(r) for r in rows]


def save_employee(data):
    with get_db() as conn:
        conn.execute('''
            INSERT OR REPLACE INTO employees
                (id, name, role, department, start_time, end_time, break_hrs, max_hrs_day, work_days, employment_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['id'], data['name'],
            data.get('role', ''), data.get('department', ''),
            data.get('start_time', '09:00'), data.get('end_time', '18:00'),
            float(data.get('break_hrs', 1.0)), float(data.get('max_hrs_day', 8.0)),
            data.get('work_days', '0,1,2,3,4'),
            data.get('employment_type', 'full_time'),
        ))


def delete_employee(emp_id):
    with get_db() as conn:
        conn.execute('DELETE FROM employees WHERE id = ?', (emp_id,))


def sync_all_from_employees():
    """Overwrite name/department/role in all attendance rows using the employees table."""
    with get_db() as conn:
        cur = conn.execute('''
            UPDATE attendance
            SET employee_name = (SELECT name       FROM employees WHERE employees.id = attendance.employee_id),
                department    = (SELECT department  FROM employees WHERE employees.id = attendance.employee_id),
                role          = (SELECT role        FROM employees WHERE employees.id = attendance.employee_id)
            WHERE employee_id != '' AND employee_id IS NOT NULL
              AND EXISTS (SELECT 1 FROM employees WHERE employees.id = attendance.employee_id)
        ''')
        return cur.rowcount


def sync_attendance_employee_info(emp_id, name, department, role):
    """Sync name/dept/role to all existing attendance records for this employee."""
    with get_db() as conn:
        conn.execute('''
            UPDATE attendance
            SET employee_name=?, department=?, role=?
            WHERE employee_id=?
        ''', (name, department, role, emp_id))


# ------------------------------------------------------------------ #
# ALIASES
# ------------------------------------------------------------------ #

def get_all_aliases():
    with get_db() as conn:
        rows = conn.execute('''
            SELECT a.*, e.name AS employee_name
            FROM employee_aliases a
            LEFT JOIN employees e ON a.employee_id = e.id
            ORDER BY a.employee_id, a.lark_name
        ''').fetchall()
        return [dict(r) for r in rows]


def save_alias(lark_name, employee_id, notes=''):
    with get_db() as conn:
        conn.execute('''
            INSERT OR REPLACE INTO employee_aliases (lark_name, employee_id, notes)
            VALUES (?, ?, ?)
        ''', (lark_name.strip(), employee_id.strip(), notes))


def delete_alias(alias_id):
    with get_db() as conn:
        conn.execute('DELETE FROM employee_aliases WHERE id = ?', (alias_id,))


# ------------------------------------------------------------------ #
# ATTENDANCE
# ------------------------------------------------------------------ #

def save_attendance_batch(records):
    with get_db() as conn:
        for r in records:
            conn.execute('''
                INSERT OR REPLACE INTO attendance
                    (date, employee_id, employee_name, lark_name, department, role,
                     clock_in, clock_out, actual_hrs, break_hrs, net_hrs, paid_hrs,
                     status, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                r['date'], r['employee_id'], r['employee_name'], r['lark_name'],
                r['department'], r['role'], r['clock_in'], r['clock_out'],
                r['actual_hrs'], r['break_hrs'], r['net_hrs'], r['paid_hrs'],
                r['status'], r['notes'],
            ))


def get_attendance(filters=None):
    filters = filters or {}
    where, params = [], []

    if filters.get('month'):
        where.append("date LIKE ?")
        params.append(filters['month'] + '%')

    if filters.get('employee_id'):
        where.append('employee_id = ?')
        params.append(filters['employee_id'])

    if filters.get('status'):
        where.append('status = ?')
        params.append(filters['status'])

    if filters.get('period') == '1':
        where.append("substr(date,9,2) <= '15'")
    elif filters.get('period') == '2':
        where.append("substr(date,9,2) >= '16'")

    if filters.get('weekday_only'):
        where.append("strftime('%w', date) NOT IN ('0', '6')")

    sql = 'SELECT * FROM attendance'
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    sql += ' ORDER BY date DESC, employee_name'

    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def get_review_queue(filters=None):
    filters     = filters or {}
    where_parts = ["status != '✅ OK'"]
    params      = []

    if filters.get('month'):
        where_parts.append('date LIKE ?')
        params.append(filters['month'] + '%')

    if filters.get('employee_id'):
        where_parts.append('employee_id = ?')
        params.append(filters['employee_id'])

    if filters.get('period') == '1':
        where_parts.append("substr(date,9,2) <= '15'")
    elif filters.get('period') == '2':
        where_parts.append("substr(date,9,2) >= '16'")

    where = ' AND '.join(where_parts)
    with get_db() as conn:
        rows = conn.execute(f"""
            SELECT * FROM attendance
            WHERE {where}
            ORDER BY
                CASE
                    WHEN status LIKE '%Not Matched%' THEN 1
                    WHEN status LIKE '%Missing%'     THEN 2
                    WHEN status LIKE '%Under%'       THEN 3
                    WHEN status LIKE '%Overtime%'    THEN 4
                    ELSE 5
                END,
                date DESC
        """, params).fetchall()
        return [dict(r) for r in rows]


def get_review_count():
    """Count of records that are non-OK and have NOT yet been actioned (for sidebar badge)."""
    with get_db() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM attendance WHERE status != '✅ OK' AND (action_taken = '' OR action_taken IS NULL)"
        ).fetchone()['c']


def get_attendance_by_id(att_id):
    with get_db() as conn:
        row = conn.execute('SELECT * FROM attendance WHERE id=?', (att_id,)).fetchone()
        return dict(row) if row else None


def get_employee_by_id(emp_id):
    with get_db() as conn:
        row = conn.execute('SELECT * FROM employees WHERE id=?', (emp_id,)).fetchone()
        return dict(row) if row else None


def save_clock_out_correction(att_id, clock_out, calc, notes, action_taken, approved_by):
    with get_db() as conn:
        conn.execute('''
            UPDATE attendance
            SET clock_out=?, actual_hrs=?, net_hrs=?, paid_hrs=?, status=?, notes=?,
                action_taken=?, approved_by=?, approved_at=datetime('now','localtime')
            WHERE id=?
        ''', (
            clock_out, calc['actual_hrs'], calc['net_hrs'], calc['paid_hrs'],
            calc['status'], notes, action_taken, approved_by, att_id,
        ))


def update_review(att_id, action_taken, approved_by, paid_hrs=None):
    with get_db() as conn:
        if paid_hrs is not None:
            conn.execute('''
                UPDATE attendance
                SET action_taken=?, approved_by=?, approved_at=datetime('now','localtime'), paid_hrs=?
                WHERE id=?
            ''', (action_taken, approved_by, paid_hrs, att_id))
        else:
            conn.execute('''
                UPDATE attendance
                SET action_taken=?, approved_by=?, approved_at=datetime('now','localtime')
                WHERE id=?
            ''', (action_taken, approved_by, att_id))


def delete_attendance(month=None, period=None):
    """Delete attendance records. month='YYYY-MM', period='1'|'2'|None."""
    where, params = [], []
    if month:
        where.append('date LIKE ?')
        params.append(month + '%')
    if period == '1':
        where.append("substr(date,9,2) <= '15'")
    elif period == '2':
        where.append("substr(date,9,2) >= '16'")
    sql = 'DELETE FROM attendance'
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    with get_db() as conn:
        cur = conn.execute(sql, params)
        return cur.rowcount


def delete_attendance_by_id(att_id):
    with get_db() as conn:
        conn.execute('DELETE FROM attendance WHERE id=?', (att_id,))


def delete_all_attendance():
    with get_db() as conn:
        cur = conn.execute('DELETE FROM attendance')
        return cur.rowcount


def get_distinct_months():
    """Returns list of 'YYYY-MM' strings that have data, newest first."""
    with get_db() as conn:
        rows = conn.execute('''
            SELECT DISTINCT substr(date, 1, 7) AS m
            FROM attendance
            ORDER BY m DESC
        ''').fetchall()
        return [r['m'] for r in rows]


def get_monthly_report(from_date=None, to_date=None):
    where, params = [], []
    if from_date:
        where.append('date >= ?'); params.append(from_date)
    if to_date:
        where.append('date <= ?'); params.append(to_date)
    w = ('WHERE ' + ' AND '.join(where)) if where else ''

    with get_db() as conn:
        rows = conn.execute(f'''
            SELECT
                employee_id, employee_name, department, role,
                COUNT(*)                                                                            AS total_days,
                COUNT(CASE WHEN status NOT LIKE '%Not Matched%'
                            AND status NOT LIKE '%Manual%'        THEN 1 END)                      AS present_days,
                ROUND(SUM(COALESCE(paid_hrs, 0)), 2)                                               AS total_paid_hrs,
                COUNT(CASE WHEN status LIKE '%Overtime%'
                            OR  status LIKE '%After 20%'          THEN 1 END)                      AS overtime_days,
                COUNT(CASE WHEN status LIKE '%Under Hours%'       THEN 1 END)                      AS under_hrs_days,
                COUNT(CASE WHEN status LIKE '%Missing Clock In%'  THEN 1 END)                      AS missing_in_days,
                COUNT(CASE WHEN status LIKE '%Missing Clock Out%' THEN 1 END)                      AS missing_out_days,
                COUNT(CASE WHEN status LIKE '%Late Clock In%'     THEN 1 END)                      AS late_in_days,
                COUNT(CASE WHEN action_taken LIKE '%Nghỉ không phép%'                THEN 1 END)   AS absent_unpaid_days,
                COUNT(CASE WHEN action_taken LIKE '%Nghỉ phép năm%'
                            OR  action_taken LIKE '%Nghỉ có phép%'               THEN 1 END)       AS absent_paid_days,
                COUNT(CASE WHEN status != '✅ OK'
                            AND (action_taken = '' OR action_taken IS NULL)       THEN 1 END)       AS unresolved_count
            FROM attendance
            {w}
            GROUP BY employee_id, employee_name
            ORDER BY employee_name
        ''', params).fetchall()
        return [dict(r) for r in rows]


def get_employee_report_detail(employee_id, from_date=None, to_date=None):
    """All non-OK records for one employee in a date range."""
    where = ["employee_id = ?", "status != '✅ OK'"]
    params = [employee_id]
    if from_date:
        where.append('date >= ?'); params.append(from_date)
    if to_date:
        where.append('date <= ?'); params.append(to_date)
    with get_db() as conn:
        rows = conn.execute(
            'SELECT * FROM attendance WHERE ' + ' AND '.join(where) + ' ORDER BY date',
            params
        ).fetchall()
        return [dict(r) for r in rows]


# ------------------------------------------------------------------ #
# USERS / AUTH
# ------------------------------------------------------------------ #

def get_user_by_username(username):
    with get_db() as conn:
        row = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        return dict(row) if row else None


def get_all_users():
    with get_db() as conn:
        rows = conn.execute(
            'SELECT id,username,display_name,role,department,employee_id,email,created_at FROM users ORDER BY username'
        ).fetchall()
        return [dict(r) for r in rows]


def get_user_by_email(email):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE LOWER(email)=LOWER(?)", (email.strip(),)
        ).fetchone()
        return dict(row) if row else None


def update_user_email(user_id, email):
    with get_db() as conn:
        conn.execute('UPDATE users SET email=? WHERE id=?', (email.strip(), user_id))


def create_user(username, password_hash, display_name='', role='viewer', department='',
                must_change_password=1, employee_id=''):
    with get_db() as conn:
        conn.execute('''
            INSERT INTO users (username, password_hash, display_name, role, department, must_change_password, employee_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username.strip(), password_hash, display_name.strip(), role,
              department.strip(), must_change_password, employee_id.strip()))


def update_user_password(user_id, password_hash):
    with get_db() as conn:
        conn.execute(
            'UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?',
            (password_hash, user_id)
        )


def create_reset_token(token, username, expires_at):
    with get_db() as conn:
        conn.execute('DELETE FROM password_reset_tokens WHERE username=? AND used=0', (username,))
        conn.execute(
            'INSERT INTO password_reset_tokens (token, username, expires_at) VALUES (?,?,?)',
            (token, username, expires_at)
        )


def get_reset_token(token):
    with get_db() as conn:
        row = conn.execute(
            'SELECT * FROM password_reset_tokens WHERE token=? AND used=0', (token,)
        ).fetchone()
        return dict(row) if row else None


def consume_reset_token(token):
    with get_db() as conn:
        conn.execute('UPDATE password_reset_tokens SET used=1 WHERE token=?', (token,))


def delete_user(user_id):
    with get_db() as conn:
        conn.execute('DELETE FROM users WHERE id=?', (user_id,))


def count_users():
    with get_db() as conn:
        return conn.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']


def get_export_preview(filters=None):
    """Return per-employee summary + unresolved list for export review page."""
    filters = filters or {}
    where, params = [], []

    if filters.get('month'):
        where.append('date LIKE ?')
        params.append(filters['month'] + '%')
    if filters.get('employee_id'):
        where.append('employee_id = ?')
        params.append(filters['employee_id'])
    if filters.get('period') == '1':
        where.append("substr(date,9,2) <= '15'")
    elif filters.get('period') == '2':
        where.append("substr(date,9,2) >= '16'")

    base_where   = ('WHERE ' + ' AND '.join(where)) if where else ''
    unres_extra  = "status != '✅ OK' AND (action_taken = '' OR action_taken IS NULL)"
    unres_where  = (base_where + ' AND ' + unres_extra) if base_where else ('WHERE ' + unres_extra)

    with get_db() as conn:
        summary = conn.execute(f'''
            SELECT
                employee_id, employee_name, department, role,
                COUNT(*)                                                                          AS total_days,
                COUNT(CASE WHEN clock_in != '' AND clock_out != '' THEN 1 END)                   AS days_complete,
                COUNT(CASE WHEN status LIKE '%Missing%'                THEN 1 END)               AS days_missing,
                COUNT(CASE WHEN status LIKE '%Overtime%'
                            OR  status LIKE '%After 20%'               THEN 1 END)               AS overtime_days,
                COUNT(CASE WHEN status LIKE '%Under Hours%'            THEN 1 END)               AS under_hrs_days,
                COUNT(CASE WHEN status LIKE '%Late Clock In%'          THEN 1 END)               AS late_in_days,
                COUNT(CASE WHEN status LIKE '%Manual%'                 THEN 1 END)               AS manual_days,
                COUNT(CASE WHEN status != '✅ OK'
                            AND (action_taken = '' OR action_taken IS NULL) THEN 1 END)          AS unresolved,
                ROUND(SUM(COALESCE(paid_hrs, 0)), 2)                                             AS total_paid_hrs
            FROM attendance
            {base_where}
            GROUP BY employee_id, employee_name
            ORDER BY employee_name
        ''', params).fetchall()

        unresolved = conn.execute(f'''
            SELECT id, date, employee_name, status, clock_in, clock_out, notes, action_taken
            FROM attendance
            {unres_where}
            ORDER BY date DESC, employee_name
        ''', params).fetchall()

        total_paid = conn.execute(
            f'SELECT ROUND(SUM(COALESCE(paid_hrs,0)),2) AS t FROM attendance {base_where}', params
        ).fetchone()['t'] or 0

        return {
            'summary':    [dict(r) for r in summary],
            'unresolved': [dict(r) for r in unresolved],
            'total_paid': total_paid,
        }


# ------------------------------------------------------------------ #
# AUDIT LOG
# ------------------------------------------------------------------ #

def log_audit(user_id, username, action, details='', ip=''):
    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO audit_log (user_id, username, action, details, ip_address) VALUES (?,?,?,?,?)',
                (user_id or 0, username or '', action, details or '', ip or ''),
            )
    except Exception:
        pass  # Never let audit log failure break the main flow


def get_audit_logs(limit=500, filters=None):
    filters = filters or {}
    where, params = [], []
    if filters.get('action'):
        where.append('action = ?'); params.append(filters['action'])
    if filters.get('username'):
        where.append('username = ?'); params.append(filters['username'])
    w = ('WHERE ' + ' AND '.join(where)) if where else ''
    with get_db() as conn:
        rows = conn.execute(
            f'SELECT * FROM audit_log {w} ORDER BY created_at DESC LIMIT ?',
            params + [limit]
        ).fetchall()
        return [dict(r) for r in rows]


def get_audit_users():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT DISTINCT username FROM audit_log WHERE username != '' ORDER BY username"
        ).fetchall()
        return [r['username'] for r in rows]


def set_must_change_password(user_id, flag):
    with get_db() as conn:
        conn.execute('UPDATE users SET must_change_password=? WHERE id=?', (1 if flag else 0, user_id))


# ------------------------------------------------------------------ #
# EXPORT HISTORY
# ------------------------------------------------------------------ #

def save_export_record(data):
    with get_db() as conn:
        conn.execute('''
            INSERT INTO export_history (filename, filepath, export_type, date_from, date_to, exported_by, file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['filename'], data['filepath'], data.get('export_type', ''),
            data.get('date_from', ''), data.get('date_to', ''),
            data.get('exported_by', ''), data.get('file_size', 0),
        ))


def get_all_exports():
    with get_db() as conn:
        rows = conn.execute(
            'SELECT * FROM export_history ORDER BY created_at DESC'
        ).fetchall()
        return [dict(r) for r in rows]


def get_export_by_id(export_id):
    with get_db() as conn:
        row = conn.execute('SELECT * FROM export_history WHERE id=?', (export_id,)).fetchone()
        return dict(row) if row else None


def delete_export_record(export_id):
    with get_db() as conn:
        conn.execute('DELETE FROM export_history WHERE id=?', (export_id,))


# ------------------------------------------------------------------ #
# TICKETS
# ------------------------------------------------------------------ #

def _generate_ticket_id(conn, ticket_type, year, month):
    prefix = 'PH' if ticket_type == 'annual_leave' else 'DT'
    month_str = f'{year}{month:02d}'
    count = conn.execute(
        "SELECT COUNT(*) AS c FROM tickets WHERE ticket_id LIKE ?",
        (f'{prefix}-{month_str}-%',)
    ).fetchone()['c']
    return f'{prefix}-{month_str}-{count + 1:03d}'


def create_ticket(data):
    from datetime import datetime as _dt, date as _date, timedelta as _td
    now = _dt.now()
    leave_date    = data['leave_date']
    leave_date_to = data.get('leave_date_to', '') or leave_date

    try:
        d_from = _date.fromisoformat(leave_date)
        d_to   = _date.fromisoformat(leave_date_to)
        if d_to < d_from:
            d_to = d_from
        days_count = (d_to - d_from).days + 1
    except ValueError:
        d_from = d_to = None
        days_count = 1

    with get_db() as conn:
        ticket_id = _generate_ticket_id(conn, data['type'], now.year, now.month)
        conn.execute('''
            INSERT INTO tickets (ticket_id, type, employee_id, employee_name,
                                 leave_date, leave_date_to, days_count,
                                 reason, expected_time, approved_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ticket_id, data['type'], data['employee_id'], data['employee_name'],
            leave_date, leave_date_to, days_count,
            data.get('reason', ''), data.get('expected_time', ''), data.get('approved_by', ''),
        ))
        # Auto-update ALL matching attendance records across the date range
        approved_by = data.get('approved_by', '')
        if data['type'] == 'annual_leave':
            action = f'Nghỉ phép năm — ticket {ticket_id}'
        else:
            t = data.get('expected_time', '')
            action = f'Đi trễ có phép{" — Đến lúc " + t if t else ""}'

        if d_from and d_to:
            cur = d_from
            while cur <= d_to:
                conn.execute('''
                    UPDATE attendance
                    SET action_taken = ?, approved_by = ?, approved_at = datetime('now','localtime')
                    WHERE date = ? AND employee_id = ?
                      AND (action_taken = '' OR action_taken IS NULL)
                ''', (action, approved_by, cur.isoformat(), data['employee_id']))
                cur += _td(days=1)
        return ticket_id


def get_all_tickets(filters=None):
    filters = filters or {}
    where, params = [], []
    if filters.get('type'):
        where.append('t.type = ?'); params.append(filters['type'])
    if filters.get('employee_id'):
        where.append('t.employee_id = ?'); params.append(filters['employee_id'])
    if filters.get('month'):
        where.append("t.leave_date LIKE ?"); params.append(filters['month'] + '%')
    w = ('WHERE ' + ' AND '.join(where)) if where else ''
    with get_db() as conn:
        rows = conn.execute(f'''
            SELECT t.*, e.department
            FROM tickets t
            LEFT JOIN employees e ON t.employee_id = e.id
            {w}
            ORDER BY t.created_at DESC
        ''', params).fetchall()
        return [dict(r) for r in rows]


def delete_ticket(ticket_db_id):
    with get_db() as conn:
        conn.execute('DELETE FROM tickets WHERE id = ?', (ticket_db_id,))


def get_ticket_count_by_type():
    with get_db() as conn:
        rows = conn.execute('''
            SELECT type, COUNT(*) AS c FROM tickets GROUP BY type
        ''').fetchall()
        return {r['type']: r['c'] for r in rows}


def get_employee_leave_summary(year, current_month):
    """Returns all employees with annual leave balance for the given year.

    Accrual: full_time employees earn 1 day/month → accrued = current_month (1–12).
    Used: count attendance rows in 'year' where action_taken contains 'Nghỉ phép năm'.
    """
    accrued = min(current_month, 12)
    with get_db() as conn:
        employees = conn.execute('SELECT * FROM employees ORDER BY name').fetchall()
        used_rows = conn.execute('''
            SELECT employee_id, COALESCE(SUM(days_count), 0) AS used_days
            FROM tickets
            WHERE type = 'annual_leave' AND leave_date LIKE ?
            GROUP BY employee_id
        ''', (str(year) + '%',)).fetchall()
        used_map = {r['employee_id']: r['used_days'] for r in used_rows}

        result = []
        for e in employees:
            emp = dict(e)
            is_fulltime = emp.get('employment_type', 'full_time') == 'full_time'
            if is_fulltime:
                used = used_map.get(emp['id'], 0)
                emp['leave_accrued']   = accrued
                emp['leave_used']      = used
                emp['leave_remaining'] = accrued - used
            else:
                emp['leave_accrued']   = None
                emp['leave_used']      = None
                emp['leave_remaining'] = None
            result.append(emp)
        return result


# ------------------------------------------------------------------ #
# LARK SYNC
# ------------------------------------------------------------------ #

def save_lark_user_id(employee_id, lark_user_id):
    with get_db() as conn:
        conn.execute("UPDATE employees SET lark_user_id=? WHERE id=?",
                     (lark_user_id.strip(), employee_id))


def get_lark_sync_logs(limit=50):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM lark_sync_logs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def add_lark_sync_log(triggered_by, date_from, date_to, count, log_text, status='ok'):
    try:
        with get_db() as conn:
            conn.execute('''
                INSERT INTO lark_sync_logs
                    (triggered_by, date_from, date_to, records_count, log_text, status)
                VALUES (?,?,?,?,?,?)
            ''', (triggered_by, date_from, date_to, count, log_text, status))
    except Exception:
        pass


def get_dashboard_stats():
    with get_db() as conn:
        total     = conn.execute('SELECT COUNT(*) AS c FROM attendance').fetchone()['c']
        review    = conn.execute("SELECT COUNT(*) AS c FROM attendance WHERE status != '✅ OK' AND (action_taken = '' OR action_taken IS NULL)").fetchone()['c']
        employees = conn.execute('SELECT COUNT(*) AS c FROM employees').fetchone()['c']
        recent    = conn.execute(
            'SELECT * FROM attendance ORDER BY created_at DESC LIMIT 8'
        ).fetchall()
        return {
            'total_records':  total,
            'review_count':   review,
            'employee_count': employees,
            'recent':         [dict(r) for r in recent],
        }


# ------------------------------------------------------------------ #
# DELIVERY — INVENTORY
# ------------------------------------------------------------------ #

def get_all_inventory(filters=None):
    filters = filters or {}
    where, params = [], []
    if filters.get('condition'):
        where.append('condition = ?'); params.append(filters['condition'])
    if filters.get('status'):
        where.append('status = ?'); params.append(filters['status'])
    if filters.get('q'):
        where.append('(serial_no LIKE ? OR model LIKE ?)')
        params += [f"%{filters['q']}%", f"%{filters['q']}%"]
    w = ('WHERE ' + ' AND '.join(where)) if where else ''
    with get_db() as conn:
        rows = conn.execute(
            f'SELECT * FROM delivery_inventory {w} ORDER BY status, condition, serial_no', params
        ).fetchall()
        return [dict(r) for r in rows]


def get_inventory_in_stock():
    """Machines available to assign to a new delivery."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM delivery_inventory WHERE status = 'in_stock' ORDER BY condition, serial_no"
        ).fetchall()
        return [dict(r) for r in rows]


def get_inventory_by_serial(serial_no):
    with get_db() as conn:
        row = conn.execute(
            'SELECT * FROM delivery_inventory WHERE serial_no = ?', (serial_no,)
        ).fetchone()
        return dict(row) if row else None


def save_inventory(data):
    """Insert or update a machine by serial number."""
    with get_db() as conn:
        existing = conn.execute(
            'SELECT id, status FROM delivery_inventory WHERE serial_no = ?',
            (data['serial_no'],)
        ).fetchone()
        if existing:
            conn.execute('''
                UPDATE delivery_inventory
                SET model = ?, condition = ?, status = ?, notes = ?
                WHERE serial_no = ?
            ''', (
                data.get('model', ''), data.get('condition', 'new'),
                data.get('status', existing['status'] or 'in_stock'),
                data.get('notes', ''), data['serial_no'],
            ))
        else:
            conn.execute('''
                INSERT INTO delivery_inventory (serial_no, model, condition, status, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                data['serial_no'], data.get('model', ''), data.get('condition', 'new'),
                data.get('status', 'in_stock'), data.get('notes', ''),
            ))


def set_inventory_status(serial_no, status):
    if not serial_no:
        return
    with get_db() as conn:
        conn.execute(
            'UPDATE delivery_inventory SET status = ? WHERE serial_no = ?',
            (status, serial_no)
        )


def delete_inventory(inv_id):
    with get_db() as conn:
        conn.execute('DELETE FROM delivery_inventory WHERE id = ?', (inv_id,))


def get_inventory_stats():
    with get_db() as conn:
        rows = conn.execute('''
            SELECT condition, status, COUNT(*) AS c
            FROM delivery_inventory
            GROUP BY condition, status
        ''').fetchall()
    stats = {'new_in_stock': 0, 'used_in_stock': 0, 'total': 0,
             'delivered': 0, 'returned': 0}
    for r in rows:
        stats['total'] += r['c']
        if r['status'] == 'in_stock':
            stats['new_in_stock' if r['condition'] == 'new' else 'used_in_stock'] += r['c']
        elif r['status'] == 'delivered':
            stats['delivered'] += r['c']
        elif r['status'] == 'returned':
            stats['returned'] += r['c']
    return stats


# ------------------------------------------------------------------ #
# DELIVERY — JOBS
# ------------------------------------------------------------------ #

def _generate_delivery_code(conn, year, month):
    month_str = f'{year}{month:02d}'
    count = conn.execute(
        "SELECT COUNT(*) AS c FROM deliveries WHERE delivery_code LIKE ?",
        (f'GH-{month_str}-%',)
    ).fetchone()['c']
    return f'GH-{month_str}-{count + 1:03d}'


def create_delivery(data):
    from datetime import datetime as _dt
    now = _dt.now()
    serial = (data.get('machine_serial') or '').strip()
    machine = get_inventory_by_serial(serial) if serial else None
    with get_db() as conn:
        code = _generate_delivery_code(conn, now.year, now.month)
        conn.execute('''
            INSERT INTO deliveries
                (delivery_code, customer_name, customer_email, customer_phone,
                 customer_address, machine_serial, machine_model, machine_condition,
                 status, scheduled_date, assigned_to, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'scheduled', ?, ?, ?)
        ''', (
            code, data['customer_name'], data.get('customer_email', ''),
            data.get('customer_phone', ''), data.get('customer_address', ''),
            serial, machine['model'] if machine else '',
            machine['condition'] if machine else '',
            data.get('scheduled_date', ''), data.get('assigned_to', ''),
            data.get('notes', ''),
        ))
        # Reserve the machine so it can't be double-assigned
        if serial:
            conn.execute(
                "UPDATE delivery_inventory SET status = 'assigned' WHERE serial_no = ?",
                (serial,)
            )
    return code


def get_all_deliveries(filters=None):
    filters = filters or {}
    where, params = [], []
    if filters.get('status'):
        where.append('status = ?'); params.append(filters['status'])
    if filters.get('date'):
        where.append('scheduled_date = ?'); params.append(filters['date'])
    if filters.get('q'):
        where.append('(customer_name LIKE ? OR delivery_code LIKE ? OR machine_serial LIKE ?)')
        params += [f"%{filters['q']}%"] * 3
    w = ('WHERE ' + ' AND '.join(where)) if where else ''
    with get_db() as conn:
        rows = conn.execute(
            f'SELECT * FROM deliveries {w} ORDER BY created_at DESC', params
        ).fetchall()
        return [dict(r) for r in rows]


def get_delivery_by_id(delivery_id):
    with get_db() as conn:
        row = conn.execute('SELECT * FROM deliveries WHERE id = ?', (delivery_id,)).fetchone()
        return dict(row) if row else None


def update_delivery_log(delivery_id, fields):
    """Update only the provided log fields (depart/arrive/setup time, location, status)."""
    allowed = ('depart_time', 'arrive_time', 'setup_time', 'location', 'status', 'assigned_to')
    sets, params = [], []
    for k in allowed:
        if k in fields and fields[k] is not None:
            sets.append(f'{k} = ?'); params.append(fields[k])
    if not sets:
        return
    params.append(delivery_id)
    with get_db() as conn:
        conn.execute(f"UPDATE deliveries SET {', '.join(sets)} WHERE id = ?", params)
        # When marked delivered, flip the machine to 'delivered'
        if fields.get('status') == 'delivered':
            row = conn.execute('SELECT machine_serial FROM deliveries WHERE id = ?',
                               (delivery_id,)).fetchone()
            if row and row['machine_serial']:
                conn.execute(
                    "UPDATE delivery_inventory SET status = 'delivered' WHERE serial_no = ?",
                    (row['machine_serial'],)
                )


def mark_label_sent(delivery_id):
    from datetime import datetime as _dt
    ts = _dt.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_db() as conn:
        conn.execute(
            'UPDATE deliveries SET label_sent = 1, label_sent_at = ? WHERE id = ?',
            (ts, delivery_id)
        )


def mark_delivery_returned(delivery_id, reason=''):
    from datetime import datetime as _dt
    ts = _dt.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_db() as conn:
        row = conn.execute('SELECT machine_serial FROM deliveries WHERE id = ?',
                           (delivery_id,)).fetchone()
        conn.execute('''
            UPDATE deliveries
            SET status = 'returned', returned_at = ?, return_reason = ?
            WHERE id = ?
        ''', (ts, reason, delivery_id))
        if row and row['machine_serial']:
            conn.execute(
                "UPDATE delivery_inventory SET status = 'returned' WHERE serial_no = ?",
                (row['machine_serial'],)
            )


def delete_delivery(delivery_id):
    """Delete a delivery and release its machine back to stock if not delivered."""
    with get_db() as conn:
        row = conn.execute('SELECT machine_serial, status FROM deliveries WHERE id = ?',
                           (delivery_id,)).fetchone()
        if row and row['machine_serial'] and row['status'] in ('scheduled', 'en_route'):
            conn.execute(
                "UPDATE delivery_inventory SET status = 'in_stock' WHERE serial_no = ?",
                (row['machine_serial'],)
            )
        conn.execute('DELETE FROM deliveries WHERE id = ?', (delivery_id,))


def get_delivery_stats():
    with get_db() as conn:
        rows = conn.execute(
            'SELECT status, COUNT(*) AS c FROM deliveries GROUP BY status'
        ).fetchall()
        by_status = {r['status']: r['c'] for r in rows}
        pending_label = conn.execute(
            "SELECT COUNT(*) AS c FROM deliveries WHERE label_sent = 0 AND status != 'returned'"
        ).fetchone()['c']
    return {
        'total':     sum(by_status.values()),
        'scheduled': by_status.get('scheduled', 0),
        'en_route':  by_status.get('en_route', 0),
        'delivered': by_status.get('delivered', 0),
        'returned':  by_status.get('returned', 0),
        'pending_label': pending_label,
    }
