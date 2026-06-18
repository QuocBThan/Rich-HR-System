"""Attendance Management System — Flask Application"""
import csv
import io
import os
import re
import secrets
from datetime import datetime as _dt, timedelta
from functools import wraps

from dotenv import load_dotenv
load_dotenv()

from flask import (Flask, Response, flash, jsonify, redirect,
                   render_template, request, session, url_for, send_file)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

import db
import processor

app = Flask(__name__)

# ── Security configuration ─────────────────────────────────────────
_FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
app.config.update(
    SECRET_KEY              = os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'Lax',
    SESSION_COOKIE_SECURE   = _FORCE_HTTPS,
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30),
    WTF_CSRF_TIME_LIMIT     = None,
    MAX_CONTENT_LENGTH      = 10 * 1024 * 1024,   # 10 MB upload limit
)
csrf = CSRFProtect(app)

# Fernet encryption for export files at rest
try:
    from cryptography.fernet import Fernet as _Fernet
    _fk = os.environ.get('FERNET_KEY', '')
    _fernet = _Fernet(_fk.encode()) if _fk else None
except Exception:
    _fernet = None

def _encrypt(data: bytes) -> bytes:
    return _fernet.encrypt(data) if _fernet else data

def _decrypt(data: bytes) -> bytes:
    return _fernet.decrypt(data) if _fernet else data

# Directory for persisted export files
EXPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'exports')
os.makedirs(EXPORTS_DIR, exist_ok=True)

db.init_db()


# ------------------------------------------------------------------ #
# EXPORT HELPERS
# ------------------------------------------------------------------ #

def _resolve_export_dates(filters):
    """Return (from_date, to_date) strings from filter dict."""
    import calendar as _cal
    month  = filters.get('month')
    period = filters.get('period')
    if month:
        yr, mo = map(int, month.split('-'))
        last   = _cal.monthrange(yr, mo)[1]
        if period == '1':   return f'{month}-01', f'{month}-15'
        elif period == '2': return f'{month}-16', f'{month}-{last:02d}'
        else:               return f'{month}-01', f'{month}-{last:02d}'
    return filters.get('from_date') or '', filters.get('to_date') or ''


def _export_fname(label, from_d, to_d, ext):
    """Build a human-readable, filesystem-safe filename."""
    def _fmt(d):
        try:
            y, m, day = d.split('-')
            return f'{day}-{m}-{y}'
        except Exception:
            return d
    if from_d and to_d:
        return f'Attendance_Report_{_fmt(from_d)}_den_{_fmt(to_d)}.{ext}'
    return f'Attendance_Report_Toan_Bo_{_dt.now().strftime("%d-%m-%Y_%H%M")}.{ext}'


def _persist_export(raw_bytes, filename, export_type, from_d, to_d):
    """Encrypt and save bytes to exports/ dir, then record in DB."""
    filepath = os.path.join(EXPORTS_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(_encrypt(raw_bytes))
    db.save_export_record({
        'filename':    filename,
        'filepath':    filepath,
        'export_type': export_type,
        'date_from':   from_d,
        'date_to':     to_d,
        'exported_by': session.get('display_name') or session.get('username', ''),
        'file_size':   os.path.getsize(filepath),
    })
    db.log_audit(session.get('user_id', 0), session.get('username', ''), 'EXPORT',
                 f'{export_type} | {filename}', request.remote_addr)


# ------------------------------------------------------------------ #
# AUTH HELPERS
# ------------------------------------------------------------------ #

# ------------------------------------------------------------------ #
# PASSWORD VALIDATION
# ------------------------------------------------------------------ #

def validate_password(pw):
    """Returns (ok, message). Min 8 chars, 1 uppercase, 1 digit, 1 special."""
    if len(pw) < 8:
        return False, 'Phải ít nhất 8 ký tự'
    if not re.search(r'[A-Z]', pw):
        return False, 'Phải có ít nhất 1 chữ HOA (A-Z)'
    if not re.search(r'[0-9]', pw):
        return False, 'Phải có ít nhất 1 chữ số (0-9)'
    if not re.search(r'[^A-Za-z0-9]', pw):
        return False, 'Phải có ít nhất 1 ký tự đặc biệt (!@#$%...)'
    return True, ''


# ------------------------------------------------------------------ #
# SECURITY MIDDLEWARE
# ------------------------------------------------------------------ #

@app.before_request
def security_middleware():
    # HTTPS enforcement
    if _FORCE_HTTPS and not request.is_secure and request.method != 'OPTIONS':
        return redirect(request.url.replace('http://', 'https://', 1), code=301)

    # Session idle timeout (30 minutes)
    if session.get('user_id'):
        last_active = session.get('_last_active', 0)
        now = _dt.now().timestamp()
        if now - last_active > 1800:
            uid, uname = session.get('user_id'), session.get('username', '')
            session.clear()
            db.log_audit(uid, uname, 'SESSION_EXPIRED', 'Phiên hết hạn tự động', request.remote_addr)
            flash('Phiên đăng nhập đã hết hạn (30 phút không hoạt động).', 'error')
            return redirect(url_for('login'))
        session['_last_active'] = now
        session.modified = True

    # Force password change redirect
    if (session.get('must_change_pw') and
            request.endpoint not in ('change_password', 'logout', 'static')):
        return redirect(url_for('change_password'))


@app.after_request
def security_headers(response):
    response.headers['X-Frame-Options']        = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection']       = '1; mode=block'
    response.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
    if _FORCE_HTTPS:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


# ------------------------------------------------------------------ #
# AUTH HELPERS
# ------------------------------------------------------------------ #

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated


def hr_required(f):
    """Only HR and admin roles can access payroll/attendance features."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        role = session.get('role')
        if role == 'employee':
            return redirect(url_for('portal'))   # employees have their own portal
        if role not in ('hr', 'admin'):
            return redirect(url_for('no_access'))
        return f(*args, **kwargs)
    return decorated


def _ensure_default_admin():
    """Create a default admin account on first run if no users exist."""
    if db.count_users() == 0:
        db.create_user(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            display_name='Administrator',
            role='admin',
            must_change_password=1,
        )

_ensure_default_admin()


# ------------------------------------------------------------------ #
# TEMPLATE HELPERS
# ------------------------------------------------------------------ #

def _status_row(s):
    if 'Not Matched'  in s: return 'row-notmatch'
    if 'Missing'      in s: return 'row-missing'
    if 'Under Hours'  in s: return 'row-under'
    if 'Overtime'     in s: return 'row-ot'
    if 'After 20'     in s: return 'row-late'
    if 'Manual'       in s: return 'row-manual'
    if 'Late Clock In' in s: return 'row-latein'
    return 'row-ok'

def _status_badge(s):
    if 'Not Matched'  in s: return 'badge-notmatch'
    if 'Missing'      in s: return 'badge-missing'
    if 'Under Hours'  in s: return 'badge-under'
    if 'Overtime'     in s: return 'badge-ot'
    if 'After 20'     in s: return 'badge-late'
    if 'Manual'       in s: return 'badge-manual'
    if 'Late Clock In' in s: return 'badge-latein'
    return 'badge-ok'

app.jinja_env.globals.update(
    status_row_class=_status_row,
    status_badge_class=_status_badge,
)


# ------------------------------------------------------------------ #
# CONTEXT PROCESSORS
# ------------------------------------------------------------------ #

@app.context_processor
def inject_globals():
    review_count = 0
    if session.get('role') in ('hr', 'admin'):
        try:
            review_count = db.get_review_count()
        except Exception:
            pass
    return {
        'review_count':  review_count,
        'current_user':  session.get('display_name', ''),
        'current_role':  session.get('role', ''),
    }


# ------------------------------------------------------------------ #
# LOGIN / LOGOUT
# ------------------------------------------------------------------ #

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user     = db.get_user_by_username(username)

        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id']        = user['id']
            session['username']       = user['username']
            session['display_name']   = user['display_name'] or user['username']
            session['role']           = user['role']
            session['department']     = user['department']
            session['employee_id']    = user.get('employee_id', '')
            session['_last_active']   = _dt.now().timestamp()
            session.permanent         = True
            if user.get('must_change_password'):
                session['must_change_pw'] = True
            db.log_audit(user['id'], user['username'], 'LOGIN', '', request.remote_addr)
            # Employee role → always go to personal portal
            if user['role'] == 'employee':
                return redirect(url_for('portal'))
            raw_next = request.args.get('next', '')
            # Only allow relative redirects (no scheme/host) to prevent open redirect
            next_url = raw_next if (raw_next and raw_next.startswith('/') and not raw_next.startswith('//')) else url_for('index')
            return redirect(next_url)
        else:
            db.log_audit(0, username, 'LOGIN_FAILED', f'Sai mật khẩu', request.remote_addr)
            error = 'Sai username hoặc password.'

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    db.log_audit(session.get('user_id', 0), session.get('username', ''), 'LOGOUT', '', request.remote_addr)
    session.clear()
    return redirect(url_for('login'))


@app.route('/no-access')
@login_required
def no_access():
    return render_template('no_access.html')


# ------------------------------------------------------------------ #
# DASHBOARD
# ------------------------------------------------------------------ #

@app.route('/')
@hr_required
def index():
    now   = _dt.now()
    stats = db.get_dashboard_stats()
    employees_leave = db.get_employee_leave_summary(now.year, now.month)
    return render_template('index.html', stats=stats,
                           employees_leave=employees_leave,
                           current_year=now.year,
                           current_month=now.month)


# ------------------------------------------------------------------ #
# UPLOAD & PROCESS
# ------------------------------------------------------------------ #

@app.route('/upload', methods=['GET', 'POST'])
@hr_required
def upload():
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or f.filename == '':
            flash('Chưa chọn file.', 'error')
            return redirect(request.url)

        if not any(f.filename.lower().endswith(ext) for ext in ('.xlsx', '.xls', '.csv')):
            flash('Chỉ hỗ trợ .xlsx, .xls, .csv', 'error')
            return redirect(request.url)

        try:
            import traceback as _tb
            f.stream.seek(0)          # đảm bảo stream ở đầu file
            records = processor.parse_lark_file(f)
            if not records:
                flash('Không tìm thấy dữ liệu hợp lệ. Kiểm tra lại format file.', 'error')
                return redirect(request.url)

            employees = db.get_all_employees()
            aliases   = db.get_all_aliases()
            processed, review_count = processor.process_records(records, employees, aliases)
            db.save_attendance_batch(processed)
            db.log_audit(session['user_id'], session['username'], 'UPLOAD',
                         f'{len(processed)} records — {review_count} cần review | file: {f.filename}',
                         request.remote_addr)

            ok_count = len(processed) - review_count
            flash(
                f'✅ Xử lý xong! {len(processed)} records — '
                f'{ok_count} OK, {review_count} cần review.',
                'success',
            )
            return redirect(url_for('review') if review_count else url_for('attendance'))

        except Exception as e:
            import traceback
            flash(f'Lỗi: {e} | {traceback.format_exc()[:500]}', 'error')

    return render_template('upload.html')


# ------------------------------------------------------------------ #
# ATTENDANCE RECORDS
# ------------------------------------------------------------------ #

@app.route('/attendance/preview_export')
@hr_required
def preview_export():
    import calendar as _cal
    from datetime import date as _date, timedelta as _td

    filters = {k: v for k, v in {
        'month':  request.args.get('month'),
        'period': request.args.get('period'),
    }.items() if v}

    records   = db.get_attendance(filters)
    employees = db.get_all_employees()
    preview   = db.get_export_preview(filters)
    months    = db.get_distinct_months()

    # Build pivot for matrix view
    pivot        = {}
    emp_ids_seen = set()
    for r in records:
        pivot.setdefault(r['date'], {})[r['employee_id']] = r
        if r['employee_id']:
            emp_ids_seen.add(r['employee_id'])

    # Date range
    if filters.get('month'):
        yr, mo   = map(int, filters['month'].split('-'))
        last_day = _cal.monthrange(yr, mo)[1]
        if filters.get('period') == '1':
            d_start, d_end = _date(yr, mo, 1),  _date(yr, mo, 15)
        elif filters.get('period') == '2':
            d_start, d_end = _date(yr, mo, 16), _date(yr, mo, last_day)
        else:
            d_start, d_end = _date(yr, mo, 1),  _date(yr, mo, last_day)
        dates, d = [], d_start
        while d <= d_end:
            dates.append(d.strftime('%Y-%m-%d'))
            d += _td(days=1)
    else:
        dates = sorted(pivot.keys())

    DAYS     = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    emp_list = [e for e in employees if e['id'] in emp_ids_seen]

    from datetime import datetime as _dt
    date_meta = {}
    for d in dates:
        try:
            dt  = _dt.strptime(d, '%Y-%m-%d')
            dow = dt.weekday()
            date_meta[d] = {
                'day_name':   DAYS[dow],
                'is_weekend': dow >= 5,
                'display':    dt.strftime('%d/%m'),
                'dow':        dow,
            }
        except Exception:
            date_meta[d] = {'day_name': '', 'is_weekend': False, 'display': d, 'dow': -1}

    return render_template('preview_export.html',
                           preview=preview,
                           filters=filters,
                           months=months,
                           pivot=pivot,
                           dates=dates,
                           emp_list=emp_list,
                           date_meta=date_meta)


@app.route('/attendance')
@hr_required
def attendance():
    filters = {k: v for k, v in {
        'month':        request.args.get('month'),
        'employee_id':  request.args.get('employee_id'),
        'status':       request.args.get('status'),
        'period':       request.args.get('period'),
        'weekday_only': request.args.get('weekday_only'),
    }.items() if v}

    records   = db.get_attendance(filters)
    employees = db.get_all_employees()
    months    = db.get_distinct_months()

    return render_template('attendance.html',
                           records=records,
                           employees=employees,
                           months=months,
                           filters=filters,
                           status_list=processor.STATUS_VALUES)


@app.route('/attendance/export')
@hr_required
def export_attendance():
    filters = {k: v for k, v in {
        'month':       request.args.get('month'),
        'employee_id': request.args.get('employee_id'),
        'period':      request.args.get('period'),
    }.items() if v}

    records = db.get_attendance(filters)
    output  = io.StringIO()
    w       = csv.writer(output)
    w.writerow(['Date', 'Employee ID', 'Name', 'Department', 'Role',
                'Clock In', 'Clock Out', 'Actual Hrs', 'Break', 'Net Hrs',
                'Paid Hrs', 'Status', 'Notes', 'Action Taken', 'Approved By'])
    for r in records:
        w.writerow([r['date'], r['employee_id'], r['employee_name'],
                    r['department'], r['role'], r['clock_in'], r['clock_out'],
                    r['actual_hrs'], r['break_hrs'], r['net_hrs'], r['paid_hrs'],
                    r['status'], r['notes'], r['action_taken'], r['approved_by']])

    content = output.getvalue()
    from_d, to_d = _resolve_export_dates(filters)
    fname = _export_fname('Full', from_d, to_d, 'csv')
    _persist_export(('﻿' + content).encode('utf-8'), fname, 'Danh Sách Đầy Đủ', from_d, to_d)

    return Response(
        '﻿' + content,
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename={fname}'},
    )


@app.route('/attendance/export_summary')
@hr_required
def export_summary():
    filters = {k: v for k, v in {
        'month':       request.args.get('month'),
        'employee_id': request.args.get('employee_id'),
        'period':      request.args.get('period'),
    }.items() if v}

    records = db.get_attendance(filters)
    output  = io.StringIO()
    w       = csv.writer(output)
    w.writerow(['Ngày', 'Nhân Viên', 'Giờ Vào', 'Giờ Ra', 'Số Giờ (Net)', 'Ghi Chú'])

    for r in records:
        if r.get('action_taken'):
            by   = f" [{r['approved_by']}]" if r.get('approved_by') else ''
            note = r['action_taken'] + by
        elif r.get('status') and r['status'] != '✅ OK':
            note = r['status']
        else:
            note = ''

        w.writerow([
            r['date'],
            r['employee_name'],
            r['clock_in']  or '',
            r['clock_out'] or '',
            r['net_hrs']   if r['net_hrs'] is not None else '',
            note,
        ])

    content = output.getvalue()
    from_d, to_d = _resolve_export_dates(filters)
    fname = _export_fname('Summary', from_d, to_d, 'csv')
    _persist_export(('﻿' + content).encode('utf-8'), fname, 'Tóm Tắt Chấm Công', from_d, to_d)

    return Response(
        '﻿' + content,
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename={fname}'},
    )


@app.route('/attendance/export_matrix')
@hr_required
def export_matrix():
    from openpyxl import Workbook
    from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    filters = {k: v for k, v in {
        'month':  request.args.get('month'),
        'period': request.args.get('period'),
    }.items() if v}

    records   = db.get_attendance(filters)
    employees = db.get_all_employees()

    if not records:
        flash('Không có dữ liệu để xuất.', 'error')
        return redirect(url_for('attendance'))

    # Build pivot: {date: {emp_id: record}}
    pivot = {}
    emp_ids_seen = set()
    for r in records:
        pivot.setdefault(r['date'], {})[r['employee_id']] = r
        if r['employee_id']:
            emp_ids_seen.add(r['employee_id'])

    # Generate full date range (including weekends) when month is known
    if filters.get('month'):
        import calendar as _cal
        yr, mo = map(int, filters['month'].split('-'))
        last_day = _cal.monthrange(yr, mo)[1]
        from datetime import date as _date, timedelta as _td
        if filters.get('period') == '1':
            d_start, d_end = _date(yr, mo, 1),  _date(yr, mo, 15)
        elif filters.get('period') == '2':
            d_start, d_end = _date(yr, mo, 16), _date(yr, mo, last_day)
        else:
            d_start, d_end = _date(yr, mo, 1),  _date(yr, mo, last_day)
        dates = []
        d = d_start
        while d <= d_end:
            dates.append(d.strftime('%Y-%m-%d'))
            d += _td(days=1)
    else:
        dates = sorted(pivot.keys())
    emp_list = [e for e in employees if e['id'] in emp_ids_seen]
    n_emp    = len(emp_list)
    last_col = get_column_letter(max(9, 2 + n_emp))   # at least col I

    # ── Style helpers ──────────────────────────────────────────────
    def _fill(h): return PatternFill(start_color=h, end_color=h, fill_type='solid')
    def _font(bold=False, color='000000', size=9, italic=False):
        return Font(bold=bold, color=color, size=size, italic=italic)
    def _align(h='center', v='center', wrap=False):
        return Alignment(horizontal=h, vertical=v, wrap_text=wrap)
    _thin   = Side(style='thin', color='E2E8F0')
    _border = Border(left=_thin, right=_thin, top=_thin, bottom=_thin)

    def _12h(t):
        if not t: return ''
        try:
            h, m = map(int, t.split(':'))
            return f"{h%12 or 12}:{m:02d} {'AM' if h < 12 else 'PM'}"
        except Exception:
            return t

    C = {   # colors
        'hdr':  '0F172A', 'sep':  '1E293B', 'rawh': 'F8FAFC',
        'ot':   'FEF9C3', 'uh':   'DBEAFE', 'mc':   'FEE2E2',
        'late': 'FED7AA', 'off':  'F1F5F9', 'ok':   'FFFFFF',
    }
    DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    # ── Workbook ───────────────────────────────────────────────────
    wb = Workbook()
    ws = wb.active
    ws.title = 'Attendance Matrix'

    # Row 1 – Title
    ws.merge_cells(f'A1:{last_col}1')
    c = ws['A1']
    c.value, c.font, c.alignment = (
        'Biweekly Attendance Matrix Report',
        _font(bold=True, size=14, color='0F172A'),
        _align('center'),
    )
    ws.row_dimensions[1].height = 26

    # Row 2 – Subtitle
    ws.merge_cells(f'A2:{last_col}2')
    c = ws['A2']
    c.value     = ('One-tab format: dates down the left, employee names across the top. '
                   'Each cell shows Clock In → Clock Out and net hours after 1-hour break.')
    c.font      = _font(italic=True, size=8, color='64748B')
    c.alignment = _align('center')
    ws.row_dimensions[2].height = 14

    ws.row_dimensions[3].height = 6   # spacer

    # Row 4 – Pay period + Legend
    pay_start = dates[0] if dates else ''
    ws['A4'].value = f'Pay Period Start: {pay_start}'
    ws['A4'].font  = _font(bold=True, size=9)
    ws['C4'].value, ws['C4'].font = 'Default Break', _font(size=9, color='64748B')
    ws['D4'].value, ws['D4'].font = '1.0', _font(bold=True, size=9)
    for col_l, txt, bg, fg in [
        ('F', 'OT = Review',       C['ot'],   'A16207'),
        ('G', 'UH = Under Hours',  C['uh'],   '1E40AF'),
        ('H', 'MC = Missing Clock',C['mc'],   'B91C1C'),
    ]:
        ws[f'{col_l}4'].value, ws[f'{col_l}4'].fill = txt, _fill(bg)
        ws[f'{col_l}4'].font  = _font(size=8, color=fg)
        ws[f'{col_l}4'].alignment = _align('center')
    ws.row_dimensions[4].height = 16

    ws.row_dimensions[5].height = 6   # spacer

    # Row 6 – Column headers
    for col_l, label in [('A', 'Date'), ('B', 'Day')]:
        c = ws[f'{col_l}6']
        c.value, c.fill  = label, _fill(C['hdr'])
        c.font, c.alignment, c.border = (
            _font(bold=True, color='FFFFFF', size=9), _align('center'), _border)
    for i, emp in enumerate(emp_list):
        c = ws[f'{get_column_letter(3+i)}6']
        c.value, c.fill  = emp['name'], _fill(C['hdr'])
        c.font, c.alignment, c.border = (
            _font(bold=True, color='FFFFFF', size=9), _align('center', wrap=True), _border)
    ws.row_dimensions[6].height = 30

    # ── Data rows ──────────────────────────────────────────────────
    for ri, date_str in enumerate(dates):
        rn      = 7 + ri
        dt      = _dt.strptime(date_str, '%Y-%m-%d')
        dow     = dt.weekday()
        weekend = dow >= 5

        for col_l, val, kw in [
            ('A', date_str, dict(bold=True, color='374151')),
            ('B', DAYS[dow], dict(color='6B7280')),
        ]:
            c = ws[f'{col_l}{rn}']
            c.value, c.font      = val, _font(size=9, **kw)
            c.alignment, c.border = _align('center'), _border
            if weekend:
                c.fill = _fill(C['off'])

        for i, emp in enumerate(emp_list):
            c = ws[f'{get_column_letter(3+i)}{rn}']
            c.alignment, c.border = _align('center', wrap=True), _border

            if weekend:
                c.value, c.fill = 'OFF', _fill(C['off'])
                c.font = _font(size=8, color='94A3B8')
            elif date_str in pivot and emp['id'] in pivot[date_str]:
                rec    = pivot[date_str][emp['id']]
                status = rec.get('status', '')
                ci, co = rec.get('clock_in', ''), rec.get('clock_out', '')
                net    = rec.get('net_hrs')

                if any(k in status for k in ('Missing', 'Manual', 'Not Matched')):
                    tag = 'MC' if 'Missing' in status else '—'
                    c.value, c.fill = tag, _fill(C['mc'])
                    c.font = _font(bold=True, size=9, color='DC2626')
                else:
                    if 'Overtime' in status or 'After 20' in status:
                        tag, bg, fg = '/ OT', C['ot'], '92400E'
                    elif 'Under Hours' in status:
                        tag, bg, fg = '/ UH', C['uh'], '1E40AF'
                    elif 'Late Clock In' in status:
                        tag, bg, fg = '/ Late', C['late'], 'C2410C'
                    else:
                        tag, bg, fg = '', C['ok'], '1F2937'

                    time_line = (f'{_12h(ci)} - {_12h(co)}' if ci and co
                                 else (ci or co or '—'))
                    net_line  = (f'{net}h {tag}'.strip() if net is not None
                                 else tag.strip() or '—')
                    c.value, c.fill = f'{time_line}\n{net_line}', _fill(bg)
                    c.font = _font(size=8, color=fg)
            else:
                c.fill = _fill('FAFAFA')
                c.font = _font(size=8)

        ws.row_dimensions[rn].height = 36

    # ── Raw data section ───────────────────────────────────────────
    sep_row  = 7 + len(dates) + 2
    max_raw  = max(9, 2 + n_emp)
    ws.merge_cells(f'A{sep_row}:{get_column_letter(max_raw)}{sep_row}')
    c = ws[f'A{sep_row}']
    c.value     = ('Raw Data Area — Paste Lark report here, '
                   'or let Apps Script populate this area automatically')
    c.fill      = _fill(C['sep'])
    c.font      = _font(bold=True, color='CBD5E1', size=8)
    c.alignment = _align('center')
    ws.row_dimensions[sep_row].height = 20

    hdr_row  = sep_row + 1
    raw_hdrs = ['Date', 'Employee', 'Clock In', 'Clock Out',
                'Break', 'Work Hours', 'Status', 'Display Text', 'Key']
    for j, h in enumerate(raw_hdrs):
        c = ws.cell(row=hdr_row, column=j+1, value=h)
        c.fill, c.font = _fill(C['rawh']), _font(bold=True, size=8, color='475569')
        c.alignment, c.border = _align('center'), _border
    ws.row_dimensions[hdr_row].height = 16

    STATUS_TAG = [
        ('OK',            'Normal',    '16A34A'),
        ('Overtime',      'OT Review', 'A16207'),
        ('After 20',      'OT Review', 'A16207'),
        ('Under Hours',   'UH',        'B91C1C'),
        ('Missing',       'MC',        'DC2626'),
        ('Late Clock In', 'Late',      'C2410C'),
    ]

    def _stag(s):
        for key, lbl, color in STATUS_TAG:
            if key in s:
                return lbl, color
        return '—', '94A3B8'

    data_row = hdr_row + 1
    for rec in sorted(records, key=lambda x: (x['date'], x.get('employee_name', ''))):
        ci, co = rec.get('clock_in', ''), rec.get('clock_out', '')
        net    = rec.get('net_hrs')
        slbl, sclr = _stag(rec.get('status', ''))
        display = f'{_12h(ci)} - {_12h(co)}\n{net}h' if ci and co and net is not None else ''
        key     = f"{rec['date']}|{rec.get('employee_name', '')}"
        row_vals = [rec['date'], rec.get('employee_name',''), ci, co,
                    rec.get('break_hrs', 1.0), net, slbl, display, key]
        for j, val in enumerate(row_vals):
            c = ws.cell(row=data_row, column=j+1, value=val)
            c.font      = _font(size=8, color=(sclr if j == 6 else '374151'))
            c.border    = _border
            c.alignment = _align('left', v='center', wrap=(j == 7))
        ws.row_dimensions[data_row].height = 30
        data_row += 1

    # ── Column widths ──────────────────────────────────────────────
    ws.column_dimensions['A'].width = 13
    ws.column_dimensions['B'].width = 5
    for i in range(n_emp):
        ws.column_dimensions[get_column_letter(3+i)].width = 20
    for j, w in enumerate([13, 18, 9, 9, 7, 10, 10, 22, 24], start=1):
        col_l = get_column_letter(j)
        cur = ws.column_dimensions[col_l].width or 0
        if w > cur:
            ws.column_dimensions[col_l].width = w

    ws.freeze_panes = ws['A7']

    # ── Output ─────────────────────────────────────────────────────
    buf = io.BytesIO()
    wb.save(buf)
    excel_bytes = buf.getvalue()
    from_d, to_d = _resolve_export_dates(filters)
    fname = _export_fname('Matrix', from_d, to_d, 'xlsx')
    _persist_export(excel_bytes, fname, 'Ma Trận Chấm Công', from_d, to_d)
    return Response(
        excel_bytes,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment; filename={fname}'},
    )


@app.route('/attendance/delete', methods=['POST'])
@hr_required
def delete_attendance():
    month  = request.form.get('month', '').strip()
    period = request.form.get('period', '').strip() or None

    if not month:
        flash('Cần chọn tháng để xóa.', 'error')
        return redirect(url_for('attendance'))

    deleted = db.delete_attendance(month=month, period=period)
    period_label = {'1': ' Kỳ 1 (1–15)', '2': ' Kỳ 2 (16–31)'}.get(period, '')
    flash(f'✅ Đã xóa {deleted} records của tháng {month}{period_label}.', 'success')
    return redirect(url_for('attendance'))


@app.route('/attendance/<int:att_id>/detail')
@hr_required
def attendance_detail(att_id):
    record = db.get_attendance_by_id(att_id)
    if not record:
        return jsonify({'ok': False, 'error': 'Not found'}), 404
    return jsonify({'ok': True, 'record': dict(record)})


@app.route('/attendance/delete/<int:att_id>', methods=['POST'])
@hr_required
def delete_attendance_record(att_id):
    db.delete_attendance_by_id(att_id)
    return jsonify({'ok': True})


@app.route('/attendance/sync_employees', methods=['POST'])
@hr_required
def sync_attendance_from_employees():
    updated = db.sync_all_from_employees()
    flash(f'✅ Đã sync department/role/name từ Employees cho {updated} records.', 'success')
    return redirect(url_for('attendance'))


@app.route('/attendance/delete_all', methods=['POST'])
@hr_required
def delete_all_attendance():
    deleted = db.delete_all_attendance()
    flash(f'✅ Đã xóa toàn bộ {deleted} records.', 'success')
    return redirect(url_for('attendance'))


# ------------------------------------------------------------------ #
# REVIEW QUEUE
# ------------------------------------------------------------------ #

@app.route('/review')
@hr_required
def review():
    filters = {k: v for k, v in {
        'month':       request.args.get('month'),
        'employee_id': request.args.get('employee_id'),
        'period':      request.args.get('period'),
    }.items() if v}

    records          = db.get_review_queue(filters)
    employees        = db.get_all_employees()
    months           = db.get_distinct_months()
    emp_map          = {e['id']: e for e in employees}
    unresolved_count = sum(1 for r in records if not r.get('action_taken'))

    return render_template('review.html',
                           records=records,
                           employees=employees,
                           emp_map=emp_map,
                           months=months,
                           filters=filters,
                           unresolved_count=unresolved_count)


@app.route('/review/clock_out/<int:att_id>', methods=['POST'])
@hr_required
def correct_clock_out(att_id):
    clock_out   = request.form.get('clock_out', '').strip()
    action      = request.form.get('action_taken', '').strip() or 'Clock out corrected'
    approved_by = request.form.get('approved_by', '').strip()

    if not clock_out:
        return jsonify({'ok': False, 'error': 'Cần nhập giờ clock out'}), 400

    record = db.get_attendance_by_id(att_id)
    if not record:
        return jsonify({'ok': False, 'error': 'Record không tồn tại'}), 404

    emp  = db.get_employee_by_id(record['employee_id']) if record.get('employee_id') else None
    calc = processor.recalculate_from_clockout(
        record['clock_in'], clock_out, record.get('break_hrs') or 1.0, emp
    )
    if not calc:
        return jsonify({'ok': False, 'error': 'Sai định dạng giờ (dùng HH:MM)'}), 400

    old_note = record.get('notes') or ''
    new_note = processor._note(old_note, calc['extra_note']) if calc['extra_note'] else old_note

    db.save_clock_out_correction(att_id, clock_out, calc, new_note, action, approved_by)

    return jsonify({
        'ok':        True,
        'clock_out': clock_out,
        'actual_hrs': calc['actual_hrs'],
        'net_hrs':   calc['net_hrs'],
        'paid_hrs':  calc['paid_hrs'],
        'status':    calc['status'],
    })


@app.route('/review/update/<int:att_id>', methods=['POST'])
@hr_required
def update_review(att_id):
    action      = request.form.get('action_taken', '')
    approved_by = request.form.get('approved_by', '')
    paid_hrs    = request.form.get('paid_hrs', '').strip()

    try:
        paid_val = float(paid_hrs) if paid_hrs else None
        db.update_review(att_id, action, approved_by, paid_val)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400


# ------------------------------------------------------------------ #
# EMPLOYEES & ALIASES
# ------------------------------------------------------------------ #

@app.route('/employees')
@hr_required
def employees():
    return render_template('employees.html',
                           employees=db.get_all_employees(),
                           aliases=db.get_all_aliases())


@app.route('/employees/save', methods=['POST'])
@hr_required
def save_employee():
    checked_days = request.form.getlist('work_days')   # e.g. ['0','1','2','3','4']
    work_days    = ','.join(sorted(set(checked_days))) if checked_days else '0,1,2,3,4'
    data = {
        'id':              request.form.get('id', '').strip().upper(),
        'name':            request.form.get('name', '').strip(),
        'role':            request.form.get('role', '').strip(),
        'department':      request.form.get('department', '').strip(),
        'start_time':      request.form.get('start_time', '09:00'),
        'end_time':        request.form.get('end_time', '18:00'),
        'break_hrs':       request.form.get('break_hrs', '1.0'),
        'max_hrs_day':     request.form.get('max_hrs_day', '8.0'),
        'work_days':       work_days,
        'employment_type': request.form.get('employment_type', 'full_time'),
    }
    if not data['id'] or not data['name']:
        flash('Employee ID và Name là bắt buộc.', 'error')
        return redirect(url_for('employees'))

    db.save_employee(data)
    db.sync_attendance_employee_info(data['id'], data['name'], data['department'], data['role'])
    flash(f"✅ Đã lưu nhân viên {data['name']} và cập nhật attendance records.", 'success')
    return redirect(url_for('employees'))


@app.route('/employees/delete/<emp_id>', methods=['POST'])
@hr_required
def delete_employee(emp_id):
    db.delete_employee(emp_id)
    flash('✅ Đã xóa nhân viên.', 'success')
    return redirect(url_for('employees'))


@app.route('/aliases/save', methods=['POST'])
@hr_required
def save_alias():
    lark_name   = request.form.get('lark_name', '').strip()
    employee_id = request.form.get('employee_id', '').strip()
    notes       = request.form.get('notes', '').strip()

    if not lark_name or not employee_id:
        flash('Lark Name và Employee ID là bắt buộc.', 'error')
        return redirect(url_for('employees'))

    db.save_alias(lark_name, employee_id, notes)
    flash(f'✅ Đã thêm alias "{lark_name}"', 'success')
    return redirect(url_for('employees'))


@app.route('/aliases/delete/<int:alias_id>', methods=['POST'])
@hr_required
def delete_alias(alias_id):
    db.delete_alias(alias_id)
    flash('✅ Đã xóa alias.', 'success')
    return redirect(url_for('employees'))


# ------------------------------------------------------------------ #
# TICKETS — LEAVE & LATE ARRIVAL
# ------------------------------------------------------------------ #

@app.route('/tickets')
@hr_required
def tickets():
    filters = {k: v for k, v in {
        'type':        request.args.get('type'),
        'employee_id': request.args.get('employee_id'),
        'month':       request.args.get('month'),
    }.items() if v}

    all_tickets    = db.get_all_tickets(filters)
    employees      = db.get_all_employees()
    months         = db.get_distinct_months()
    today          = _dt.now().strftime('%Y-%m-%d')
    now            = _dt.now()
    leave_summary  = db.get_employee_leave_summary(now.year, now.month)
    leave_map      = {e['id']: e for e in leave_summary}
    created_ticket = request.args.get('created', '')
    return render_template('tickets.html',
                           tickets=all_tickets,
                           employees=employees,
                           months=months,
                           filters=filters,
                           today=today,
                           leave_map=leave_map,
                           created_ticket=created_ticket,
                           current_user=session.get('display_name', ''))


@app.route('/tickets/create', methods=['POST'])
@hr_required
def create_ticket():
    ticket_type   = request.form.get('type', '').strip()
    employee_id   = request.form.get('employee_id', '').strip()
    leave_date    = request.form.get('leave_date', '').strip()
    leave_date_to = request.form.get('leave_date_to', '').strip()
    reason        = request.form.get('reason', '').strip()
    expected_time = request.form.get('expected_time', '').strip()
    approved_by   = session.get('display_name') or session.get('username', '')

    if ticket_type not in ('annual_leave', 'late_arrival'):
        flash('Loại ticket không hợp lệ.', 'error')
        return redirect(url_for('tickets'))
    if not employee_id or not leave_date:
        flash('Nhân viên và ngày là bắt buộc.', 'error')
        return redirect(url_for('tickets'))

    emp = db.get_employee_by_id(employee_id)
    if not emp:
        flash('Không tìm thấy nhân viên.', 'error')
        return redirect(url_for('tickets'))

    if emp.get('employment_type') == 'part_time':
        if ticket_type == 'annual_leave':
            flash(f'{emp["name"]} là nhân viên Part-time — không áp dụng phép năm.', 'error')
        else:
            flash(f'{emp["name"]} là nhân viên Part-time — lương tính theo giờ thực làm, không cần ticket đi trễ.', 'error')
        return redirect(url_for('tickets'))

    ticket_id = db.create_ticket({
        'type':          ticket_type,
        'employee_id':   employee_id,
        'employee_name': emp['name'],
        'leave_date':    leave_date,
        'leave_date_to': leave_date_to,
        'reason':        reason,
        'expected_time': expected_time,
        'approved_by':   approved_by,
    })

    type_label = 'Nghỉ phép năm' if ticket_type == 'annual_leave' else 'Xin đi trễ'
    date_label = f'{leave_date} → {leave_date_to}' if leave_date_to and leave_date_to != leave_date else leave_date
    flash(f'✅ Đã tạo ticket {ticket_id} — {type_label} cho {emp["name"]} ngày {date_label}.', 'success')
    return redirect(url_for('tickets', created=ticket_id))


@app.route('/tickets/delete/<int:ticket_id>', methods=['POST'])
@hr_required
def delete_ticket(ticket_id):
    db.delete_ticket(ticket_id)
    flash('✅ Đã xóa ticket.', 'success')
    return redirect(url_for('tickets'))


# ------------------------------------------------------------------ #
# MONTHLY REPORT
# ------------------------------------------------------------------ #

@app.route('/report')
@hr_required
def report():
    import calendar as _cal
    months    = db.get_distinct_months()
    from_date = request.args.get('from_date', '').strip()
    to_date   = request.args.get('to_date', '').strip()

    # Quick shortcut: month + period → auto-fill date range
    month  = request.args.get('month', '').strip()
    period = request.args.get('period', '').strip()
    if month and not from_date:
        yr, mo   = map(int, month.split('-'))
        last_day = _cal.monthrange(yr, mo)[1]
        if period == '1':
            from_date, to_date = f'{month}-01', f'{month}-15'
        elif period == '2':
            from_date, to_date = f'{month}-16', f'{month}-{last_day:02d}'
        else:
            from_date, to_date = f'{month}-01', f'{month}-{last_day:02d}'

    report_data = db.get_monthly_report(from_date or None, to_date or None)
    return render_template('report.html',
                           report=report_data,
                           months=months,
                           from_date=from_date,
                           to_date=to_date,
                           current_month=month)


@app.route('/report/employee/<emp_id>')
@hr_required
def report_employee_detail(emp_id):
    from_date = request.args.get('from_date', '') or None
    to_date   = request.args.get('to_date', '')   or None
    records   = db.get_employee_report_detail(emp_id, from_date, to_date)
    return jsonify({'ok': True, 'records': records})


@app.route('/report/export')
@hr_required
def export_report():
    from_date   = request.args.get('from_date', '') or None
    to_date     = request.args.get('to_date', '')   or None
    report_data = db.get_monthly_report(from_date, to_date)

    output = io.StringIO()
    w      = csv.writer(output)
    w.writerow(['Employee ID', 'Name', 'Department', 'Role',
                'Total Days', 'Present Days', 'Total Paid Hrs',
                'Overtime Days', 'Under Hrs Days',
                'Late In Days', 'Missing In Days', 'Missing Out Days',
                'Nghi Khong Phep', 'Nghi Phep Nam', 'Unresolved'])
    for r in report_data:
        w.writerow([
            r['employee_id'], r['employee_name'], r['department'], r['role'],
            r['total_days'], r['present_days'], r['total_paid_hrs'],
            r['overtime_days'], r['under_hrs_days'],
            r['late_in_days'], r['missing_in_days'], r['missing_out_days'],
            r['absent_unpaid_days'], r['absent_paid_days'], r['unresolved_count'],
        ])

    content = output.getvalue()
    fname = _export_fname('Report', from_date or '', to_date or '', 'csv')
    _persist_export(('﻿' + content).encode('utf-8'), fname, 'Báo Cáo Tháng', from_date or '', to_date or '')
    return Response(
        '﻿' + content,
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename={fname}'},
    )


# ------------------------------------------------------------------ #
# EXPORT HISTORY
# ------------------------------------------------------------------ #

@app.route('/exports')
@hr_required
def exports():
    records = db.get_all_exports()
    # Annotate with file-exists flag
    for r in records:
        r['exists'] = os.path.isfile(r.get('filepath', ''))
        r['size_kb'] = round(r['file_size'] / 1024, 1) if r['file_size'] else 0
    return render_template('exports.html', exports=records)


@app.route('/exports/download/<int:export_id>')
@hr_required
def download_export(export_id):
    from flask import send_file
    rec = db.get_export_by_id(export_id)
    if not rec or not os.path.isfile(rec['filepath']):
        flash('File không còn tồn tại trên hệ thống.', 'error')
        return redirect(url_for('exports'))
    ext = rec['filename'].rsplit('.', 1)[-1].lower()
    mime = ('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            if ext == 'xlsx' else 'text/csv; charset=utf-8')
    with open(rec['filepath'], 'rb') as f:
        raw = _decrypt(f.read())
    db.log_audit(session['user_id'], session['username'], 'EXPORT',
                 f'Download: {rec["filename"]}', request.remote_addr)
    return Response(raw, mimetype=mime,
                    headers={'Content-Disposition': f'attachment; filename={rec["filename"]}'})


@app.route('/exports/delete/<int:export_id>', methods=['POST'])
@hr_required
def delete_export(export_id):
    if session.get('role') != 'admin':
        flash('Chỉ Admin mới được xóa file export.', 'error')
        return redirect(url_for('exports'))
    rec = db.get_export_by_id(export_id)
    if rec:
        try:
            if os.path.isfile(rec['filepath']):
                os.remove(rec['filepath'])
        except OSError:
            pass
        db.delete_export_record(export_id)
        flash(f'✅ Đã xóa file {rec["filename"]}.', 'success')
    return redirect(url_for('exports'))


# ------------------------------------------------------------------ #
# USER MANAGEMENT (admin only)
# ------------------------------------------------------------------ #

@app.route('/users')
@hr_required
def manage_users():
    if session.get('role') != 'admin':
        return redirect(url_for('no_access'))
    return render_template('users.html', users=db.get_all_users(),
                           employees=db.get_all_employees(),
                           current_user_id=session.get('user_id'))


@app.route('/users/save', methods=['POST'])
@hr_required
def save_user():
    if session.get('role') != 'admin':
        return redirect(url_for('no_access'))

    username     = request.form.get('username', '').strip()
    display_name = request.form.get('display_name', '').strip()
    role         = request.form.get('role', 'viewer')
    department   = request.form.get('department', '').strip()
    password     = request.form.get('password', '').strip()
    employee_id  = request.form.get('employee_id', '').strip()

    if not username or not password:
        flash('Username và Password là bắt buộc.', 'error')
        return redirect(url_for('manage_users'))

    if role == 'employee' and not employee_id:
        flash('Role "employee" phải được gán với một nhân viên.', 'error')
        return redirect(url_for('manage_users'))

    try:
        db.create_user(username, generate_password_hash(password), display_name, role, department,
                       must_change_password=1, employee_id=employee_id)
        db.log_audit(session['user_id'], session['username'], 'USER_CREATED',
                     f'Tạo user: {username} ({role})', request.remote_addr)
        flash(f'✅ Đã tạo user "{username}". Người dùng sẽ được yêu cầu đổi mật khẩu khi đăng nhập lần đầu.', 'success')
    except Exception as e:
        flash(f'Lỗi: {e}', 'error')
    return redirect(url_for('manage_users'))


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@hr_required
def delete_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('no_access'))
    if user_id == session.get('user_id'):
        flash('Không thể tự xóa tài khoản đang dùng.', 'error')
        return redirect(url_for('manage_users'))
    target = next((u for u in db.get_all_users() if u['id'] == user_id), {})
    db.delete_user(user_id)
    db.log_audit(session['user_id'], session['username'], 'USER_DELETED',
                 f'Xóa user: {target.get("username", user_id)}', request.remote_addr)
    flash('✅ Đã xóa user.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    forced = bool(session.get('must_change_pw'))
    if request.method == 'POST':
        old_pw  = request.form.get('old_password', '')
        new_pw  = request.form.get('new_password', '').strip()
        confirm = request.form.get('confirm_password', '').strip()

        user = db.get_user_by_username(session['username'])
        if not check_password_hash(user['password_hash'], old_pw):
            flash('Mật khẩu cũ không đúng.', 'error')
            return redirect(url_for('change_password'))

        ok, msg = validate_password(new_pw)
        if not ok:
            flash(f'Mật khẩu không hợp lệ: {msg}', 'error')
            return redirect(url_for('change_password'))

        if new_pw != confirm:
            flash('Xác nhận mật khẩu không khớp.', 'error')
            return redirect(url_for('change_password'))

        db.update_user_password(session['user_id'], generate_password_hash(new_pw))
        db.set_must_change_password(session['user_id'], False)
        session.pop('must_change_pw', None)
        db.log_audit(session['user_id'], session['username'], 'PASSWORD_CHANGED', '', request.remote_addr)
        flash('✅ Đã đổi mật khẩu thành công.', 'success')
        return redirect(url_for('index') if forced else
                        (url_for('manage_users') if session['role'] == 'admin' else url_for('index')))

    return render_template('change_password.html', forced=forced)


@app.route('/users/change_password', methods=['POST'])
@login_required
def change_password_legacy():
    """Redirect legacy form submissions to new route."""
    return redirect(url_for('change_password'))


# ------------------------------------------------------------------ #
# EMPLOYEE PORTAL (employee role only)
# ------------------------------------------------------------------ #

@app.route('/portal')
@login_required
def portal():
    if session.get('role') != 'employee':
        return redirect(url_for('index'))

    emp_id = session.get('employee_id', '')
    if not emp_id:
        flash('Tài khoản này chưa được gán với nhân viên nào. Liên hệ admin.', 'error')
        return redirect(url_for('logout'))

    from_date = request.args.get('from_date', '')
    to_date   = request.args.get('to_date', '')

    # Default to current month
    today = _dt.now()
    if not from_date:
        from_date = today.replace(day=1).strftime('%Y-%m-%d')
    if not to_date:
        to_date = today.strftime('%Y-%m-%d')

    with db.get_db() as conn:
        records = conn.execute('''
            SELECT a.*, e.name AS employee_name
            FROM attendance a
            LEFT JOIN employees e ON a.employee_id = e.id
            WHERE a.employee_id = ?
              AND DATE(a.date) BETWEEN ? AND ?
            ORDER BY a.date DESC
        ''', (emp_id, from_date, to_date)).fetchall()

        emp = conn.execute('SELECT * FROM employees WHERE id = ?', (emp_id,)).fetchone()

    # Build summary stats
    total = len(records)
    ok_count      = sum(1 for r in records if '✅' in (r['status'] or ''))
    late_count     = sum(1 for r in records if 'Late' in (r['status'] or '') and 'Out' not in (r['status'] or ''))
    missing_count  = sum(1 for r in records if 'Missing' in (r['status'] or ''))
    ot_count       = sum(1 for r in records if 'Overtime' in (r['status'] or '') or 'After 20' in (r['status'] or ''))

    return render_template('portal.html',
                           records=records,
                           employee=emp,
                           from_date=from_date,
                           to_date=to_date,
                           stats={
                               'total':   total,
                               'ok':      ok_count,
                               'late':    late_count,
                               'missing': missing_count,
                               'ot':      ot_count,
                           })


@app.route('/audit')
@login_required
def audit_log():
    if session.get('role') != 'admin':
        return redirect(url_for('no_access'))
    filters = {k: v for k, v in {
        'action':   request.args.get('action'),
        'username': request.args.get('username'),
    }.items() if v}
    logs      = db.get_audit_logs(limit=1000, filters=filters)
    all_users = db.get_audit_users()
    actions   = [
        'LOGIN', 'LOGIN_FAILED', 'LOGOUT', 'SESSION_EXPIRED',
        'PASSWORD_CHANGED', 'UPLOAD', 'EXPORT', 'TICKET_CREATED',
        'REVIEW_ACTION', 'USER_CREATED', 'USER_DELETED',
        'EMPLOYEE_SAVED', 'RECORD_DELETED',
    ]
    return render_template('audit.html', logs=logs, all_users=all_users,
                           actions=actions, filters=filters)


# ------------------------------------------------------------------ #
# SYSTEM / UPDATE
# ------------------------------------------------------------------ #

_SYSTEM_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'system_config.json')
_APP_DIR            = os.path.dirname(os.path.abspath(__file__))

def _load_sys_config():
    import json
    try:
        with open(_SYSTEM_CONFIG_PATH, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {'github_repo': '', 'branch': 'main', 'version': '1.0.0', 'last_update': ''}

def _save_sys_config(cfg):
    import json
    with open(_SYSTEM_CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


@app.route('/system')
@login_required
def system():
    if session.get('role') != 'admin':
        flash('Chỉ admin mới xem được trang này.', 'error')
        return redirect(url_for('index'))
    import sys, platform, sqlite3
    cfg = _load_sys_config()
    db_path = os.path.join(_APP_DIR, 'attendance.db')
    db_size = round(os.path.getsize(db_path) / 1024, 1) if os.path.exists(db_path) else 0
    return render_template('system.html',
                           cfg=cfg,
                           py_version=sys.version.split()[0],
                           platform=platform.system() + ' ' + platform.release(),
                           db_size=db_size,
                           current_user=session.get('display_name', ''))


@app.route('/system/config', methods=['POST'])
@login_required
def system_config_save():
    if session.get('role') != 'admin':
        return jsonify({'ok': False, 'error': 'Forbidden'}), 403
    cfg = _load_sys_config()
    cfg['github_repo'] = request.form.get('github_repo', '').strip()
    cfg['branch']      = request.form.get('branch', 'main').strip() or 'main'
    _save_sys_config(cfg)
    flash('✅ Đã lưu cấu hình GitHub.', 'success')
    return redirect(url_for('system'))


@app.route('/system/update', methods=['POST'])
@login_required
def system_update():
    if session.get('role') != 'admin':
        return jsonify({'ok': False, 'error': 'Forbidden'}), 403

    import json, urllib.request, urllib.error, zipfile, io, threading, time, sys

    cfg = _load_sys_config()
    repo   = cfg.get('github_repo', '').strip()
    branch = cfg.get('branch', 'main').strip() or 'main'

    if not repo:
        return jsonify({'ok': False, 'error': 'Chưa cấu hình GitHub repo. Vào System → cài đặt trước.'})

    url = f'https://github.com/{repo}/archive/refs/heads/{branch}.zip'
    steps = []

    try:
        steps.append(f'Đang tải từ GitHub: {url}')
        req = urllib.request.Request(url, headers={'User-Agent': 'RichHR-Updater/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            zip_data = resp.read()
        steps.append(f'Tải xong — {round(len(zip_data)/1024, 1)} KB')
    except urllib.error.HTTPError as e:
        return jsonify({'ok': False, 'error': f'Không tải được từ GitHub (HTTP {e.code}). Kiểm tra repo URL và quyền truy cập.', 'steps': steps})
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Lỗi kết nối: {str(e)}', 'steps': steps})

    # Extract — skip database, venv, uploads, __pycache__, system_config.json
    SKIP_PREFIXES = ('venv/', 'uploads/', '__pycache__/', '.git/', '.impeccable/')
    SKIP_SUFFIXES = ('.db', '.sqlite', '.pyc')
    SKIP_FILES    = ('system_config.json',)
    extracted = 0

    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            for name in zf.namelist():
                parts = name.split('/', 1)
                if len(parts) < 2:
                    continue
                rel = parts[1]
                if not rel:
                    continue
                if any(rel.startswith(p) for p in SKIP_PREFIXES):
                    continue
                if any(rel.endswith(s) for s in SKIP_SUFFIXES):
                    continue
                if rel in SKIP_FILES:
                    continue
                target = os.path.join(_APP_DIR, rel.replace('/', os.sep))
                if name.endswith('/'):
                    os.makedirs(target, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(name) as src:
                        with open(target, 'wb') as dst:
                            dst.write(src.read())
                    extracted += 1
        steps.append(f'Giải nén xong — {extracted} files cập nhật')
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Lỗi giải nén: {str(e)}', 'steps': steps})

    # Save update timestamp and version
    cfg['last_update'] = _dt.now().strftime('%Y-%m-%d %H:%M:%S')
    _save_sys_config(cfg)
    steps.append('Đang khởi động lại server…')

    def _restart():
        time.sleep(1.5)
        os.execv(sys.executable, [sys.executable] + sys.argv)

    threading.Thread(target=_restart, daemon=True).start()

    return jsonify({'ok': True, 'steps': steps,
                    'message': 'Cập nhật thành công! Server đang khởi động lại…'})


# ------------------------------------------------------------------ #

if __name__ == '__main__':
    import sys, io as _io
    sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = _io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    print('\n' + '='*50)
    print('  Attendance Management System')
    print('  Mo trinh duyet: http://localhost:5000')
    print('  Nhan Ctrl+C de dung')
    print('='*50 + '\n')
    app.run(debug=False, host='127.0.0.1', port=5000)
