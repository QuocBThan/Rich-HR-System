"""
Lark Wide-Format Attendance Parser + Calculation Engine
"""
import re
import pandas as pd
import io

CONFIG = {
    'STANDARD_HOURS':      8,
    'DEFAULT_BREAK':       1,
    'MAX_CLOCKOUT_HOUR':   20,
    'UNDER_HOURS_THRESHOLD': 6,
    'DEFAULT_START':       '09:30',
    'LATE_THRESHOLD_MINS': 15,
}

STATUS = {
    'OK':           '✅ OK',
    'OVERTIME':     '🟡 Overtime Review',
    'UNDER_HOURS':  '🔴 Under Hours',
    'MISSING_IN':   '🔴 Missing Clock In',
    'MISSING_OUT':  '🔴 Missing Clock Out',
    'NOT_MATCHED':  '❌ Name Not Matched',
    'LATE_CLOCKOUT':'🟡 Clock Out After 20:00',
    'LATE_IN':      '🟠 Late Clock In',
    'MANUAL':       '⚠️ Manual Review',
}

STATUS_VALUES = list(STATUS.values())

# ------------------------------------------------------------------ #
# FILE PARSING
# ------------------------------------------------------------------ #

def parse_lark_file(file_obj):
    """Parse uploaded Lark XLSX/CSV → flat list of attendance records."""
    filename = file_obj.filename.lower()
    # Seek to start in case stream was already read (Flask/Werkzeug upload)
    try:
        file_obj.stream.seek(0)
    except Exception:
        pass
    content  = file_obj.read()
    print(f'[DEBUG parse_lark_file] filename={filename} content_len={len(content)}', flush=True)
    buf      = io.BytesIO(content)

    if filename.endswith('.csv'):
        df = pd.read_csv(buf, header=None, dtype=str, keep_default_na=False)
    elif filename.endswith(('.xlsx', '.xls')):
        df = pd.read_excel(buf, header=None, dtype=str, keep_default_na=False)
    else:
        raise ValueError('Chỉ hỗ trợ file .xlsx, .xls hoặc .csv')

    data = df.values.tolist()

    print(f'[DEBUG] data rows={len(data)}, cols={len(data[0]) if data else 0}', flush=True)
    if data:
        print(f'[DEBUG] row0[:4]={[str(c)[:20] for c in data[0][:4]]}', flush=True)

    header_idx = _find_header_row(data)
    print(f'[DEBUG] header_idx={header_idx}', flush=True)
    if header_idx < 0:
        raise ValueError('Không tìm thấy dòng header (cột A phải là "Name")')

    result = _parse_wide_format(data[header_idx:])
    print(f'[DEBUG] records parsed={len(result)}', flush=True)
    return result


def _find_header_row(data):
    """
    Find the row that contains date column headers.
    Handles Lark's 2-row header structure:
      Row 0: 'Name' | 'Basic information' | ... | 'Time' | ...
      Row 1:  ''    | 'Department' | ... | '2026-05-15' | '2026-05-16' | ...
    Returns the index of the row that has >= 2 valid date values.
    """
    for i, row in enumerate(data[:5]):
        date_count = sum(1 for cell in row if cell and _parse_date_header(str(cell)))
        if date_count >= 2:
            return i
    return -1


def _parse_wide_format(data):
    """
    Input (data[0] = date-header row):
      Simple:  ['Name', 'Department', '2026-06-01', '2026-06-02', ...]
      Lark:    [''    , 'Department', 'Emp type', 'Hire date', '2026-05-15', ...]

    data[1:] = employee rows (col 0 = name, col 1 = department, col N = attendance cell)

    Output: [{ lark_name, department, date, clock_in, clock_out, cell_note }, ...]
    """
    if len(data) < 2:
        return []

    header  = data[0]
    records = []

    # Department is always col 1 (right after Name), if it's not a date itself
    dept_col = 1 if (len(header) > 1 and not _parse_date_header(str(header[1]))) else -1

    # Find first date column and collect all date columns
    first_date = next(
        (c for c in range(1, len(header)) if _parse_date_header(str(header[c]))),
        -1,
    )

    if first_date < 0:
        return []

    date_cols = [
        (c, _parse_date_header(header[c]))
        for c in range(first_date, len(header))
        if _parse_date_header(header[c])
    ]

    for row in data[1:]:
        raw_name = str(row[0] if row else '').strip()
        if not raw_name or raw_name.lower() == 'nan':
            continue

        dept = str(row[dept_col]).strip() if dept_col >= 0 and dept_col < len(row) else ''
        if dept.lower() == 'nan':
            dept = ''

        for col_idx, date_str in date_cols:
            cell = row[col_idx] if col_idx < len(row) else ''
            parsed = _parse_cell_value(cell)
            if parsed is None:
                continue

            records.append({
                'lark_name':   raw_name,
                'department':  dept,
                'date':        date_str,
                'clock_in':    parsed['clock_in'],
                'clock_out':   parsed['clock_out'],
                'cell_note':   parsed['note'],
            })

    return records


def _parse_date_header(val):
    """Return ISO date string 'yyyy-MM-dd' or None."""
    if not val:
        return None
    s = str(val).strip()
    if s.lower() in ('', 'nan', 'none'):
        return None

    # yyyy-MM-dd  (Lark default)
    if re.match(r'^\d{4}-\d{2}-\d{2}$', s):
        return s

    # dd/MM/yyyy
    m = re.match(r'^(\d{1,2})/(\d{1,2})/(\d{4})$', s)
    if m:
        return f"{m.group(3)}-{m.group(2).zfill(2)}-{m.group(1).zfill(2)}"

    # dd-MM-yyyy
    m = re.match(r'^(\d{1,2})-(\d{1,2})-(\d{4})$', s)
    if m:
        return f"{m.group(3)}-{m.group(2).zfill(2)}-{m.group(1).zfill(2)}"

    return None


def _parse_cell_value(val):
    """
    Parse a Lark attendance cell.
    Returns { clock_in, clock_out, note } or None (absent/empty).

    Formats handled:
      '09:34,18:33'
      '09:34, 18:33'
      '10:05, 18:30 (Late Arrival Approved)'
      '-'  →  None
    """
    if val is None:
        return None

    s = str(val).strip()
    if not s or s.lower() in ('nan', 'none', 'absent', 'off', 'leave'):
        return None
    if re.match(r'^[-–—]+$', s):
        return None

    # Extract parenthesised note at end
    note     = ''
    main_str = s
    note_m   = re.search(r'\(([^)]+)\)\s*$', s)
    if note_m:
        note     = note_m.group(1).strip()
        main_str = s[:s.rfind('(')].strip()

    parts     = main_str.split(',')
    clock_in  = _extract_time(parts[0] if parts else '')
    clock_out = _extract_time(parts[1] if len(parts) > 1 else '')

    if not clock_in and not clock_out:
        return None

    return {'clock_in': clock_in, 'clock_out': clock_out, 'note': note}


def _extract_time(s):
    if not s:
        return ''
    m = re.search(r'(\d{1,2}):(\d{2})', str(s).strip())
    if not m:
        return ''
    return f"{int(m.group(1)):02d}:{m.group(2)}"


# ------------------------------------------------------------------ #
# ATTENDANCE CALCULATION
# ------------------------------------------------------------------ #

def process_records(flat_records, employees, aliases):
    """
    Match employees, calculate hours, flag anomalies.
    Returns (processed_list, review_count).
    """
    emp_map   = {e['id']: e for e in employees}
    alias_map = {a['lark_name'].strip(): a['employee_id'] for a in aliases}

    processed    = []
    review_count = 0

    for rec in flat_records:
        result = _process_single(rec, emp_map, alias_map)
        processed.append(result)
        if result['status'] != STATUS['OK']:
            review_count += 1

    return processed, review_count


def _process_single(rec, emp_map, alias_map):
    lark_name = rec['lark_name']
    match     = _match_employee(lark_name, alias_map, emp_map)

    clock_in  = rec['clock_in']
    clock_out = rec['clock_out']
    t_in      = _parse_time_str(clock_in)
    t_out     = _parse_time_str(clock_out)
    break_hrs = match['emp'].get('break_hrs', CONFIG['DEFAULT_BREAK']) if match['found'] else CONFIG['DEFAULT_BREAK']

    status    = STATUS['OK']
    actual    = None
    net       = None
    paid      = None
    notes     = rec.get('cell_note', '') or ''

    if not match['found']:
        status = STATUS['NOT_MATCHED']
        notes  = _note(notes, f'Không tìm thấy "{lark_name}" trong hệ thống')

    elif not t_in and not t_out:
        status = STATUS['MANUAL']
        notes  = _note(notes, 'Thiếu cả Clock In và Clock Out')

    elif not t_in:
        status = STATUS['MISSING_IN']
        notes  = _note(notes, 'Thiếu Clock In')

    elif not t_out:
        # Record late-in note even when clock-out is missing
        late_mins = _calc_late_mins(t_in, match['emp'])
        if late_mins > CONFIG['LATE_THRESHOLD_MINS']:
            notes = _note(notes, f'Đi muộn {late_mins} phút (vào lúc {clock_in})')
        status = STATUS['MISSING_OUT']
        notes  = _note(notes, 'Thiếu Clock Out')

    else:
        actual = _round(_diff_hours(t_in, t_out))
        net    = _round(max(0.0, actual - break_hrs))

        # Check late clock-in
        late_mins = _calc_late_mins(t_in, match['emp'])
        if late_mins > CONFIG['LATE_THRESHOLD_MINS']:
            notes = _note(notes, f'Đi muộn {late_mins} phút (vào lúc {clock_in})')

        if t_out[0] >= CONFIG['MAX_CLOCKOUT_HOUR']:
            status = STATUS['LATE_CLOCKOUT']
            notes  = _note(notes, f'Clock Out lúc {clock_out} (sau {CONFIG["MAX_CLOCKOUT_HOUR"]}:00)')

        if net > CONFIG['STANDARD_HOURS']:
            status = STATUS['OVERTIME']
            paid   = float(CONFIG['STANDARD_HOURS'])
            ot     = _round(net - CONFIG['STANDARD_HOURS'])
            notes  = _note(notes, f'Overtime +{ot}h → Paid Hrs giữ 8h chờ duyệt')

        elif net < CONFIG['UNDER_HOURS_THRESHOLD']:
            status = STATUS['UNDER_HOURS']
            paid   = net
            notes  = _note(notes, f'Chỉ làm {net}h (dưới {CONFIG["UNDER_HOURS_THRESHOLD"]}h)')

        else:
            paid = _round(min(net, CONFIG['STANDARD_HOURS']))
            # Only flag pure late-in when no other issue
            if status == STATUS['OK'] and late_mins > CONFIG['LATE_THRESHOLD_MINS']:
                status = STATUS['LATE_IN']

    emp = match['emp'] if match['found'] else {}

    return {
        'date':          rec['date'],
        'employee_id':   emp.get('id', ''),
        'employee_name': emp.get('name', lark_name),
        'lark_name':     lark_name,
        'department':    emp.get('department', '') or rec.get('department', ''),
        'role':          emp.get('role', ''),
        'clock_in':      clock_in,
        'clock_out':     clock_out,
        'actual_hrs':    actual,
        'break_hrs':     break_hrs,
        'net_hrs':       net,
        'paid_hrs':      paid,
        'status':        status,
        'notes':         notes,
    }


def recalculate_from_clockout(clock_in_str, clock_out_str, break_hrs, emp=None):
    """Recalculate all time fields after correcting a missing clock-out.
    Returns dict of updated fields, or None on invalid input."""
    t_in  = _parse_time_str(clock_in_str)
    t_out = _parse_time_str(clock_out_str)
    if not t_in or not t_out:
        return None

    actual     = _round(_diff_hours(t_in, t_out))
    net        = _round(max(0.0, actual - break_hrs))
    extra_note = []
    status     = STATUS['OK']

    if t_out[0] >= CONFIG['MAX_CLOCKOUT_HOUR']:
        status = STATUS['LATE_CLOCKOUT']
        extra_note.append(f'Clock Out lúc {clock_out_str} (sau {CONFIG["MAX_CLOCKOUT_HOUR"]}:00)')

    if net > CONFIG['STANDARD_HOURS']:
        status = STATUS['OVERTIME']
        paid   = float(CONFIG['STANDARD_HOURS'])
        ot     = _round(net - CONFIG['STANDARD_HOURS'])
        extra_note.append(f'Overtime +{ot}h')
    elif net < CONFIG['UNDER_HOURS_THRESHOLD']:
        status = STATUS['UNDER_HOURS']
        paid   = net
        extra_note.append(f'Chỉ làm {net}h')
    else:
        paid      = _round(min(net, CONFIG['STANDARD_HOURS']))
        late_mins = _calc_late_mins(t_in, emp or {})
        if late_mins > CONFIG['LATE_THRESHOLD_MINS']:
            status = STATUS['LATE_IN']
            extra_note.append(f'Đi muộn {late_mins} phút')

    return {
        'actual_hrs': actual,
        'net_hrs':    net,
        'paid_hrs':   paid,
        'status':     status,
        'extra_note': ' | '.join(extra_note),
    }


def _calc_late_mins(t_in, emp):
    """Return minutes late vs employee start_time (negative = early)."""
    start_str = emp.get('start_time', CONFIG['DEFAULT_START']) if emp else CONFIG['DEFAULT_START']
    start_t   = _parse_time_str(start_str)
    if not start_t or not t_in:
        return 0
    return (t_in[0] * 60 + t_in[1]) - (start_t[0] * 60 + start_t[1])


def _match_employee(lark_name, alias_map, emp_map):
    if not lark_name:
        return {'found': False, 'emp': {}}

    norm = lark_name.lower().strip()

    # 1. Exact alias match
    for alias, emp_id in alias_map.items():
        if alias.lower().strip() == norm:
            emp = emp_map.get(emp_id)
            if emp:
                return {'found': True, 'emp': emp}

    # 2. Partial alias match
    for alias, emp_id in alias_map.items():
        a = alias.lower().strip()
        if a and (a in norm or norm in a):
            emp = emp_map.get(emp_id)
            if emp:
                return {'found': True, 'emp': emp}

    # 3. Direct employee name
    for emp in emp_map.values():
        n = emp['name'].lower().strip()
        if n and (n == norm or norm in n or n in norm):
            return {'found': True, 'emp': emp}

    return {'found': False, 'emp': {}}


def _parse_time_str(s):
    if not s:
        return None
    m = re.match(r'^(\d{1,2}):(\d{2})$', str(s).strip())
    return (int(m.group(1)), int(m.group(2))) if m else None


def _diff_hours(t1, t2):
    mins = (t2[0] * 60 + t2[1]) - (t1[0] * 60 + t1[1])
    return max(0.0, mins / 60.0)


def _round(n):
    return round(n, 2)


def _note(existing, new):
    return f"{existing} | {new}" if existing else new
