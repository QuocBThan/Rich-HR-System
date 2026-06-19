"""Carrier tracking integration — UPS & USPS (OAuth 2.0 REST APIs).

Credentials live in system_config.json (managed from the Tracking page):
    ups_client_id, ups_client_secret, ups_test
    usps_client_id, usps_client_secret
Pure functions — the Flask app passes the config dict in and persists results.
"""
import base64
import json as _json
import re
import urllib.request
import urllib.error


# ------------------------------------------------------------------ #
# Carrier detection / extraction
# ------------------------------------------------------------------ #

def detect_carrier(num):
    """Guess the carrier from a tracking number's format."""
    if not num:
        return ''
    n = re.sub(r'\s+', '', str(num)).upper()
    if n.startswith('1Z'):
        return 'ups'
    # USPS Intelligent Mail / impb: 20-22 digits, often starts 92/93/94/95/82
    if re.fullmatch(r'(92|93|94|95|82|94)\d{18,20}', n):
        return 'usps'
    if re.fullmatch(r'\d{20,22}', n):
        return 'usps'
    # USPS international S10: 2 letters + 9 digits + US
    if re.fullmatch(r'[A-Z]{2}\d{9}US', n):
        return 'usps'
    # UPS alphanumeric fallback (e.g. T-prefixed) — treat 18-char alnum as UPS
    if re.fullmatch(r'1Z[0-9A-Z]{16}', n):
        return 'ups'
    return ''


_UPS_RE  = re.compile(r'\b1Z[0-9A-Z]{16}\b', re.I)
_USPS_RE = re.compile(r'\b(?:92|93|94|95|82)\d{18,20}\b|\b\d{20,22}\b')


def extract_tracking(text):
    """Pull the first tracking number out of a free-text note. Returns (num, carrier)."""
    if not text:
        return '', ''
    m = _UPS_RE.search(str(text))
    if m:
        return m.group(0).upper(), 'ups'
    m = _USPS_RE.search(str(text))
    if m:
        return m.group(0), 'usps'
    return '', ''


# ------------------------------------------------------------------ #
# UPS  —  https://developer.ups.com  (Tracking API + OAuth client_credentials)
# ------------------------------------------------------------------ #

def _ups_base(cfg):
    return 'https://wwwcie.ups.com' if cfg.get('ups_test') else 'https://onlinetools.ups.com'


def ups_token(cfg):
    cid = (cfg.get('ups_client_id') or '').strip()
    sec = (cfg.get('ups_client_secret') or '').strip()
    if not cid or not sec:
        return None
    url  = _ups_base(cfg) + '/security/v1/oauth/token'
    auth = base64.b64encode(f'{cid}:{sec}'.encode()).decode()
    req  = urllib.request.Request(
        url, data=b'grant_type=client_credentials',
        headers={'Authorization': f'Basic {auth}',
                 'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return _json.loads(resp.read()).get('access_token')
    except Exception:
        return None


def ups_track(cfg, token, num):
    url = _ups_base(cfg) + f'/api/track/v1/details/{num}'
    req = urllib.request.Request(url, headers={
        'Authorization':  f'Bearer {token}',
        'transId':        'richhr-tracking',
        'transactionSrc': 'richhr',
        'Accept':         'application/json',
    })
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = _json.loads(resp.read())
    try:
        pkg = data['trackResponse']['shipment'][0]['package'][0]
    except (KeyError, IndexError, TypeError):
        return {'status': '', 'code': '', 'delivered': False, 'when': ''}
    cur   = pkg.get('currentStatus', {}) or {}
    acts  = pkg.get('activity', []) or []
    last  = (acts[0] if acts else {}) or {}
    lstat = last.get('status', {}) or {}
    code  = cur.get('type') or lstat.get('type') or ''
    desc  = cur.get('description') or lstat.get('description') or ''
    return {
        'status':    desc,
        'code':      code,
        'delivered': code == 'D',
        'when':      f"{last.get('date','')} {last.get('time','')}".strip(),
    }


# ------------------------------------------------------------------ #
# USPS  —  https://developer.usps.com  (Tracking 3.0 + OAuth client_credentials)
# ------------------------------------------------------------------ #

def usps_token(cfg):
    cid = (cfg.get('usps_client_id') or '').strip()
    sec = (cfg.get('usps_client_secret') or '').strip()
    if not cid or not sec:
        return None
    url  = 'https://apis.usps.com/oauth2/v3/token'
    body = _json.dumps({'client_id': cid, 'client_secret': sec,
                        'grant_type': 'client_credentials'}).encode()
    req  = urllib.request.Request(url, data=body,
                                  headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return _json.loads(resp.read()).get('access_token')
    except Exception:
        return None


def usps_track(cfg, token, num):
    url = f'https://apis.usps.com/tracking/v3/tracking/{num}?expand=DETAIL'
    req = urllib.request.Request(url, headers={
        'Authorization': f'Bearer {token}',
        'Accept':        'application/json',
    })
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = _json.loads(resp.read())
    summary = data.get('statusSummary') or data.get('status') or ''
    events  = data.get('trackingEvents', []) or []
    last    = (events[0] if events else {}) or {}
    status  = summary or last.get('eventType', '')
    return {
        'status':    status,
        'code':      last.get('eventCode', ''),
        'delivered': 'delivered' in str(status).lower(),
        'when':      last.get('eventTimestamp', ''),
    }


# ------------------------------------------------------------------ #
# Unified entry — token cache per carrier for batch use
# ------------------------------------------------------------------ #

class Tracker:
    """Caches one OAuth token per carrier across a batch of lookups."""
    def __init__(self, cfg):
        self.cfg = cfg
        self._tok = {}

    def _token(self, carrier):
        if carrier not in self._tok:
            self._tok[carrier] = ups_token(self.cfg) if carrier == 'ups' else usps_token(self.cfg)
        return self._tok[carrier]

    def track(self, num, carrier=None):
        carrier = carrier or detect_carrier(num)
        if carrier not in ('ups', 'usps'):
            raise RuntimeError(f'Không nhận diện được hãng vận chuyển cho mã: {num}')
        tok = self._token(carrier)
        if not tok:
            raise RuntimeError(f'{carrier.upper()}: chưa cấu hình API hoặc lấy token thất bại')
        result = ups_track(self.cfg, tok, num) if carrier == 'ups' else usps_track(self.cfg, tok, num)
        result['carrier'] = carrier
        return result
