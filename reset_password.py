"""
Emergency password reset — chạy từ command line khi không vào được web UI.

Cách dùng:
  py reset_password.py                     <- liệt kê tất cả users
  py reset_password.py admin               <- reset password cho user "admin"
  py reset_password.py admin NewPass@2026  <- reset không hỏi lại
"""
import sys
import sqlite3
import getpass
from werkzeug.security import generate_password_hash

DB_PATH = 'attendance.db'


def list_users():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        'SELECT username, display_name, role, created_at FROM users ORDER BY username'
    ).fetchall()
    conn.close()
    if not rows:
        print('Không có user nào trong DB.')
        return
    print(f'\n{"USERNAME":<20} {"DISPLAY NAME":<25} {"ROLE":<10} {"CREATED"}')
    print('-' * 75)
    for r in rows:
        print(f'{r[0]:<20} {r[1]:<25} {r[2]:<10} {r[3]}')
    print()


def reset(username, new_password=None):
    conn = sqlite3.connect(DB_PATH)
    row  = conn.execute(
        'SELECT id, username, role FROM users WHERE username = ?', (username,)
    ).fetchone()

    if not row:
        print(f'❌ Không tìm thấy user "{username}".')
        conn.close()
        list_users()
        return

    print(f'\nUser: {row[1]}  (role: {row[2]})')

    if not new_password:
        while True:
            pw  = getpass.getpass('Mật khẩu mới: ')
            pw2 = getpass.getpass('Nhập lại     : ')
            if pw != pw2:
                print('❌ Không khớp. Thử lại.')
                continue
            if len(pw) < 6:
                print('❌ Mật khẩu phải ít nhất 6 ký tự.')
                continue
            new_password = pw
            break

    hashed = generate_password_hash(new_password)
    conn.execute(
        'UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?',
        (hashed, row[0])
    )
    conn.commit()
    conn.close()
    print(f'\n✅ Đã reset mật khẩu cho "{username}" thành công.')
    print('   Bạn có thể đăng nhập ngay trên web.')


if __name__ == '__main__':
    args = sys.argv[1:]

    if not args:
        print(__doc__)
        list_users()
        sys.exit(0)

    username     = args[0]
    new_password = args[1] if len(args) > 1 else None
    reset(username, new_password)
