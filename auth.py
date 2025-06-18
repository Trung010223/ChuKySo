from flask import Blueprint, request, render_template, redirect, url_for, session, flash
import hashlib, json, os

auth_bp = Blueprint('auth', __name__, template_folder='templates')

USER_FILE = 'users.json'

# Tải danh sách người dùng từ file JSON
def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r') as f:
            try:
                content = f.read().strip()
                return json.loads(content) if content else {}
            except json.JSONDecodeError:
                flash("⚠️ File người dùng bị lỗi định dạng JSON!", "danger")
                return {}
    return {}

# Lưu danh sách người dùng vào file JSON
def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f, indent=4)

# ------------------------
# Đăng nhập
# ------------------------
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            flash("⚠️ Vui lòng nhập đầy đủ thông tin!", "warning")
        else:
            hashed = hashlib.sha256(password.encode()).hexdigest()
            if users.get(username) == hashed:
                session['username'] = username
                flash(f"✅ Chào mừng {username}!", "success")
                return redirect(url_for('file.dashboard'))
            flash("❌ Sai tài khoản hoặc mật khẩu!", "danger")
    return render_template('login.html')

# ------------------------
# Đăng ký
# ------------------------
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            flash("⚠️ Vui lòng điền đầy đủ thông tin.", "warning")
        elif username in users:
            flash("❌ Tên người dùng đã tồn tại!", "danger")
        else:
            users[username] = hashlib.sha256(password.encode()).hexdigest()
            save_users(users)
            flash("✅ Đăng ký thành công! Vui lòng đăng nhập.", "success")
            return redirect(url_for('auth.login'))

    return render_template('register.html')

# ------------------------
# Đăng xuất
# ------------------------
@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("ℹ️ Đăng xuất thành công.", "info")
    return redirect(url_for('auth.login'))
