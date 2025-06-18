from flask import Blueprint, request, render_template, redirect, url_for, session, flash, send_file
import os, hashlib, json
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

file_bp = Blueprint('file', __name__, template_folder='templates')

UPLOAD_FOLDER = 'uploads'
RECEIVE_FOLDER = 'received'
KEY_FOLDER = 'keys'
RECORD_FILE = 'file_records.json'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RECEIVE_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

# Tạo khóa RSA nếu chưa có
def generate_keys(username):
    priv_path = os.path.join(KEY_FOLDER, f'{username}_private.pem')
    pub_path = os.path.join(KEY_FOLDER, f'{username}_public.pem')
    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(priv_path, 'wb') as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))

        with open(pub_path, 'wb') as f:
            f.write(public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))

# Lưu lịch sử gửi file
def save_record(data):
    records = []
    if os.path.exists(RECORD_FILE):
        with open(RECORD_FILE, 'r') as f:
            try:
                records = json.load(f)
            except json.JSONDecodeError:
                records = []

    records.append(data)
    with open(RECORD_FILE, 'w') as f:
        json.dump(records, f, indent=2)

@file_bp.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    return render_template('dashboard.html', username=session['username'])

@file_bp.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        file = request.files.get('file')
        recipient = request.form.get('recipient')
        sender = session['username']
        signature_hex = request.form.get('signature')  # 👈 Nhận chữ ký số từ người gửi

        if file and recipient and signature_hex:
            generate_keys(sender)
            filename = f"{sender}_{file.filename}"
            path = os.path.join(RECEIVE_FOLDER, filename)
            file.save(path)

            with open(path, 'rb') as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()

            save_record({
                "from": sender,
                "to": recipient,
                "filename": file.filename,
                "stored_as": filename,
                "hash": file_hash,
                "signature": signature_hex.strip(),
                "time": datetime.now().isoformat()
            })

            flash("📦 Gửi file thành công.")
            return redirect(url_for('file.dashboard'))
        else:
            flash("⚠️ Vui lòng điền đầy đủ thông tin và chữ ký số.")

    return render_template('upload.html')

@file_bp.route('/received')
def received_files():
    if 'username' not in session:
        return redirect(url_for('auth.login'))

    user = session['username']
    records = []
    if os.path.exists(RECORD_FILE):
        with open(RECORD_FILE, 'r') as f:
            try:
                records = json.load(f)
            except json.JSONDecodeError:
                records = []

    my_files = [r for r in records if r.get('to') == user]

    for r in my_files:
        r['verified'] = False
        try:
            pub_key_path = os.path.join(KEY_FOLDER, f"{r.get('from')}_public.pem")
            file_path = os.path.join(RECEIVE_FOLDER, r.get('stored_as'))
            if os.path.exists(pub_key_path) and os.path.exists(file_path):
                with open(pub_key_path, 'rb') as f:
                    public_key = serialization.load_pem_public_key(f.read())
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                public_key.verify(
                    bytes.fromhex(r.get('signature', '')),
                    file_data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                r['verified'] = True
        except Exception:
            r['verified'] = False

    return render_template('received_files.html', files=my_files)

@file_bp.route('/verify_download/<filename>', methods=['GET', 'POST'])
def verify_download(filename):
    if 'username' not in session:
        return redirect(url_for('auth.login'))

    file_path = os.path.join(RECEIVE_FOLDER, filename)
    if not os.path.exists(file_path):
        flash("❌ File không tồn tại.")
        return redirect(url_for('file.received_files'))

    if request.method == 'POST':
        user_input_signature = request.form.get('signature')
        if not user_input_signature:
            flash("⚠️ Bạn phải nhập chữ ký số.")
            return redirect(request.url)

        with open(RECORD_FILE, 'r') as f:
            try:
                records = json.load(f)
            except json.JSONDecodeError:
                records = []

        record = next((r for r in records if r.get('stored_as') == filename), None)
        if not record:
            flash("❌ Không tìm thấy thông tin file.")
            return redirect(url_for('file.received_files'))

        file_data = open(file_path, 'rb').read()
        try:
            actual_signature = record.get('signature', '')
            if user_input_signature.strip() == actual_signature:
                flash("✅ Chữ ký số hợp lệ. Đang tải file...")
                return send_file(file_path, as_attachment=True)
            else:
                flash("❌ Chữ ký không khớp với hệ thống.")
                return redirect(request.url)
        except Exception:
            flash("❌ Lỗi xác minh chữ ký.")
            return redirect(request.url)

    return render_template('verify_signature.html', filename=filename)
