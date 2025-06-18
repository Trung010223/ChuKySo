from flask import Flask, session, redirect, url_for
from auth import auth_bp
from file_transfer import file_bp

app = Flask(__name__)
app.secret_key = 'r@nd0m_s3cr3t_k3y'

# ⚠️ Gắn tiền tố URL đúng cho blueprint
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(file_bp, url_prefix='/file')

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('file.dashboard'))  # -> /file/dashboard
    return redirect(url_for('auth.login'))          # -> /auth/login

if __name__ == '__main__':
    app.run(debug=True)
