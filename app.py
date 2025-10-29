from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, random, datetime, time
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "your_secret_key_here"

# 🔐 Set session timeout to 5 minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

# ===== MAIL CONFIG =====
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='mohammedibrahim0821@gmail.com',      # replace with your email
    MAIL_PASSWORD='odddijafmwvlcrpe'                    # Gmail App password
)
mail = Mail(app)

# ===== DATABASE =====
def init_db():
    with sqlite3.connect("users.db") as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT
        )""")
init_db()

def get_user(email):
    with sqlite3.connect("users.db") as con:
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()

# ===== OTP =====
def send_otp(email):
    otp = str(random.randint(100000, 999999))
    expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)
    session['otp'] = otp
    session['otp_expiry'] = expiry.strftime("%Y-%m-%d %H:%M:%S")
    msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your OTP is {otp}. It is valid for 5 minutes.'
    mail.send(msg)
    print(f"OTP for {email}: {otp}")  # debugging
    return otp

# ===== ROUTES =====
@app.route('/')
def index():
    return redirect(url_for('login'))

# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user(email)
        if user and check_password_hash(user[3], password):
            send_otp(email)
            session['email'] = email
            session['mode'] = 'login'
            flash("OTP sent to your email.", "info")
            return redirect(url_for('verify'))
        else:
            flash("Invalid credentials or email not registered.", "danger")
    return render_template('login.html')

# ---------- REGISTER ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        try:
            with sqlite3.connect("users.db") as con:
                con.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                            (name, email, password))
            send_otp(email)
            session['email'] = email
            session['mode'] = 'register'
            flash("Registered! OTP sent to verify your account.", "success")
            return redirect(url_for('verify'))
        except sqlite3.IntegrityError:
            flash("Email already registered. Try logging in.", "warning")
            return redirect(url_for('login'))
    return render_template('register.html')

# ---------- VERIFY OTP ----------
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        otp_in = request.form['otp']
        otp = session.get('otp')
        expiry = session.get('otp_expiry')

        if not otp or not expiry:
            flash("Session expired. Please request a new OTP.", "warning")
            return redirect(url_for('login'))

        expiry_time = datetime.datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() > expiry_time:
            flash("OTP expired. Please resend.", "danger")
            return redirect(url_for('resend_otp'))

        if otp_in == otp:
            session.pop('otp', None)
            session.pop('otp_expiry', None)
            if session.get('mode') in ['login', 'register']:
                session['logged_in'] = True
                flash("OTP verified successfully!", "success")
                return redirect(url_for('ogl'))  # redirect to OGL
            elif session.get('mode') == 'reset':
                return redirect(url_for('reset_password'))
        else:
            flash("Invalid OTP. Try again.", "danger")

    # This renders the OTP form when GET request happens
    return render_template('otp.html')

# ---------- RESEND OTP ----------
@app.route('/resend-otp')
def resend_otp():
    email = session.get('email')
    if email:
        send_otp(email)
        flash("New OTP sent to your email.", "info")
    return redirect(url_for('verify'))

# ---------- HOME ----------
#@app.route('/home')
#def home():
#    if session.get('logged_in'):
#        user = get_user(session['email'])
#        return render_template('home.html', name=user[1])
#    flash("Please login first.", "warning")
#    return redirect(url_for('login'))

# ---------- OGL PAGE (PROTECTED ACCESS) ----------
@app.route('/open_ogl')
def open_ogl():
    if session.get('logged_in'):
        # Only accessible after login
        return redirect("https://aathiguru0508.github.io/OGL_STEP_GUIDES_LINK")
    else:
        flash("Please login first to access this page.", "warning")
        return redirect(url_for('login'))

# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# ---------- FORGOT PASSWORD ----------
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        user = get_user(email)
        if user:
            session['email'] = email
            session['mode'] = 'reset'
            send_otp(email)
            flash("OTP sent to your email to reset password.", "info")
            return redirect(url_for('verify'))
        else:
            flash("Email not registered.", "danger")
    return render_template('forgot.html')

# ---------- RESET PASSWORD ----------
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_pass = generate_password_hash(request.form['password'])
        with sqlite3.connect("users.db") as con:
            con.execute("UPDATE users SET password=? WHERE email=?", (new_pass, session['email']))
        flash("Password reset successful. Please login.", "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# ---------- PROTECTED OGL LINK ----------
@app.route('/ogl')
def ogl():
    if not session.get('logged_in'):
        flash("Please log in to access OGL Step Guides.", "warning")
        return redirect(url_for('login'))
    return render_template('ogl.html')

# ---------- SESSION TIME LOGOUT ------------
@app.before_request
def session_timeout_check():
    session.permanent = True  # Enable session lifetime tracking
    session.modified = True
    now = time.time()
    
    if 'last_activity' in session:
        # Check inactivity
        if now - session['last_activity'] > 300:  # 5 minutes = 300 seconds
            session.clear()
            flash("Session expired due to inactivity. Please log in again.", "warning")
            return redirect(url_for('login'))
    
    # Update activity timestamp
    session['last_activity'] = now

# ---------- RUN APP ----------
if __name__ == '__main__':
    import webbrowser
    webbrowser.open("http://127.0.0.1:5000/")
    app.run(debug=True)