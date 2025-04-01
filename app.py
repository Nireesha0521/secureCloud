import os
import psycopg2
from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64
import io
import uuid
import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-random-secret-key-123')

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
mail = Mail(app)

# Database Connection
def get_db_connection():
    return psycopg2.connect(os.environ['DATABASE_URL'])

def init_db():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            username VARCHAR(50) NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            filename VARCHAR(255) NOT NULL,
            manual_filename VARCHAR(255) NOT NULL,
            encrypted_data TEXT NOT NULL,
            nonce TEXT NOT NULL,
            tag TEXT NOT NULL,
            encrypted_keyword TEXT NOT NULL,
            metadata TEXT NOT NULL,
            upload_date TIMESTAMP NOT NULL,
            shared_with INTEGER REFERENCES users(id),
            share_token VARCHAR(100)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS password_resets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            token VARCHAR(100) NOT NULL,
            created_at TIMESTAMP NOT NULL
        )''')
        c.execute("SELECT 1 FROM users WHERE email = %s", ('admin@example.com',))
        if not c.fetchone():
            c.execute("INSERT INTO users (email, password, username) VALUES (%s, %s, %s)",
                      ('admin@example.com', generate_password_hash('admin123'), 'admin'))
        conn.commit()
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        if conn: conn.rollback()
        raise e
    finally:
        if conn: conn.close()

# Encryption Helpers
def derive_key(keyword):
    hasher = SHA256.new()
    hasher.update(keyword.encode('utf-8'))
    return hasher.digest()

def encrypt_keyword(keyword):
    key = derive_key(app.secret_key)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(keyword.encode('utf-8'))
    return (base64.b64encode(ciphertext).decode('utf-8'),
            base64.b64encode(nonce).decode('utf-8'),  # Fixed: 'utf-8'
            base64.b64encode(tag).decode('utf-8'))

def decrypt_keyword(encrypted_keyword, nonce, tag):
    key = derive_key(app.secret_key)
    encrypted_keyword = base64.b64decode(encrypted_keyword)
    nonce = base64.b64decode(nonce)
    tag = base64.b64decode(tag)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_keyword = cipher.decrypt_and_verify(encrypted_keyword, tag)
    return decrypted_keyword.decode('utf-8')

# Routes
@app.route('/')
def index():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, manual_filename, user_id, encrypted_keyword, nonce, tag, upload_date FROM files")
    files = c.fetchall()
    file_list = []
    for file in files:
        c.execute("SELECT username FROM users WHERE id = %s", (file[2],))
        username = c.fetchone()
        file_list.append({
            'id': file[0],
            'manual_filename': file[1],
            'uploader': username[0] if username else "Unknown",
            'encrypted_keyword': file[3],
            'nonce': file[4],
            'tag': file[5],
            'upload_date': file[6]
        })
    conn.close()
    return render_template('index.html', files=file_list)

@app.route('/search_filename', methods=['POST'])
def search_filename():
    search_term = request.form['search_term']
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, manual_filename, user_id, encrypted_keyword, upload_date FROM files WHERE manual_filename ILIKE %s",
              (f'%{search_term}%',))
    files = c.fetchall()
    file_list = []
    for file in files:
        c.execute("SELECT username FROM users WHERE id = %s", (file[2],))
        username = c.fetchone()
        file_list.append({
            'id': file[0],
            'manual_filename': file[1],
            'uploader': username[0] if username else "Unknown",
            'encrypted_keyword': file[3],
            'upload_date': file[4]
        })
    conn.close()
    return render_template('index.html', files=file_list, search_term=search_term)

@app.route('/search_keyword', methods=['GET', 'POST'])
def search_keyword():
    if request.method == 'POST':
        keyword = request.form['keyword']
        key = derive_key(keyword)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, manual_filename, encrypted_data, nonce, tag FROM files")
        files = c.fetchall()
        matching_files = []
        for file in files:
            try:
                encrypted_data = base64.b64decode(file[2])
                nonce = base64.b64decode(file[3])
                tag = base64.b64decode(file[4])
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                cipher.decrypt_and_verify(encrypted_data, tag)
                matching_files.append({'id': file[0], 'manual_filename': file[1]})
            except:
                continue
        conn.close()
        if matching_files:
            flash(f'Found {len(matching_files)} file(s) encrypted with keyword "{keyword}".', 'success')
        else:
            flash(f'No files found with keyword "{keyword}".', 'danger')
        return render_template('search_keyword.html', files=matching_files, keyword=keyword)
    return render_template('search_keyword.html', files=None)

@app.route('/decrypt_keyword/<int:file_id>', methods=['GET', 'POST'])
def decrypt_keyword_route(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT manual_filename, encrypted_keyword, nonce, tag, user_id, shared_with FROM files WHERE id = %s",
              (file_id,))
    file = c.fetchone()
    if not file or (file[4] != session['user_id'] and file[5] != session['user_id']):
        flash('File not found or you do not have access.', 'danger')
        conn.close()
        return redirect(url_for('index'))
    if request.method == 'POST':
        try:
            decrypted_keyword = decrypt_keyword(file[1], file[2], file[3])
            flash(f'The keyword for "{file[0]}" is: {decrypted_keyword}', 'success')
        except Exception as e:
            flash(f'Failed to decrypt keyword: {e}', 'danger')
        return redirect(url_for('index'))
    conn.close()
    return render_template('decrypt_keyword.html', file_id=file_id, manual_filename=file[0])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        hashed_password = generate_password_hash(password)
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO users (email, password, username) VALUES (%s, %s, %s) RETURNING id",
                      (email, hashed_password, username))
            conn.commit()
            conn.close()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except psycopg2.Error as e:
            flash(f'Registration failed: {e}', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, password, username FROM users WHERE email = %s", (email,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = user[2]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = c.fetchone()
        if user:
            token = str(uuid.uuid4())
            c.execute("INSERT INTO password_resets (user_id, token, created_at) VALUES (%s, %s, %s)",
                      (user[0], token, datetime.datetime.utcnow()))
            conn.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Click to reset your password: {reset_link}\nExpires in 1 hour.'
            mail.send(msg)
            flash('Reset link sent to your email.', 'success')
        else:
            flash('Email not found.', 'danger')
        conn.close()
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT user_id, created_at FROM password_resets WHERE token = %s", (token,))
    reset_request = c.fetchone()
    if not reset_request or (datetime.datetime.utcnow() - reset_request[1]).total_seconds() > 3600:
        flash('Invalid or expired reset link.', 'danger')
        if reset_request:
            c.execute("DELETE FROM password_resets WHERE token = %s", (token,))
            conn.commit()
        conn.close()
        return redirect(url_for('login'))
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'])
        c.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, reset_request[0]))
        c.execute("DELETE FROM password_resets WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        flash('Password reset successfully!', 'success')
        return redirect(url_for('login'))
    conn.close()
    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, manual_filename FROM files WHERE user_id = %s OR shared_with = %s",
              (session['user_id'], session['user_id']))
    files = c.fetchall()
    conn.close()
    return render_template('dashboard.html', files=files)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email, username FROM users WHERE id = %s", (session['user_id'],))
    user = c.fetchone()
    c.execute("SELECT COUNT(*) FROM files WHERE user_id = %s", (session['user_id'],))
    upload_count = c.fetchone()[0]
    conn.close()
    return render_template('profile.html', email=user[0], username=user[1], upload_count=upload_count)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        manual_filename = request.form['manual_filename']
        keyword = request.form['keyword']
        if not file or not manual_filename or not keyword:
            flash('All fields are required.', 'danger')
            return redirect(url_for('upload'))
        file_data = file.read()
        original_filename = file.filename
        file_size = len(file_data)
        upload_date = datetime.datetime.utcnow()
        metadata = f"Original Filename: {original_filename}, Size: {file_size} bytes, Uploaded: {upload_date}"
        key = derive_key(keyword)
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(file_data)
        encrypted_data_b64 = base64.b64encode(ciphertext).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')  # Fixed: 'utf-8'
        tag_b64 = base64.b64encode(tag).decode('utf-8')
        encrypted_keyword, keyword_nonce, keyword_tag = encrypt_keyword(keyword)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO files (user_id, filename, manual_filename, encrypted_data, nonce, tag, encrypted_keyword, metadata, upload_date) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                  (session['user_id'], original_filename, manual_filename, encrypted_data_b64, nonce_b64, tag_b64, encrypted_keyword, metadata, upload_date))
        conn.commit()
        conn.close()
        flash('File uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('upload.html')

@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
def download(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT manual_filename, encrypted_data, nonce, tag, user_id, shared_with FROM files WHERE id = %s",
              (file_id,))
    file = c.fetchone()
    if not file or (file[4] != session['user_id'] and file[5] != session['user_id']):
        flash('File not found or no access.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        keyword = request.form['keyword']
        encrypted_data = base64.b64decode(file[1])
        nonce = base64.b64decode(file[2])
        tag = base64.b64decode(file[3])
        key = derive_key(keyword)
        try:
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
            return send_file(io.BytesIO(decrypted_data), download_name=file[0], as_attachment=True)
        except Exception as e:
            flash(f'Decryption failed: {e} (wrong keyword?)', 'danger')
            return redirect(url_for('download', file_id=file_id))
    conn.close()
    return render_template('download.html', file_id=file_id)

@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
def share(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT user_id FROM files WHERE id = %s", (file_id,))
    file = c.fetchone()
    if not file or file[0] != session['user_id']:
        flash('File not found or no permission.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email']
        c.execute("SELECT id FROM users WHERE email = %s", (email,))
        recipient = c.fetchone()
        if not recipient:
            flash('User not found.', 'danger')
            conn.close()
            return redirect(url_for('dashboard'))
        share_token = str(uuid.uuid4())
        c.execute("UPDATE files SET shared_with = %s, share_token = %s WHERE id = %s",
                  (recipient[0], share_token, file_id))
        conn.commit()
        share_link = url_for('access_shared_file', token=share_token, _external=True)
        msg = Message('File Shared with You', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'A file has been shared with you: {share_link}\nYou need the keyword to decrypt it.'
        mail.send(msg)
        flash('File shared successfully!', 'success')
        conn.close()
        return redirect(url_for('dashboard'))
    conn.close()
    return render_template('share.html', file_id=file_id)

@app.route('/shared/<token>')
def access_shared_file(token):
    if 'user_id' not in session:
        flash('Please log in to access shared files.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, shared_with FROM files WHERE share_token = %s", (token,))
    file = c.fetchone()
    if not file or file[1] != session['user_id']:
        flash('Invalid share link or no access.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))
    conn.close()
    return redirect(url_for('download', file_id=file[0]))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    try:
        init_db()
        port = int(os.environ.get('PORT', 5000))
        app.run(debug=True, host='0.0.0.0', port=port)
    except Exception as e:
        print(f"Failed to start app: {e}")
        raise e