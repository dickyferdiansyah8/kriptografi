from flask import Flask, request, redirect, url_for, render_template_string, flash, send_file
import os, time, base64, hashlib, secrets, binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from werkzeug.utils import secure_filename
from pathlib import Path

app = Flask(__name__)
app.secret_key = 'dev-secret'

UPLOAD_FOLDER = 'uploads'
ENC_FOLDER = 'encrypted'
DEC_FOLDER = 'decrypted'
for d in (UPLOAD_FOLDER, ENC_FOLDER, DEC_FOLDER):
    os.makedirs(d, exist_ok=True)

SALT_SIZE = 16
PBKDF2_ITER = 100_000
code_map = {}
time_records = {}  # untuk menyimpan waktu proses tiap kode


# ==== Utility Functions ====
def derive_key(password, salt, key_len=32):
    return PBKDF2(password.encode(), salt, dkLen=key_len, count=PBKDF2_ITER, hmac_hash_module=SHA256)

def file_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def file_head(path, length=64):
    with open(path, 'rb') as f:
        data = f.read(length)
    return binascii.hexlify(data).decode()

# ==== AES Encryption / Decryption ====
def encrypt_file(in_path, out_path, password):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    with open(in_path, 'rb') as fin:
        data = fin.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    combined = salt + nonce + tag + ciphertext
    encoded = base64.b64encode(combined)

    with open(out_path, 'wb') as fout:
        fout.write(encoded)

def decrypt_file(in_path, out_path, password):
    with open(in_path, 'rb') as fin:
        encoded = fin.read()
    combined = base64.b64decode(encoded)

    salt = combined[:SALT_SIZE]
    nonce = combined[SALT_SIZE:SALT_SIZE+16]
    tag = combined[SALT_SIZE+16:SALT_SIZE+32]
    ciphertext = combined[SALT_SIZE+32:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    with open(out_path, 'wb') as fout:
        fout.write(data)


# ==== ROUTES ====
@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files.get('file')
    password = request.form.get('password', '')
    if not file or not password:
        flash("File dan password diperlukan.")
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    src_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(src_path)

    code = secrets.token_urlsafe(12).upper()
    enc_path = os.path.join(ENC_FOLDER, f"{code}.enc")

    start_time = time.time()
    encrypt_file(src_path, enc_path, password)
    enc_duration = time.time() - start_time

    # Empirical Data
    orig_hash = file_hash(src_path)
    enc_hash = file_hash(enc_path)
    orig_size = os.path.getsize(src_path)
    enc_size = os.path.getsize(enc_path)
    ratio = round((enc_size / orig_size) * 100, 2) if orig_size > 0 else 0
    orig_head = file_head(src_path)
    enc_head = file_head(enc_path)

    code_map[code] = enc_path
    time_records[code] = {'encrypt_time': enc_duration}

    return render_template_string(INDEX_HTML,
        code=code,
        orig_hash=orig_hash,
        enc_hash=enc_hash,
        orig_size=orig_size,
        enc_size=enc_size,
        ratio=ratio,
        orig_head=orig_head,
        enc_head=enc_head,
        enc_time=round(enc_duration, 3)
    )

@app.route('/decrypt', methods=['POST'])
def decrypt():
    code = request.form.get('code','').strip().upper()
    password = request.form.get('password','')
    enc_path = code_map.get(code)
    if not enc_path or not os.path.exists(enc_path):
        flash("Kode tidak valid atau file tidak ditemukan.")
        return redirect(url_for('index'))

    dec_filename = f"{code}_decrypted.mp4"
    dec_path = os.path.join(DEC_FOLDER, dec_filename)

    start_time = time.time()
    try:
        decrypt_file(enc_path, dec_path, password)
        dec_duration = time.time() - start_time

        dec_hash = file_hash(dec_path)
        orig_uploads = os.listdir(UPLOAD_FOLDER)
        if orig_uploads:
            first_file = os.path.join(UPLOAD_FOLDER, orig_uploads[0])
            orig_hash = file_hash(first_file)
            orig_size = os.path.getsize(first_file)
            dec_size = os.path.getsize(dec_path)
            same = (dec_hash == orig_hash)
        else:
            orig_hash = "N/A"
            same = False
            orig_size = dec_size = 0

        enc_time = time_records.get(code, {}).get('encrypt_time', 0)

        return render_template_string(INDEX_HTML,
            dec_file=dec_filename,
            dec_hash=dec_hash,
            orig_hash=orig_hash,
            same=same,
            dec_time=round(dec_duration, 3),
            enc_time=round(enc_time, 3),
            orig_size=orig_size,
            dec_size=dec_size
        )
    except Exception as e:
        flash(f"Password salah atau file rusak: {e}")
        return redirect(url_for('index'))

@app.route('/decrypted/<path:filename>')
def download_dec(filename):
    safe_path = Path(DEC_FOLDER) / filename
    try:
        safe_path_resolved = safe_path.resolve(strict=True)
    except FileNotFoundError:
        flash("File tidak ditemukan.")
        return redirect(url_for('index'))

    if not str(safe_path_resolved).startswith(str(Path(DEC_FOLDER).resolve())):
        flash("Access denied.")
        return redirect(url_for('index'))

    return send_file(str(safe_path_resolved), as_attachment=True, download_name=filename)


# ==== HTML TEMPLATE (Chart.js integrated) ====
INDEX_HTML = """
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AES Video Encrypt/Decrypt + Perhitungan Empiris + 3 Grafik</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font-family:Segoe UI,Roboto,Arial;margin:0;background:#f4f7fa;}
.wrap{max-width:960px;margin:40px auto;padding:20px;}
h1{text-align:center;color:#0e7490;}
.card{background:#fff;border-radius:12px;box-shadow:0 6px 16px rgba(0,0,0,0.06);padding:20px;margin-bottom:20px;}
label{font-weight:600;display:block;margin-top:10px;}
input[type=file],input[type=password],input[type=text]{width:100%;padding:10px;border:1px solid #ccc;border-radius:8px;margin-bottom:10px;}
button{background:#0ea5a4;color:#fff;padding:10px 14px;border:none;border-radius:8px;cursor:pointer;}
button:hover{background:#0c8d8b;}
.hashbox{font-family:monospace;font-size:13px;word-break:break-all;background:#eef2f7;padding:8px;border-radius:6px;}
.table{width:100%;border-collapse:collapse;margin-top:10px;font-size:14px;}
.table th,.table td{padding:6px 8px;border-bottom:1px solid #e5e7eb;text-align:left;}
.table th{background:#f0f9f9;}
.success{color:#16a34a;font-weight:bold;}
.fail{color:#dc2626;font-weight:bold;}
footer{text-align:center;margin-top:30px;color:#6b7280;font-size:13px;}
.chart-container{position:relative;height:300px;width:100%;margin-top:20px;}
</style>
</head>
<body>
<div class="wrap">
  <h1>🔐 AES Video Encrypt / Decrypt </h1>

  <div class="card">
    <h2>Encrypt Video</h2>
    <form method="post" enctype="multipart/form-data" action="{{ url_for('encrypt') }}">
      <label>File Video</label>
      <input type="file" name="file" required>
      <label>Password</label>
      <input type="password" name="password" required>
      <button type="submit">Encrypt</button>
    </form>

    {% if code %}
    <hr>
    <h3>📊 Hasil Empiris (Enkripsi)</h3>
    <table class="table">
      <tr><th>Hash Asli</th><td><div class="hashbox">{{ orig_hash }}</div></td></tr>
      <tr><th>Hash Enkripsi</th><td><div class="hashbox">{{ enc_hash }}</div></td></tr>
      <tr><th>Ukuran File Asli</th><td>{{ orig_size }} bytes</td></tr>
      <tr><th>Ukuran File Enkripsi</th><td>{{ enc_size }} bytes</td></tr>
      <tr><th>Rasio Ukuran</th><td>{{ ratio }}%</td></tr>
      <tr><th>64 byte pertama (Asli)</th><td><div class="hashbox">{{ orig_head }}</div></td></tr>
      <tr><th>64 byte pertama (Enkripsi)</th><td><div class="hashbox">{{ enc_head }}</div></td></tr>
      <tr><th>Waktu Enkripsi</th><td>{{ enc_time }} detik</td></tr>
    </table>

    <div class="chart-container">
      <canvas id="chartEncrypt"></canvas>
    </div>
    <script>
      new Chart(document.getElementById('chartEncrypt'), {
        type: 'bar',
        data: {
          labels: ['File Asli', 'File Enkripsi'],
          datasets: [{
            label: 'Ukuran File (bytes)',
            data: [{{ orig_size }}, {{ enc_size }}],
            backgroundColor: ['#06b6d4', '#0f766e']
          }]
        },
        options: {responsive: true, plugins: {legend: {display: false}}}
      });
    </script>

    <p><b>Kode Unik:</b> {{ code }}</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>Decrypt Video</h2>
    <form method="post" action="{{ url_for('decrypt') }}">
      <label>Kode Unik</label>
      <input type="text" name="code" required>
      <label>Password</label>
      <input type="password" name="password" required>
      <button type="submit">Decrypt</button>
    </form>

    {% if dec_file %}
    <hr>
    <h3>📊 Hasil Empiris (Dekripsi)</h3>
    <table class="table">
      <tr><th>Hash File Asli</th><td><div class="hashbox">{{ orig_hash }}</div></td></tr>
      <tr><th>Hash File Dekripsi</th><td><div class="hashbox">{{ dec_hash }}</div></td></tr>
      <tr><th>Status Verifikasi</th>
        <td>{% if same %}<span class="success">✅ Sama (Hash identik)</span>{% else %}<span class="fail">❌ Berbeda</span>{% endif %}</td>
      </tr>
      <tr><th>Waktu Dekripsi</th><td>{{ dec_time }} detik</td></tr>
      <tr><th>Waktu Enkripsi</th><td>{{ enc_time }} detik</td></tr>
    </table>

    <div class="chart-container">
      <canvas id="chartDecrypt"></canvas>
    </div>
    <script>
      new Chart(document.getElementById('chartDecrypt'), {
        type: 'bar',
        data: {
          labels: ['File Asli', 'File Dekripsi'],
          datasets: [{
            label: 'Ukuran File (bytes)',
            data: [{{ orig_size or 0 }}, {{ dec_size or 0 }}],
            backgroundColor: ['#06b6d4', '#0f766e']
          }]
        },
        options: {responsive: true, plugins: {legend: {display: false}}}
      });

      new Chart(document.createElement('canvas'), {
        type: 'bar',
        data: {
          labels: ['Enkripsi', 'Dekripsi'],
          datasets: [{
            label: 'Waktu Proses (detik)',
            data: [{{ enc_time or 0 }}, {{ dec_time or 0 }}],
            backgroundColor: ['#0284c7', '#22c55e']
          }]
        },
        options: {responsive: true, plugins: {legend: {display: false}}}
      });
    </script>

    <div class="chart-container">
      <canvas id="chartTime"></canvas>
    </div>
    <script>
      new Chart(document.getElementById('chartTime'), {
        type: 'bar',
        data: {
          labels: ['Enkripsi', 'Dekripsi'],
          datasets: [{
            label: 'Waktu Proses (detik)',
            data: [{{ enc_time or 0 }}, {{ dec_time or 0 }}],
            backgroundColor: ['#0284c7', '#22c55e']
          }]
        },
        options: {responsive: true, plugins: {legend: {display: false}}}
      });
    </script>

    <a href="{{ url_for('download_dec', filename=dec_file) }}">⬇️ Download {{ dec_file }}</a>
    {% endif %}
  </div>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="card fail">
        {% for m in messages %}
          <p>⚠️ {{ m }}</p>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  <footer>Versi empiris + 3 grafik — enkripsi AES-GCM + validasi hash</footer>
</div>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(port=5000, debug=True)
