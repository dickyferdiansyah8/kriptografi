from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import os, time, base64, hashlib, secrets
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import numpy as np
from io import BytesIO
from docx import Document
from pathlib import Path
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'aes-demo-secret'
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ========== Fungsi utilitas ==========
def sha256sum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    p, _ = np.histogram(np.frombuffer(data, dtype=np.uint8), bins=256, range=(0, 256))
    p = p / np.sum(p)
    p = p[p > 0]
    return -np.sum(p * np.log2(p))

def histogram_data(data: bytes):
    hist, _ = np.histogram(np.frombuffer(data, dtype=np.uint8), bins=256, range=(0, 256))
    return hist.tolist()

def npcr_uaci(data1, data2):
    """Menghitung NPCR (Number of Pixel Change Rate) dan UACI (Unified Average Changing Intensity)"""
    if len(data1) != len(data2):
        # Jika panjang berbeda, buat data dengan panjang yang sama
        min_len = min(len(data1), len(data2))
        data1 = data1[:min_len]
        data2 = data2[:min_len]
    
    if len(data1) == 0:
        return 0, 0
    
    arr1 = np.frombuffer(data1, dtype=np.uint8)
    arr2 = np.frombuffer(data2, dtype=np.uint8)
    
    # NPCR: Percentage of different bytes
    diff_bytes = np.sum(arr1 != arr2)
    npcr_value = (diff_bytes / len(arr1)) * 100
    
    # UACI: Average intensity difference
    uaci_value = np.mean(np.abs(arr1.astype(float) - arr2.astype(float)) / 255) * 100
    
    return round(npcr_value, 3), round(uaci_value, 3)

def mse_psnr(data1, data2):
    """Menghitung MSE (Mean Squared Error) dan PSNR (Peak Signal to Noise Ratio)"""
    if len(data1) != len(data2):
        # Jika panjang berbeda, buat data dengan panjang yang sama
        min_len = min(len(data1), len(data2))
        data1 = data1[:min_len]
        data2 = data2[:min_len]
    
    if len(data1) == 0:
        return 0, 0
    
    arr1 = np.frombuffer(data1, dtype=np.uint8).astype(float)
    arr2 = np.frombuffer(data2, dtype=np.uint8).astype(float)
    
    # MSE
    mse_value = np.mean((arr1 - arr2) ** 2)
    
    # PSNR - batasi maksimal 100 dB
    if mse_value == 0:
        psnr_value = 100.0  # Daripada infinity, gunakan 100 dB
    elif mse_value > 255**2:
        psnr_value = 0.0  # Jika MSE sangat besar, PSNR = 0
    else:
        psnr_value = 10 * np.log10(255**2 / mse_value)
        # Batasi maksimal 100 dB
        psnr_value = min(psnr_value, 100.0)
    
    return round(mse_value, 3), round(psnr_value, 3)

def is_image(filename):
    ext = filename.lower().split('.')[-1]
    return ext in ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp']

def is_video(filename):
    ext = filename.lower().split('.')[-1]
    return ext in ['mp4', 'avi', 'mov', 'mkv', 'webm', 'flv', 'wmv']

# ========== Fungsi AES ==========
def aes_encrypt(data: bytes, password: str):
    salt = os.urandom(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    result = salt + cipher.nonce + tag + ciphertext
    code = base64.urlsafe_b64encode(salt + cipher.nonce + tag).decode()
    return result, code

def aes_decrypt(data: bytes, password: str):
    salt, nonce, tag = data[:16], data[16:32], data[32:48]
    ciphertext = data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# ========== ROUTES ==========
@app.route('/')
def index():
    return render_template('index.html',
                         hist_orig=[],
                         hist_enc=[], 
                         hist_dec=[],
                         orig_hash='-',
                         enc_hash='-',
                         dec_hash='-',
                         orig_size=0,
                         enc_size=0,
                         dec_size=0,
                         ent_orig='-',
                         ent_enc='-',
                         ent_dec='-',
                         npcr='-',
                         uaci='-',
                         mse='-',
                         psnr='-',
                         enc_time=0,
                         dec_time=0,
                         code='-',
                         preview_orig=None,
                         preview_dec=None,
                         mse_orig='-',
                         psnr_orig='-',
                         npcr_orig='-',
                         uaci_orig='-',
                         mse_enc='-',
                         psnr_enc='-',
                         npcr_dec='-',
                         uaci_dec='-',
                         orig_time=0)

# Variabel global untuk menyimpan data terakhir
last_encryption_data = {}

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        file = request.files['file']
        password = request.form['password']
        if not file or not password:
            flash("File atau password tidak boleh kosong!")
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        data = open(filepath, 'rb').read()

        # --- Statistik Asli ---
        orig_hash = sha256sum(data)
        ent_orig = round(entropy(data), 4)
        hist_orig = histogram_data(data)
        orig_size = len(data)

        # --- Enkripsi ---
        start = time.time()
        enc_data, code = aes_encrypt(data, password)
        enc_time = time.time() - start  # dalam detik

        enc_path = os.path.join(UPLOAD_FOLDER, f"{filename}.enc")
        open(enc_path, 'wb').write(enc_data)

        enc_hash = sha256sum(enc_data)
        ent_enc = round(entropy(enc_data), 4)
        hist_enc = histogram_data(enc_data)
        enc_size = len(enc_data)

        # Hitung NPCR dan UACI untuk file asli vs terenkripsi
        npcr, uaci = npcr_uaci(data, enc_data)
        
        # Hitung MSE dan PSNR untuk file asli vs terenkripsi
        mse_enc, psnr_enc = mse_psnr(data, enc_data)

        # Untuk file asli, MSE dan PSNR tidak relevan (bandingkan dengan diri sendiri)
        # Tapi kita beri nilai default yang masuk akal
        mse_orig, psnr_orig = 0, 100.0
        npcr_orig, uaci_orig = 0, 0

        # Preview - simpan file preview jika gambar/video
        preview_orig = None
        if is_image(filename) or is_video(filename):
            preview_orig = filename

        # Simpan data enkripsi untuk digunakan nanti
        global last_encryption_data
        last_encryption_data = {
            'orig_hash': orig_hash,
            'orig_size': orig_size,
            'ent_orig': ent_orig,
            'hist_orig': hist_orig,
            'enc_hash': enc_hash,
            'enc_size': enc_size,
            'ent_enc': ent_enc,
            'hist_enc': hist_enc,
            'npcr': npcr,
            'uaci': uaci,
            'enc_time': enc_time,
            'mse_enc': mse_enc,
            'psnr_enc': psnr_enc,
            'mse_orig': mse_orig,
            'psnr_orig': psnr_orig,
            'npcr_orig': npcr_orig,
            'uaci_orig': uaci_orig,
            'preview_orig': preview_orig,
            'code': code,
            'orig_data': data,
            'enc_data': enc_data,
            'orig_filename': filename
        }

        flash("File berhasil dienkripsi!")
        return render_template('index.html',
                               # File Asli
                               orig_hash=orig_hash, 
                               orig_size=orig_size,
                               ent_orig=ent_orig, 
                               hist_orig=hist_orig,
                               mse_orig=mse_orig,
                               psnr_orig=psnr_orig,
                               npcr_orig=npcr_orig,
                               uaci_orig=uaci_orig,
                               preview_orig=preview_orig,
                               
                               # Enkripsi
                               enc_hash=enc_hash, 
                               enc_size=enc_size,
                               ent_enc=ent_enc, 
                               hist_enc=hist_enc,
                               npcr=npcr, 
                               uaci=uaci,
                               enc_time=enc_time,
                               mse_enc=mse_enc,
                               psnr_enc=psnr_enc,
                               code=code,
                               
                               # Dekripsi (kosong)
                               dec_hash='-',
                               dec_size=0,
                               ent_dec='-',
                               hist_dec=[],
                               mse='-',
                               psnr='-',
                               dec_time=0,
                               npcr_dec='-',
                               uaci_dec='-',
                               preview_dec=None,
                               orig_time=0)

    except Exception as e:
        flash(f"Enkripsi gagal: {str(e)}")
        return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        code = request.form['code']
        password = request.form['password']
        if not code or not password:
            flash("Kode atau password tidak boleh kosong!")
            return redirect(url_for('index'))

        # Gunakan data enkripsi terakhir yang disimpan
        global last_encryption_data
        
        if not last_encryption_data:
            flash("Silakan lakukan enkripsi terlebih dahulu!")
            return redirect(url_for('index'))

        # Gunakan data terenkripsi yang disimpan
        enc_data = last_encryption_data.get('enc_data')
        if not enc_data:
            flash("Data enkripsi tidak ditemukan!")
            return redirect(url_for('index'))

        start = time.time()
        dec_data = aes_decrypt(enc_data, password)
        dec_time = time.time() - start  # dalam detik

        # Buat nama file dekripsi
        orig_filename = last_encryption_data.get('orig_filename', 'file')
        # Hapus extension .enc jika ada dan tambahkan _dec
        if orig_filename.endswith('.enc'):
            dec_filename = orig_filename[:-4] + '_dec'
        else:
            dec_filename = orig_filename + '_dec'
        
        dec_path = os.path.join(UPLOAD_FOLDER, dec_filename)
        open(dec_path, 'wb').write(dec_data)

        # Statistik Dekripsi
        dec_hash = sha256sum(dec_data)
        ent_dec = round(entropy(dec_data), 4)
        hist_dec = histogram_data(dec_data)
        dec_size = len(dec_data)

        # Hitung MSE dan PSNR untuk file asli vs terdekripsi (seharusnya 0 dan 100 jika sempurna)
        orig_data = last_encryption_data.get('orig_data', b'')
        mse, psnr = mse_psnr(orig_data, dec_data)
        
        # Hitung NPCR dan UACI untuk file asli vs terdekripsi (seharusnya 0 jika sempurna)
        npcr_dec, uaci_dec = npcr_uaci(orig_data, dec_data)

        # Preview untuk file dekripsi
        preview_dec = None
        if is_image(dec_filename) or is_video(dec_filename):
            preview_dec = dec_filename

        flash("File berhasil didekripsi!")
        return render_template('index.html',
                               # Data File Asli (dari enkripsi terakhir)
                               orig_hash=last_encryption_data.get('orig_hash', '-'),
                               orig_size=last_encryption_data.get('orig_size', 0),
                               ent_orig=last_encryption_data.get('ent_orig', '-'),
                               hist_orig=last_encryption_data.get('hist_orig', []),
                               mse_orig=last_encryption_data.get('mse_orig', '-'),
                               psnr_orig=last_encryption_data.get('psnr_orig', '-'),
                               npcr_orig=last_encryption_data.get('npcr_orig', '-'),
                               uaci_orig=last_encryption_data.get('uaci_orig', '-'),
                               preview_orig=last_encryption_data.get('preview_orig'),
                               
                               # Data Enkripsi (dari enkripsi terakhir)
                               enc_hash=last_encryption_data.get('enc_hash', '-'),
                               enc_size=last_encryption_data.get('enc_size', 0),
                               ent_enc=last_encryption_data.get('ent_enc', '-'),
                               hist_enc=last_encryption_data.get('hist_enc', []),
                               npcr=last_encryption_data.get('npcr', '-'),
                               uaci=last_encryption_data.get('uaci', '-'),
                               enc_time=last_encryption_data.get('enc_time', 0),
                               mse_enc=last_encryption_data.get('mse_enc', '-'),
                               psnr_enc=last_encryption_data.get('psnr_enc', '-'),
                               code=last_encryption_data.get('code', '-'),
                               
                               # Data Dekripsi (baru) - bandingkan dengan file asli
                               dec_hash=dec_hash, 
                               ent_dec=ent_dec, 
                               hist_dec=hist_dec,
                               dec_size=dec_size, 
                               mse=mse, 
                               psnr=psnr, 
                               dec_time=dec_time,
                               npcr_dec=npcr_dec, 
                               uaci_dec=uaci_dec,
                               preview_dec=preview_dec,
                               
                               # Default values
                               orig_time=0)

    except Exception as e:
        flash(f"Dekripsi gagal: {str(e)}")
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_dec(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

@app.route('/report', methods=['POST'])
def report():
    code = request.form.get('code', '')
    doc = Document()
    doc.add_heading('Laporan Enkripsi AES-GCM', 0)
    doc.add_paragraph(f'Kode Unik: {code}')
    doc.add_paragraph('Laporan ini dihasilkan otomatis oleh sistem Flask.')
    out = BytesIO()
    doc.save(out)
    out.seek(0)
    return send_file(out, as_attachment=True, download_name='laporan_AES.docx')

if __name__ == '__main__':
    app.run(debug=True)