from flask import Flask, render_template, request, redirect, url_for, session
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import pyotp

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Untuk menjaga sesi tetap aman

# Simulasi username dan password
USERNAME = "nasabah"
PASSWORD = "password123"

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# OTP instance
otp_instance = pyotp.TOTP(pyotp.random_base32())

# Simpan transaksi di memori sementara
transactions = []
balance = 10000000  # Saldo awal

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_process():
    username = request.form['username']
    password = request.form['password']

    if username == USERNAME and password == PASSWORD:
        session['user'] = username
        return redirect(url_for('index'))
    else:
        return "<h3>❌ Login Gagal! Username atau Password Salah.</h3><a href='/'>Coba Lagi</a>"

@app.route('/home')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', transactions=transactions, balance=balance)

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    transaction_data = request.form['transaction']
    transactions.append(transaction_data)
    return redirect(url_for('index'))

@app.route('/process/<int:transaction_id>', methods=['POST'])
def process(transaction_id):
    global balance  # Menggunakan variabel global untuk saldo

    if transaction_id >= len(transactions):
        return "<h3>❌ Transaksi tidak ditemukan!</h3><a href='/home'>Kembali</a>"

    transaction_data = transactions[transaction_id]
    try:
        amount = int(transaction_data.split(" ")[1])  # Asumsi format "Transfer <jumlah>"
    except (IndexError, ValueError):
        return "<h3>❌ Format transaksi salah! Gunakan format 'Transfer <jumlah>'</h3><a href='/home'>Kembali</a>"

    # Periksa apakah saldo mencukupi
    if amount > balance:
        return "<h3>❌ Saldo tidak mencukupi!</h3><a href='/home'>Kembali</a>"

    # Kurangi saldo
    balance -= amount

    # Hash transaction data
    digest = hashes.Hash(hashes.SHA256())
    digest.update(transaction_data.encode())
    hashed_transaction = digest.finalize().hex()

    # Encrypt transaction data
    encrypted_data = public_key.encrypt(
        transaction_data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Generate OTP
    otp = otp_instance.now()

    # Simpan hasil proses ke sesi
    session['hashed'] = hashed_transaction
    session['encrypted'] = encrypted_data
    session['otp'] = otp

    return render_template('result.html', hashed=hashed_transaction, otp=otp, transaction=transaction_data, balance=balance)

@app.route('/verify', methods=['POST'])
def verify():
    user_otp = request.form['otp']
    encrypted_data = session.get('encrypted')

    if otp_instance.verify(user_otp):
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return render_template('verify.html', result=f"✅ Verifikasi Berhasil! Data asli: {decrypted_data.decode()}")
    else:
        return render_template('verify.html', result="❌ Verifikasi Gagal! OTP Salah.")

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
