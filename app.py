import os
import uuid
import hashlib
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv
import datetime

# Load environment variables
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super-secret-key')

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx', 'zip', 'mp4', 'mov'}
app.config['MAX_DOWNLOAD_ATTEMPTS'] = 3  # Max password attempts
app.config['BASE_URL'] = 'http://localhost:5000'  # Change this in production

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def derive_key(password, salt):
    """Derive a 256-bit key from password using PBKDF2-HMAC-SHA256"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,  # Number of iterations
        dklen=32  # Derived key length
    )


def encrypt_file(file_path, password, original_name):
    """Encrypt file using AES-CBC with password-derived key"""
    # Generate random salt and IV
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)

    # Derive encryption key from password
    key = derive_key(password, salt)

    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Read and encrypt file
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Generate unique file ID
    file_id = str(uuid.uuid4())
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)

    # Write salt + IV + ciphertext
    with open(encrypted_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)

    # Calculate and store file hash
    file_hash = hashlib.sha256(plaintext).hexdigest()
    with open(encrypted_path + '.hash', 'w') as f:
        f.write(file_hash)

    # Store metadata
    with open(encrypted_path + '.meta', 'w') as f:
        f.write(f"original_name:{original_name}\n")
        f.write(f"uploaded:{datetime.datetime.now().isoformat()}\n")
        f.write(f"file_size:{len(plaintext)}\n")

    os.remove(file_path)
    return file_id


def decrypt_file(file_path, password):
    """Decrypt file using password-derived key"""
    # Read salt, IV and ciphertext
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    # Derive encryption key from password
    key = derive_key(password, salt)

    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError as e:
        raise ValueError("Decryption failed - possibly wrong password") from e

    # Verify file hash
    file_hash = hashlib.sha256(plaintext).hexdigest()
    hash_path = file_path + '.hash'
    if os.path.exists(hash_path):
        with open(hash_path, 'r') as f:
            stored_hash = f.read().strip()
        if file_hash != stored_hash:
            raise ValueError("File integrity check failed. File may be corrupted!")

    # Get original filename from metadata
    meta_path = file_path + '.meta'
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            for line in f:
                if line.startswith("original_name:"):
                    original_name = line.split(':', 1)[1].strip()
                    break
            else:
                original_name = f"decrypted_file_{uuid.uuid4().hex[:8]}"
    else:
        original_name = f"decrypted_file_{uuid.uuid4().hex[:8]}"

    # Create temporary decrypted file
    temp_id = str(uuid.uuid4())
    decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{temp_id}")
    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_path, original_name


def is_text_file(filename):
    """Check if file is text-based based on extension"""
    text_extensions = {'txt', 'csv', 'log', 'json', 'xml', 'html', 'htm', 'js', 'css', 'py'}
    extension = filename.split('.')[-1].lower()
    return extension in text_extensions


def generate_share_link(file_id):
    """Generate shareable download link with pre-filled file ID"""
    return f"{app.config['BASE_URL']}/download?file_id={file_id}"


@app.route('/')
def index():
    """Home page with upload form"""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and encryption"""
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['file']
    password = request.form.get('password', '').strip()

    if not password:
        flash('Password is required', 'danger')
        return redirect(request.url)

    if len(password) < 6:
        flash('Password must be at least 6 characters', 'danger')
        return redirect(request.url)

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    if file and allowed_file(file.filename):
        # Save original file temporarily
        filename = secure_filename(file.filename)
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(original_path)

        # Encrypt and store
        file_id = encrypt_file(original_path, password, filename)

        # Store file ID in session for success page
        session['file_id'] = file_id

        return redirect(url_for('upload_success'))

    flash('Invalid file type', 'danger')
    return redirect(request.url)


@app.route('/upload/success')
def upload_success():
    """Show success page after upload"""
    if 'file_id' not in session:
        return redirect(url_for('index'))

    file_id = session['file_id']
    session.pop('file_id', None)  # Clear session after use

    # Generate shareable link
    share_link = generate_share_link(file_id)

    return render_template('success.html', file_id=file_id, share_link=share_link)


@app.route('/download', methods=['GET', 'POST'])
def download_page():
    """Page for downloading files by ID and password"""
    error = None
    attempts = session.get('download_attempts', 0)

    # Get file_id from query parameters
    file_id_from_url = request.args.get('file_id', '').strip()

    if request.method == 'POST':
        file_id = request.form.get('file_id', '').strip()
        password = request.form.get('password', '').strip()

        if not file_id or not password:
            error = 'File ID and password are required'
        else:
            try:
                encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
                if not os.path.exists(encrypted_path):
                    error = 'File not found'
                else:
                    # Try to decrypt
                    decrypted_path, original_name = decrypt_file(encrypted_path, password)

                    # Get file info
                    meta_path = encrypted_path + '.meta'
                    if os.path.exists(meta_path):
                        with open(meta_path, 'r') as f:
                            metadata = f.readlines()
                        for line in metadata:
                            if line.startswith("uploaded:"):
                                upload_time = line.split(':', 1)[1].strip()
                            elif line.startswith("file_size:"):
                                file_size = int(line.split(':', 1)[1].strip())
                    else:
                        upload_time = "Unknown"
                        file_size = os.path.getsize(decrypted_path)

                    # Store in session for download
                    session['download_file_path'] = decrypted_path
                    session['download_original_name'] = original_name
                    session.pop('download_attempts', None)  # Reset attempts

                    return render_template('download.html',
                                           file_id=file_id,
                                           original_name=original_name,
                                           upload_time=upload_time,
                                           file_size=file_size)
            except Exception as e:
                error = str(e)
                attempts += 1
                session['download_attempts'] = attempts

                if attempts >= app.config['MAX_DOWNLOAD_ATTEMPTS']:
                    error = "Too many failed attempts. Please try again later."
                    session.pop('download_attempts', None)
                    return render_template('download_page.html', error=error, disabled=True, file_id=file_id_from_url)

    return render_template('download_page.html', error=error, attempts=attempts, file_id=file_id_from_url)


@app.route('/download/file')
def download_file():
    """Download decrypted file"""
    if 'download_file_path' not in session or 'download_original_name' not in session:
        return redirect(url_for('download_page'))

    file_path = session['download_file_path']
    original_name = session['download_original_name']

    # Send decrypted file
    response = send_file(
        file_path,
        as_attachment=True,
        download_name=original_name
    )

    # Clean up after download
    response.call_on_close(lambda: os.remove(file_path))

    # Clear session
    session.pop('download_file_path', None)
    session.pop('download_original_name', None)

    return response


@app.route('/decrypt', methods=['POST'])
def decrypt_page():
    """Decrypt and display text-based files"""
    file_id = request.form.get('file_id', '').strip()
    password = request.form.get('password', '').strip()

    if not file_id or not password:
        flash('File ID and password are required', 'danger')
        return redirect(url_for('download_page'))

    try:
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        if not os.path.exists(encrypted_path):
            flash('File not found', 'danger')
            return redirect(url_for('download_page'))

        # Decrypt file
        decrypted_path, original_name = decrypt_file(encrypted_path, password)

        # Check if file is text-based
        if not is_text_file(original_name):
            os.remove(decrypted_path)
            flash('Only text files can be previewed', 'warning')
            return redirect(url_for('download_page'))

        # Read content
        try:
            with open(decrypted_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            os.remove(decrypted_path)
            flash('File contains binary data and cannot be previewed', 'warning')
            return redirect(url_for('download_page'))

        # Store in session for download
        session['download_file_path'] = decrypted_path
        session['download_original_name'] = original_name

        return render_template('decrypt.html',
                               content=content,
                               original_name=original_name,
                               file_id=file_id)
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('download_page'))

if __name__ == '__main__':
    print("Running at http://127.0.0.1:5000/")
    app.run(port=5000, debug=True)