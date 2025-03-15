from flask import Flask, render_template, request, send_file, jsonify
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator  # Use local Aer simulator only
from numpy.random import randint
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import secrets
import string
import tempfile
import logging
import time 
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# Configure your email settings

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

SMTP_SERVER = "smtp.gmail.com"  # Change based on your email provider
SMTP_PORT = 587  # Change based on your email provider


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder="../static", template_folder="../templates")
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def generate_bb84_key(num_qubits=20):
    # Generate random bases and states for Alice and Bob
    alice_basis = randint(2, size=num_qubits)
    alice_state = randint(2, size=num_qubits)
    bob_basis = randint(2, size=num_qubits)

    def bb84_circuit(state, basis, measurement_basis):
        num_qubits = len(state)
        circuit = QuantumCircuit(num_qubits)

        # Sender prepares qubits
        for i in range(len(basis)):
            if state[i] == 1:
                circuit.x(i)
            if basis[i] == 1:
                circuit.h(i)

        # Measuring action performed by Bob
        for i in range(len(measurement_basis)):
            if measurement_basis[i] == 1:
                circuit.h(i)

        circuit.measure_all()
        return circuit

    # Create the quantum circuit
    circuit = bb84_circuit(alice_state, alice_basis, bob_basis)

    time.sleep(10)
    print("\nGenerating keys...")
    backend = AerSimulator()
    transpiled_circuit = transpile(circuit.reverse_bits(), backend=backend)
    job = backend.run(transpiled_circuit, shots=1024)
    result = job.result()
    counts = result.get_counts(transpiled_circuit)

    # Extract the encryption key
    encryption_key = ''
    for i in range(len(alice_basis)):
        if alice_basis[i] == bob_basis[i]:
            encryption_key += list(counts.keys())[0][i]

    # Get the QASM code
    try:
        qasm_code = circuit.qasm()
    except AttributeError:
        qasm_code = "QASM extraction failed, try another method."

    return encryption_key, counts, qasm_code

def pad_key(key):
    """ Pad the key to 256 bits (32 bytes) """
    return key.ljust(32, '0')

def encrypt_file(input_file, output_file, key):
   
    with open(input_file, 'rb') as f:
        data = f.read()

    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)


def generate_random_string(length=10):
    """Generate a random string of specified length."""
    characters = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

def merge_strings(value, random_string, initial_random_chars=3):
    """Merge the value and random string without clear separation."""
    merged = []
    merged.extend(random_string[:initial_random_chars])
    max_length = max(len(value), len(random_string))

    for i in range(max_length):
        if i < len(random_string) and i >= initial_random_chars:
            merged.append(random_string[i])
        if i < len(value):
            merged.append(value[i])

    return ''.join(merged)

def hex_encrypt(merged_string):
    """Encrypt the merged string using Hexadecimal."""
    return merged_string.encode('utf-8').hex()

def decrypt_file(input_file, output_file, key):
    print("="*50)
    print("\nDecrypting the file....\n")
    print("="*50)
    try:
        with open(input_file, 'rb') as f:
            iv = f.read(16)  # AES IV size is 16 bytes
            encrypted_data = f.read()

        backend = default_backend()
        cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(data)

        print("Decryption successful.")

        # Rename the decrypted file
        base_name, extension = os.path.splitext(output_file)
        if "_" in base_name:
            new_base_name = base_name.rsplit('_', 1)[0]  # Remove everything after the last underscore
            new_file_name = f"{new_base_name}{extension}"
            os.rename(output_file, new_file_name)
            print(f"File renamed to: {os.path.basename(new_file_name)}")
            return new_file_name
        else:
            print("No underscores found in the file name. File name remains unchanged.")
            return output_file

    except ValueError as e:
        print(f"Decryption failed: {e}. Check the key or file integrity.")
        exit(1)

# Place these helper functions before the main function or any usage
def hex_decrypt(hex_string):
    """Decrypt the hexadecimal string."""
    try:
        return bytes.fromhex(hex_string).decode('utf-8')
    except ValueError as e:
        print(f"Error in hex decryption: {e}")
        return None

def extract_key_from_merged_string(merged_string, initial_random_chars=3):
    """Extract the binary key from the merged string."""
    relevant_part = merged_string[initial_random_chars:]
    key = ''.join(char for char in relevant_part if char in '01')
    return key

def extract_actual_key_from_filename(input_file, initial_random_chars=3):
    global file_name, file_ext  # Make these variables global
    file_name, file_ext = os.path.splitext(input_file)  # Split filename and extension
    
    if "_" not in file_name:
        print("No encrypted key found in the file name.")
        return None
    
    encrypted_key = file_name.split('_')[-1]  # Extract the key after the last underscore
    time.sleep(10)
    print("=" * 50)
    print(f"\nEncrypted key from filename: {encrypted_key}")
    
    # Step 1: Decrypt the merged string
    merged_string = hex_decrypt(encrypted_key)
    if not merged_string:
        print("Hex decryption of the key failed.")
        return None
    
    # Step 2: Extract the actual key (bits from the merged string)
    actual_key = extract_key_from_merged_string(merged_string, initial_random_chars)
    print(f"Extracted key from merged string: {actual_key}")
    
    return actual_key



@app.route('/')
def index():
    return render_template('qkd.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    try:
        # Save the uploaded file
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(input_path)
        
        # Extract file name and extension
        file_name, file_ext = os.path.splitext(file.filename)
        
        # Generate quantum encryption key
        key, counts, qasm_code = generate_bb84_key()
        logger.info(f"Generated key: {key}")
        
        # Pad key to required length
        padded_key = pad_key(key)
        
        # Create output filename
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"encrypted_{file.filename}")
        
        # Encrypt the file
        encrypt_file(input_path, output_path, padded_key)
        
        # Generate and embed the key in the filename
        random_string = generate_random_string(16)
        merged_string = merge_strings(key, random_string)
        encrypted_id = hex_encrypt(merged_string)
        
        final_output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_name}_{encrypted_id}{file_ext}")
        os.rename(output_path, final_output_path)
        
        return jsonify({
            'success': True, 
            'key': key,
            'filename': f"{file_name}_{encrypted_id}{file_ext}",
            'download_url': f"/download?path={final_output_path}&filename={file_name}_{encrypted_id}{file_ext}"
        })
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Get the key (either from filename or manually entered)
    manual_key = request.form.get('key', '')

    try:
        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save the uploaded file
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(input_path)

        # Extract key from filename
        actual_key = extract_actual_key_from_filename(file.filename)

        # Use manual key if automatic extraction failed
        if not actual_key:
            actual_key = manual_key
            
        # Pad key
        padded_key = pad_key(actual_key)

        # Generate output filename from input filename
        base_name, extension = os.path.splitext(file.filename)
        # Remove any encryption indicators from filename
        if "_" in base_name:
            base_name = base_name.rsplit('_', 1)[0]  # Remove everything after the last underscore
        
        output_filename = f"{base_name}{extension}"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        # Decrypt file
        new_filename = decrypt_file(input_path, output_path, padded_key)
        
        # If decrypt_file returns a new filename, use that
        if new_filename:
            output_filename = os.path.basename(new_filename)

        return jsonify({
            'success': True,
            'key': actual_key,
            'filename': output_filename,
            'download_url': f"/download?path={output_path}&filename={output_filename}"
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download')
def download():
    file_path = request.args.get('path')
    filename = request.args.get('filename')
    original_filename = request.args.get('original_filename')
    
    if not file_path or not filename or not os.path.exists(file_path):
        return "File not found", 404
    
    # Use the original_filename for the download name
    return send_file(file_path, as_attachment=True, download_name=original_filename)

@app.route('/generate_key', methods=['POST'])
def generate_key():
    try:
        num_qubits = int(request.form.get('num_qubits', 20))
        key, counts, qasm_code = generate_bb84_key(num_qubits)
        return jsonify({
            'success': True,
            'key': key,
            'qasm_code': qasm_code
        })
    except Exception as e:
        logger.error(f"Key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/placeholder/<int:width>/<int:height>')
def placeholder_image(width, height):
    """Serve the folder.png image resized to requested dimensions."""
    from PIL import Image
    from io import BytesIO
    
    # Path to your folder.png image
    folder_image_path = os.path.join('static/images', 'folder.png')
    
    # Open and resize the image
    img = Image.open(folder_image_path)
    img = img.resize((width, height), Image.LANCZOS)
    
    # Save the resized image to a bytes buffer
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    # Return the image with the appropriate MIME type
    return send_file(img_io, mimetype='image/png')

@app.route('/share-email', methods=['POST'])
def share_email():
    try:
        # Get form data
        recipient_email = request.form.get('email')
        message_text = request.form.get('message', '')
        file_url = request.form.get('file_url')
        file_name = request.form.get('file_name')
        is_encrypted = request.form.get('is_encrypted') == 'true'
        encryption_key = request.form.get('encryption_key', '')

        # Validate input
        if not recipient_email or not file_url or not file_name:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400

        # Get the Downloads folder path
        downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        file_path = os.path.join(downloads_folder, file_name)

        # Debugging: Print file path
        print(f"Checking file in Downloads: {file_path}")

        # Check if file exists
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'error': f'File not found at {file_path}'}), 404

        # Construct email
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = recipient_email
        msg['Subject'] = f"{'🔐 Encrypted' if is_encrypted else '📄 File'}: {file_name}"

        # Email body
        body = message_text if message_text else f"Here is the {'encrypted' if is_encrypted else 'decrypted'} file you requested."

        msg.attach(MIMEText(body, 'plain'))

        # Attach file
        with open(file_path, 'rb') as file:
            part = MIMEApplication(file.read(), Name=file_name)
            part['Content-Disposition'] = f'attachment; filename="{file_name}"'
            msg.attach(part)

        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print("✅ Email sent successfully!")
        return jsonify({'success': True}), 200

    except Exception as e:
        print(f"❌ Error sending email: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    print("Starting Quantum Encryption Web App on http://127.0.0.1:5000")
    app.run(debug=True)

