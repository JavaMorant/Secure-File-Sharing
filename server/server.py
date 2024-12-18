from flask import Flask, request, send_file, jsonify
from pathlib import Path
import os
from werkzeug.utils import secure_filename
import ssl
import json
from OpenSSL import crypto
from flask_cors import CORS


app = Flask(__name__)
CORS(app)

# server storage paths
STORAGE_DIR = Path("server_storage")
FILES_DIR = STORAGE_DIR / "files"
KEYS_DIR = STORAGE_DIR / "public_keys"

# Create storage directories
FILES_DIR.mkdir(parents=True, exist_ok=True)
KEYS_DIR.mkdir(parents=True, exist_ok=True)
STORAGE_DIR.mkdir(exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle encrypted file upload"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
            
        file = request.files['file']
        metadata = json.loads(request.form.get('metadata', '{}'))
        
        if not file:
            return jsonify({'error': 'No file selected'}), 400
            
        # Generate secure filename using provided ID
        file_id = metadata.get('file_id')
        if not file_id:
            return jsonify({'error': 'No file ID provided'}), 400
            
        # Store encrypted file
        file_path = FILES_DIR / f"{file_id}.enc"
        metadata_path = FILES_DIR / f"{file_id}.meta"
        
        file.save(file_path)
        
        # Store metadata
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
            
        return jsonify({'message': 'File uploaded successfully', 'file_id': file_id}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    """Handle encrypted file download"""
    try:
        file_path = FILES_DIR / f"{file_id}.enc"
        metadata_path = FILES_DIR / f"{file_id}.meta"
        
        if not file_path.exists() or not metadata_path.exists():
            return jsonify({'error': 'File not found'}), 404
            
        # Read metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
            
        # Send encrypted file and metadata
        return send_file(
            file_path,
            as_attachment=True,
            download_name=f"{file_id}.enc",
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/metadata/<file_id>', methods=['GET'])
def get_metadata(file_id):
    """Get file metadata"""
    try:
        metadata_path = FILES_DIR / f"{file_id}.meta"
        
        if not metadata_path.exists():
            return jsonify({'error': 'Metadata not found'}), 404
            
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
            
        return jsonify(metadata), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/metadata/<file_id>', methods=['PUT'])
def update_metadata(file_id):
    """Update file metadata (for sharing)"""
    try:
        metadata_path = FILES_DIR / f"{file_id}.meta"
        
        if not metadata_path.exists():
            return jsonify({'error': 'Metadata not found'}), 404
            
        new_metadata = request.json
        if not new_metadata:
            return jsonify({'error': 'No metadata provided'}), 400
            
        with open(metadata_path, 'w') as f:
            json.dump(new_metadata, f)
            
        return jsonify({'message': 'Metadata updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/list', methods=['POST'])
def list_files():
    """List files for a user"""
    try:
        data = request.json
        username = data.get('username')
        
        if not username:
            return jsonify({'error': 'No username provided'}), 400
            
        files = []
        for meta_file in FILES_DIR.glob("*.meta"):
            with open(meta_file, 'r') as f:
                metadata = json.load(f)
                
            # Only include files owned by or shared with the user
            if (username == metadata['owner'] or 
                username in metadata.get('shared_with', {})):
                file_id = meta_file.stem
                files.append({
                    'file_id': file_id,
                    'metadata': metadata
                })
                
        return jsonify({'files': files}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/public_key/<username>', methods=['PUT'])
def store_public_key(username):
    """Store user's public key"""
    try:
        if 'key' not in request.files:
            return jsonify({'error': 'No key provided'}), 400
            
        key_file = request.files['key']
        key_path = KEYS_DIR / f"{username}.pub"
        
        key_file.save(key_path)
        return jsonify({'message': 'Public key stored successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/public_key/<username>', methods=['GET'])
def get_public_key(username):
    """Retrieve user's public key"""
    try:
        key_path = KEYS_DIR / f"{username}.pub"
        
        if not key_path.exists():
            return jsonify({'error': 'Public key not found'}), 404
            
        return send_file(
            key_path,
            as_attachment=True,
            download_name=f"{username}.pub",
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def create_self_signed_cert():
    """Create self-signed certificate for development"""    
    # Generate key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Generate certificate
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    # Save certificate and private key
    cert_path = STORAGE_DIR / "server.crt"
    key_path = STORAGE_DIR / "server.key"
    
    with open(cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
    return cert_path, key_path


@app.route('/health', methods=['GET'])
def health_check():
    """Basic health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'server is running'
    }), 200

if __name__ == '__main__':
    # Create self-signed certificate
    cert_path, key_path = create_self_signed_cert()
    
    # Run server with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    
    # Run the server
    app.run(
        host='0.0.0.0',  # Changed from localhost
        port=3000,
        ssl_context=context,
        debug=True
    )