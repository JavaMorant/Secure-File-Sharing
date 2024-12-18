# Zero-Knowledge Secure File System

A secure file-sharing system implementing zero-knowledge principles, where the server never sees unencrypted data.

## Existing Test Accounts

The following accounts are available for testing:
```
username : password
a : b
b : c
mal : mal
```

## Setup

1. Clone the repository and create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. Install required packages:
```bash
pip install flask flask-cors requests urllib3 cryptography pyOpenSSL pytest
```

## Running the System

1. First, start the server:
```bash
cd server
python server.py
```
The server will start on https://localhost:5000

2. In a new terminal, start the GUI:
```bash
cd client
python secure_file_gui.py
```

## Running Tests

1. To run unit tests:
```bash
cd client
pytest test_encryption.py  # Tests encryption/decryption functionality
pytest test_client.py     # Tests client-server operations
```

Note: Some file sharing operations cannot be automatically tested due to their interactive nature, but have been manually verified.

## Using the System

1. Create an account:
   - Enter a username and password
   - Account creation is automatic on first login
   - Or use one of the existing test accounts listed above

2. Upload files:
   - Click "Upload File"
   - Select a file to encrypt, a type of encryption and upload

3. Share files:
   - Select a file in the list
   - Enter recipient's username
   - Click "Share"

4. Download files:
   - Double-click a file or
   - Select file and click "Download"

## Security Features

- Client-side encryption
- Multiple encryption schemes available
- Zero-knowledge server design
- Secure file sharing

## Troubleshooting

If you see SSL errors:
- The server uses self-signed certificates for development
- These warnings can be safely ignored in development

## Directory Structure
```
project/
├── server/
│   └── server.py
└── client/
    ├── secure_file_gui.py
    ├── client.py
    ├── test_encryption.py
    └── test_client.py
```
