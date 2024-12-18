from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from client import SecureFileClient
import os
import datetime
import json
import base64
import tkinter as tk

# Define encryption schemes
class EncryptionScheme:
    def __init__(self, name, key_size):
        self.name = name
        self.key_size = key_size

# Encryption manager initialisation
class EncryptionManager:
    """Manages different encryption schemes"""

    SCHEMES = {
        'AES-GCM': EncryptionScheme('AES-GCM', 256),
        'AES-CBC': EncryptionScheme('AES-CBC', 256),
        'ChaCha20': EncryptionScheme('ChaCha20', 256),
    }

    @staticmethod
    def encrypt_data(data: bytes, key: bytes, scheme_name: str) -> tuple[bytes, dict]:
        """Encrypt data using selected scheme"""
        if scheme_name == 'AES-GCM':
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)  # AES-GCM uses 96-bit (12-byte) nonce
            ciphertext = aesgcm.encrypt(nonce, data, None)
            return ciphertext, {'nonce': nonce, 'scheme': scheme_name}

        elif scheme_name == 'AES-CBC':
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            iv = os.urandom(16)  # AES-CBC uses 128-bit (16-byte) IV
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return ciphertext, {'iv': iv, 'scheme': scheme_name}

        elif scheme_name == 'ChaCha20':
            nonce = os.urandom(16)  # ChaCha20 uses 128-bit (16-byte) nonce
            algorithm = algorithms.ChaCha20(key, nonce)
            cipher = Cipher(algorithm, mode=None)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return ciphertext, {'nonce': nonce, 'scheme': scheme_name}

        else:
            raise ValueError(f"Unsupported encryption scheme: {scheme_name}")

    @staticmethod
    def decrypt_data(ciphertext: bytes, key: bytes, params: dict) -> bytes:
        """Decrypt data using scheme from params"""
        scheme = params.get('scheme')
        print(f"Decrypting with scheme: {scheme}, params: {params}")

        if scheme == 'AES-GCM':
            if 'nonce' not in params:
                raise ValueError("Missing nonce for AES-GCM decryption")
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(params['nonce'], ciphertext, None)

        elif scheme == 'AES-CBC':
            if 'iv' not in params:
                raise ValueError("Missing IV for AES-CBC decryption")
            cipher = Cipher(algorithms.AES(key), modes.CBC(params['iv']))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()

        elif scheme == 'ChaCha20':
            if 'nonce' not in params:
                raise ValueError("Missing nonce for ChaCha20 decryption")
            algorithm = algorithms.ChaCha20(key, params['nonce'])
            cipher = Cipher(algorithm, mode=None)
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()

        else:
            raise ValueError(f"Unsupported encryption scheme: {scheme}")
class SecureFileSystemGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Zero-Knowledge File System")
        self.root.geometry("800x600")

        self.encryption_manager = EncryptionManager()
        self.current_scheme = tk.StringVar(value='AES-GCM')  # Default scheme
        
        # Initialize client
        self.client = SecureFileClient()
        
        # Test server connection
        if not self.client.test_connection():
            messagebox.showwarning(
                "server Connection",
                "Could not connect to server. Some features may not work."
        )
        
        # client-side key storage
        self.keys_dir = Path("client_keys")
        self.keys_dir.mkdir(exist_ok=True)
        
        # Cache directory for temporary decrypted files
        self.cache_dir = Path("client_cache")
        self.cache_dir.mkdir(exist_ok=True)
        
        # Authentication state
        self.is_authenticated = False
        self.current_user = None
        self.user_private_key = None
        self.user_public_key = None
        
        # Create frames
        self.login_frame = ttk.Frame(root, padding="20")
        self.main_frame = ttk.Frame(root, padding="20")
        
        self.setup_login_frame()
        self.setup_main_frame()
        
        # Show login frame initially
        self.show_login_frame()
    
    def setup_login_frame(self):
        # Login widgets
        ttk.Label(self.login_frame, text="Secure File System", font=('Helvetica', 16)).pack(pady=20)
        
        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.username_var).pack(pady=5)
        
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.password_var, show="*").pack(pady=5)
        
        ttk.Button(self.login_frame, text="Login", command=self.handle_login).pack(pady=20)
        
    def setup_main_frame(self):
        # File management widgets
        self.setup_toolbar()
        self.setup_file_list()
        self.setup_share_frame()
        
        
    def setup_share_frame(self):
        share_frame = ttk.LabelFrame(self.main_frame, text="Share File", padding="10")
        share_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(share_frame, text="Share with user:").pack(side=tk.LEFT, padx=5)
        self.share_username_var = tk.StringVar()
        ttk.Entry(share_frame, textvariable=self.share_username_var).pack(side=tk.LEFT, padx=5)
        ttk.Button(share_frame, text="Share", command=self.handle_share).pack(side=tk.LEFT, padx=5)

    def generate_user_keys(self, username, password):
        """Generate RSA key pair for new user and upload public key to server"""
        try:
            # Generate salt and derive key for private key encryption
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.b64encode(kdf.derive(password.encode()))

            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()

            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(key)
            )

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Save keys locally
            user_dir = self.keys_dir / username
            user_dir.mkdir(exist_ok=True)

            with open(user_dir / "private.pem", "wb") as f:
                f.write(private_pem)
            with open(user_dir / "public.pem", "wb") as f:
                f.write(public_pem)
            with open(user_dir / "salt", "wb") as f:
                f.write(salt)

            # Upload public key to server
            files = {
                'key': ('public_key', public_pem, 'application/octet-stream')
            }
            response = self.client.session.put(
                f"{self.client.server_url}/public_key/{username}",
                files=files,
                verify=False
            )

            if response.status_code != 200:
                print(f"Failed to upload public key to server: {response.text}")
                raise Exception("Failed to upload public key")

            return private_key, public_key

        except Exception as e:
            print(f"Key generation error: {str(e)}")
            raise

    def handle_login(self):
        username = self.username_var.get()
        password = self.password_var.get()

        if username and password:
            try:
                # Load or generate user keys
                private_key, public_key = self.load_user_keys(username, password)
                if private_key and public_key:
                    self.current_user = username
                    self.user_private_key = private_key
                    self.user_public_key = public_key

                    # Ensure public key is on server
                    public_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

                    # Upload/update public key on server
                    files = {
                        'key': ('public_key', public_pem, 'application/octet-stream')
                    }
                    response = self.client.session.put(
                        f"{self.client.server_url}/public_key/{username}",
                        files=files,
                        verify=False
                    )

                    if response.status_code != 200:
                        print(f"Warning: Failed to update public key on server: {response.text}")

                    self.is_authenticated = True
                    self.show_main_frame()
                    self.refresh_file_list()
                else:
                    messagebox.showerror("Error", "Failed to load user keys")
            except Exception as e:
                print(f"Login error: {str(e)}")
                messagebox.showerror("Error", f"Login failed: {str(e)}")
        else:
            messagebox.showerror("Error", "Invalid credentials")

    def load_user_keys(self, username, password):
        """Load existing user keys or generate new ones"""
        user_dir = self.keys_dir / username
        if not user_dir.exists():
            print(f"Generating new keys for user: {username}")
            return self.generate_user_keys(username, password)

        try:
            # Read salt and derive key
            with open(user_dir / "salt", "rb") as f:
                salt = f.read()

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.b64encode(kdf.derive(password.encode()))

            # Load private key
            with open(user_dir / "private.pem", "rb") as f:
                private_pem = f.read()
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=key
            )

            # Load public key
            with open(user_dir / "public.pem", "rb") as f:
                public_pem = f.read()
            public_key = serialization.load_pem_public_key(public_pem)

            return private_key, public_key

        except Exception as e:
            print(f"Failed to load keys: {str(e)}")
            return None, None

    def setup_toolbar(self):
        toolbar = ttk.Frame(self.main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        # Add encryption scheme selector
        ttk.Label(toolbar, text="Encryption:").pack(side=tk.LEFT, padx=5)
        scheme_selector = ttk.Combobox(
            toolbar,
            textvariable=self.current_scheme,
            values=list(EncryptionManager.SCHEMES.keys()),
            state='readonly',
            width=10
        )
        scheme_selector.pack(side=tk.LEFT, padx=5)

        # Existing buttons
        ttk.Button(toolbar, text="Upload File", command=self.handle_upload).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Download Selected", command=self.handle_download).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_file_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Logout", command=self.handle_logout).pack(side=tk.RIGHT, padx=5)

    def share_file_key(self, metadata, recipient_public_key):
        try:
            our_encrypted_key = base64.b64decode(metadata['key'])

            file_key = self.user_private_key.decrypt(
                our_encrypted_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            recipient_encrypted_key = recipient_public_key.encrypt(
                file_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return base64.b64encode(recipient_encrypted_key).decode('utf-8')

        except Exception as e:
            print(f"Key sharing error: {str(e)}")
            messagebox.showerror("Error", f"Key sharing failed: {str(e)}")
            return None

    def handle_download(self):
        if not self.is_authenticated:
            messagebox.showerror("Error", "Please login first")
            return

        selection = self.file_list.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a file")
            return

        try:
            # Get file ID from selection
            item = self.file_list.item(selection[0])
            file_id = item['text']
            print(f"\n=== Starting download process for file: {file_id} ===")

            # Download encrypted file and metadata from server
            encrypted_data, metadata = self.client.download_file(file_id)
            if not encrypted_data or not metadata:
                messagebox.showerror("Error", "Failed to download file from server")
                return

            print(f"Downloaded encrypted data: {len(encrypted_data)} bytes")
            print(f"Metadata received: {metadata}")

            # Check access and get correct key
            if self.current_user == metadata['owner']:
                print("User is owner, using owner's key")
                key_data = metadata['key']
            elif self.current_user in metadata.get('shared_with', {}):
                print("User is shared recipient, using shared key")
                key_data = metadata['shared_with'][self.current_user]
            else:
                print("Access denied")
                messagebox.showerror("Error", "Access denied")
                return

            # Prepare metadata for decryption with all necessary parameters
            scheme = metadata['scheme']
            decryption_params = {'scheme': scheme}

            # Add appropriate parameters based on scheme
            if scheme == 'AES-CBC':
                if 'iv' in metadata and metadata['iv']:
                    decryption_params['iv'] = base64.b64decode(metadata['iv'])
            elif scheme in ['AES-GCM', 'ChaCha20']:
                if 'nonce' in metadata and metadata['nonce']:
                    decryption_params['nonce'] = base64.b64decode(metadata['nonce'])

            decryption_metadata = {
                'key': key_data,
                'scheme': scheme,
                'params': decryption_params
            }

            print(f"Decryption metadata prepared: {decryption_metadata}")

            # Decrypt the file
            decrypted_data = self.decrypt_file(encrypted_data, decryption_metadata)
            if not decrypted_data:
                return

            # Get original filename or use default
            original_filename = metadata.get('original_filename', 'downloaded_file')

            # Prepare filename with extension if needed
            initial_filename = original_filename
            if not Path(original_filename).suffix and 'file_extension' in metadata:
                initial_filename = f"{original_filename}{metadata['file_extension']}"

            # Ask where to save the file
            save_path = filedialog.asksaveasfilename(
                initialfile=initial_filename,
                defaultextension=metadata.get('file_extension', ''),
                filetypes=[
                    ("All Files", "*.*"),
                    ("Text Files", "*.txt"),
                    ("Images", "*.png *.jpg *.jpeg *.gif"),
                    ("Documents", "*.pdf *.doc *.docx")
                ]
            )

            if save_path:
                with open(save_path, "wb") as f:
                    f.write(decrypted_data)
                print(f"File saved successfully as: {save_path}")
                messagebox.showinfo("Success", "File downloaded and decrypted successfully")

        except Exception as e:
            print(f"Download error: {str(e)}")
            print(f"Metadata structure: {metadata}")
            messagebox.showerror("Error", f"Download failed: {str(e)}")
            raise

    def decrypt_file(self, encrypted_data, metadata):
        """Decrypt a file using scheme from metadata"""
        try:
            print(f"Decrypting with metadata: {metadata}")

            scheme = metadata['scheme']
            params = metadata['params']

            # Debugging information
            print(f"Encryption scheme: {scheme}")
            print(f"Parameters before processing: {params}")

            # Verify required parameters are present
            if scheme == 'AES-CBC' and 'iv' not in params:
                raise ValueError("Missing IV for AES-CBC decryption")
            elif scheme in ['AES-GCM', 'ChaCha20'] and 'nonce' not in params:
                raise ValueError(f"Missing nonce for {scheme} decryption")

            # Decrypt file key
            encrypted_key = base64.b64decode(metadata['key'])
            file_key = self.user_private_key.decrypt(
                encrypted_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            print(f"Decrypting with scheme: {scheme}")
            print(f"Final decryption parameters: {params}")

            # Decrypt file with scheme from metadata
            return EncryptionManager.decrypt_data(encrypted_data, file_key, params)

        except Exception as e:
            print(f"Decryption error: {str(e)}")
            print(f"Metadata structure: {metadata}")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            return None

    def encrypt_file(self, file_path):
        """Encrypt a file with selected scheme"""
        try:
            scheme = EncryptionManager.SCHEMES[self.current_scheme.get()]
            file_key = os.urandom(scheme.key_size // 8)

            with open(file_path, 'rb') as f:
                data = f.read()

            encrypted_data, params = EncryptionManager.encrypt_data(
                data, file_key, self.current_scheme.get()
            )

            encrypted_key = self.user_public_key.encrypt(
                file_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Create metadata with parameters at root level
            metadata = {
                'key': base64.b64encode(encrypted_key).decode('utf-8'),
                'owner': self.current_user,
                'shared_with': {},
                'scheme': self.current_scheme.get()
            }

            # Add nonce or IV depending on scheme
            if 'nonce' in params:
                metadata['nonce'] = base64.b64encode(params['nonce']).decode('utf-8')
            if 'iv' in params:
                metadata['iv'] = base64.b64encode(params['iv']).decode('utf-8')

            return encrypted_data, metadata

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            raise




    def handle_logout(self):
        self.is_authenticated = False
        self.current_user = None
        self.username_var.set("")
        self.password_var.set("")
        self.show_login_frame()

    def handle_upload(self):
        if not self.is_authenticated:
            messagebox.showerror("Error", "Please login first")
            return
                
        filename = filedialog.askopenfilename()
        if not filename:
            return
            
        try:
            print(f"Starting upload for file: {filename}")
            original_file = Path(filename)
            
            # First encrypt the file
            encrypted_data, metadata = self.encrypt_file(filename)
            if not encrypted_data or not metadata:
                return
                
            # Add additional metadata
            metadata.update({
                'original_filename': original_file.name,
                'file_extension': original_file.suffix,
                'mime_type': self.get_mime_type(original_file),
                'owner': self.current_user,
                'upload_date': str(datetime.datetime.now())
            })
            
            # Upload to server
            file_id = self.client.upload_file(original_file, encrypted_data, metadata)
            if not file_id:
                messagebox.showerror("Error", "Failed to upload file to server")
                return
                
            print(f"File encrypted and uploaded with ID: {file_id}")
            print(f"Original filename: {metadata['original_filename']}")
            
            self.refresh_file_list()
            messagebox.showinfo("Success", f"File {original_file.name} uploaded successfully")
            
        except Exception as e:
            print(f"Upload error: {str(e)}")
            messagebox.showerror("Error", f"Upload failed: {str(e)}")
            raise

    def get_mime_type(self, file_path):
        """Get MIME type based on file extension"""
        import mimetypes
        mime_type, _ = mimetypes.guess_type(str(file_path))
        return mime_type or 'application/octet-stream'

    def handle_share(self):
        if not self.is_authenticated:
            messagebox.showerror("Error", "Please login first")
            return

        selection = self.file_list.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a file to share")
            return

        share_username = self.share_username_var.get()
        if not share_username:
            messagebox.showerror("Error", "Please enter a username to share with")
            return

        try:
            # Get file ID from selection
            item = self.file_list.item(selection[0])
            file_id = item['text']

            # Get file metadata from server
            response = self.client.session.get(
                f"{self.client.server_url}/metadata/{file_id}",
                verify=False
            )

            if response.status_code != 200:
                messagebox.showerror("Error", "Failed to get file metadata")
                return

            metadata = response.json()

            # Check ownership
            if metadata['owner'] != self.current_user:
                messagebox.showerror("Error", "Only the owner can share this file")
                return

            # Check if already shared with this user
            if share_username in metadata.get('shared_with', {}):
                messagebox.showinfo("Info", f"File already shared with {share_username}")
                return

            # Get recipient's public key from server
            response = self.client.session.get(
                f"{self.client.server_url}/public_key/{share_username}",
                verify=False
            )

            if response.status_code != 200:
                messagebox.showerror("Error", f"User {share_username} not found")
                return

            # Load recipient's public key
            recipient_public_key = serialization.load_pem_public_key(response.content)

            # Share the file key
            shared_key = self.share_file_key(metadata, recipient_public_key)
            if not shared_key:
                return

            # Update metadata with shared key
            if 'shared_with' not in metadata:
                metadata['shared_with'] = {}
            metadata['shared_with'][share_username] = shared_key

            # Update metadata on server
            response = self.client.session.put(
                f"{self.client.server_url}/metadata/{file_id}",
                json=metadata,
                verify=False
            )

            if response.status_code != 200:
                messagebox.showerror("Error", "Failed to update file sharing")
                return

            self.refresh_file_list()
            messagebox.showinfo("Success", f"File shared with {share_username}")
            self.share_username_var.set("")

        except Exception as e:
            print(f"Sharing error: {str(e)}")
            messagebox.showerror("Error", f"Sharing failed: {str(e)}")

    # Also, update refresh_file_list to use server data:
    def refresh_file_list(self):
        """Update the file list from server"""
        for item in self.file_list.get_children():
            self.file_list.delete(item)

        if not self.is_authenticated:
            return

        try:
            # Get file list from server
            response = self.client.session.post(
                f"{self.client.server_url}/list",
                json={'username': self.current_user},
                verify=False
            )

            if response.status_code != 200:
                print("Failed to get file list from server")
                return

            files = response.json().get('files', [])

            # Update the treeview
            for file in files:
                metadata = file['metadata']
                file_id = file['file_id']

                self.file_list.insert("", tk.END,
                                      text=file_id,
                                      values=(
                                          metadata['owner'],
                                          ', '.join(metadata.get('shared_with', {}).keys()) or 'No one',
                                          metadata.get('original_filename', 'Unknown'),
                                          metadata.get('mime_type', 'Unknown')
                                      )
                                      )

        except Exception as e:
            print(f"Failed to refresh file list: {str(e)}")
            messagebox.showerror("Error", f"Failed to refresh file list: {str(e)}")

    def handle_file_select(self, event):
        selection = self.file_list.selection()
        if selection:
            item = self.file_list.item(selection[0])
            file_id = item['text']
            
            try:
                # Read metadata
                metadata_path = self.cache_dir / f"{file_id}.meta"
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    
                info_text = f"""
                File ID: {file_id}
                Owner: {metadata['owner']}
                Shared with: {', '.join(metadata['shared_with'].keys()) or 'No one'}
                """
                messagebox.showinfo("File Info", info_text)
                
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file info: {str(e)}")


    def setup_file_list(self):
        # File list with scrollbar
        list_frame = ttk.Frame(self.main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.file_list = ttk.Treeview(
            list_frame, 
            columns=("Owner", "Shared With", "Filename", "Type"),
            show="headings"
        )
        
        # Define columns
        self.file_list.heading("Owner", text="Owner")
        self.file_list.heading("Shared With", text="Shared With")
        self.file_list.heading("Filename", text="Filename")
        self.file_list.heading("Type", text="Type")
        
        # Set column widths
        self.file_list.column("Owner", width=100)
        self.file_list.column("Shared With", width=150)
        self.file_list.column("Filename", width=200)
        self.file_list.column("Type", width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_list.yview)
        self.file_list.configure(yscrollcommand=scrollbar.set)
        
        self.file_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
                
    def show_login_frame(self):
        self.main_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
    def show_main_frame(self):
        self.login_frame.pack_forget()
        self.main_frame.pack(fill=tk.BOTH, expand=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileSystemGUI(root)
    root.mainloop()