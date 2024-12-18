import requests
import json
from pathlib import Path
import urllib3
import uuid
from typing import Optional, Dict, Any, Tuple

# Disable SSL warning for self-signed certificates in development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecureFileClient:
    def __init__(self, server_url: str = "https://localhost:3000"):
        self.server_url = server_url
        self.session = requests.Session()

        # Configure SSL verification
        self.session.verify = False  # Disable SSL verification for development

        # Configure SSL adapter with custom settings
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=3,
            pool_block=False
        )
        self.session.mount('https://', adapter)

    def test_connection(self) -> bool:
        """Test if server is accessible"""
        try:
            response = self.session.get(
                f"{self.server_url}/health",
                timeout=5,
                verify=False  # Explicitly disable verification for test
            )
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            print(f"Connection test failed: {str(e)}")
            return False

    def upload_file(self, file_path: Path, encrypted_data: bytes, metadata: Dict[str, Any]) -> Optional[str]:
        """
        Upload an encrypted file to the server
        Returns file_id if successful, None otherwise
        """
        try:
            # Generate a unique file ID
            file_id = str(uuid.uuid4())
            metadata['file_id'] = file_id

            # Prepare the file and metadata for upload
            files = {
                'file': ('encrypted_file', encrypted_data, 'application/octet-stream')
            }
            data = {
                'metadata': json.dumps(metadata)
            }

            # Send the request
            response = self.session.post(
                f"{self.server_url}/upload",
                files=files,
                data=data
            )

            if response.status_code == 200:
                return file_id
            else:
                print(f"Upload failed: {response.json().get('error', 'Unknown error')}")
                return None

        except Exception as e:
            print(f"Upload error: {str(e)}")
            return None

    def download_file(self, file_id: str) -> Tuple[Optional[bytes], Optional[Dict[str, Any]]]:
        """
        Download an encrypted file and its metadata from the server
        Returns (encrypted_data, metadata) if successful, (None, None) otherwise
        """
        try:
            # Get the file
            response = self.session.get(f"{self.server_url}/download/{file_id}")
            if response.status_code != 200:
                print(f"Download failed: {response.json().get('error', 'Unknown error')}")
                return None, None

            encrypted_data = response.content

            # Get the metadata
            metadata_response = self.session.get(f"{self.server_url}/metadata/{file_id}")
            if metadata_response.status_code != 200:
                print(f"Metadata retrieval failed: {metadata_response.json().get('error', 'Unknown error')}")
                return None, None

            metadata = metadata_response.json()
            return encrypted_data, metadata

        except Exception as e:
            print(f"Download error: {str(e)}")
            return None, None

    def list_files(self, username: str) -> Optional[list]:
        """
        Get list of files accessible to the user
        """
        try:
            response = self.session.post(
                f"{self.server_url}/list",
                json={'username': username}
            )

            if response.status_code == 200:
                return response.json().get('files', [])
            else:
                print(f"List files failed: {response.json().get('error', 'Unknown error')}")
                return None

        except Exception as e:
            print(f"List files error: {str(e)}")
            return None

    def store_public_key(self, username: str, public_key_data: bytes) -> bool:
        """
        Store user's public key on the server
        """
        try:
            files = {
                'key': ('public_key', public_key_data, 'application/octet-stream')
            }
            response = self.session.put(
                f"{self.server_url}/public_key/{username}",
                files=files
            )

            return response.status_code == 200

        except Exception as e:
            print(f"Store public key error: {str(e)}")
            return False

    def get_public_key(self, username: str) -> Optional[bytes]:
        """
        Retrieve a user's public key from the server
        """
        try:
            response = self.session.get(f"{self.server_url}/public_key/{username}")

            if response.status_code == 200:
                return response.content
            else:
                print(f"Get public key failed: {response.json().get('error', 'Unknown error')}")
                return None

        except Exception as e:
            print(f"Get public key error: {str(e)}")
            return None

    def update_metadata(self, file_id: str, metadata: Dict[str, Any]) -> bool:
        """
        Update file metadata (used for sharing)
        """
        try:
            response = self.session.put(
                f"{self.server_url}/metadata/{file_id}",
                json=metadata
            )

            return response.status_code == 200

        except Exception as e:
            print(f"Update metadata error: {str(e)}")
            return False

    def share_file(self, file_id: str, owner: str, recipient: str, encrypted_key: str) -> bool:
        """
        Share a file with another user by updating metadata
        """
        try:
            # Get current metadata
            response = self.session.get(f"{self.server_url}/metadata/{file_id}")
            if response.status_code != 200:
                return False

            metadata = response.json()

            # Update sharing information
            if 'shared_with' not in metadata:
                metadata['shared_with'] = {}
            metadata['shared_with'][recipient] = encrypted_key

            # Update metadata on server
            return self.update_metadata(file_id, metadata)

        except Exception as e:
            print(f"Share file error: {str(e)}")
            return False

    def verify_server_certificate(self, cert_path: Path) -> bool:
        """
        For production: verify server certificate against a known CA
        """
        try:
            self.session.verify = str(cert_path)
            response = self.session.get(f"{self.server_url}/health")
            return response.status_code == 200
        except Exception:
            return False

if __name__ == "__main__":
    # Test client functionality
    client = SecureFileClient()

    # Test connection
    try:
        response = client.session.get(f"{client.server_url}/health")
        print(f"Server connection: {'OK' if response.status_code == 200 else 'Failed'}")
    except Exception as e:
        print(f"Connection test failed: {str(e)}")