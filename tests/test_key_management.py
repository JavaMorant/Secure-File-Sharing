import unittest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def test_key_generation(self):
        self.assertIsNotNone(self.private_key)
        self.assertIsNotNone(self.public_key)
        self.assertEqual(self.private_key.key_size, 2048)

    def test_key_encryption(self):
        test_data = b"Secret key data"
        encrypted_data = self.public_key.encrypt(
            test_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_data = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.assertEqual(test_data, decrypted_data)

    def test_key_storage(self):
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"testpassword")
        )
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.assertIsNotNone(private_pem)
        self.assertIsNotNone(public_pem)
