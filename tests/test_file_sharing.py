import unittest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class TestFileSharing(unittest.TestCase):
    def setUp(self):
        self.owner_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.owner_public = self.owner_private.public_key()
        self.recipient_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.recipient_public = self.recipient_private.public_key()
        self.file_key = AESGCM.generate_key(bit_length=256)

    def test_key_sharing(self):
        owner_encrypted_key = self.owner_public.encrypt(
            self.file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_key = self.owner_private.decrypt(
            owner_encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        recipient_encrypted_key = self.recipient_public.encrypt(
            decrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        final_key = self.recipient_private.decrypt(
            recipient_encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.assertEqual(self.file_key, final_key)

    def test_unauthorized_access(self):
        unauthorized_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        owner_encrypted_key = self.owner_public.encrypt(
            self.file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with self.assertRaises(ValueError):
            unauthorized_private.decrypt(
                owner_encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )