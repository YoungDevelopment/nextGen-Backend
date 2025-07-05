"""
Cryptographic operations module for encryption, decryption, and digital signatures.
"""

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Tuple, NamedTuple
import config


class EncryptionResult(NamedTuple):
    """Result of encryption operation."""
    ciphertext: bytes
    iv: bytes
    tag: bytes
    ephemeral_public_key: ec.EllipticCurvePublicKey


class CryptoOperations:
    """Handles encryption, decryption, and digital signature operations."""
    
    @staticmethod
    def generate_ephemeral_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate ephemeral key pair for ECDH."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def derive_shared_key(private_key: ec.EllipticCurvePrivateKey, 
                         public_key: ec.EllipticCurvePublicKey) -> bytes:
        """Derive shared key using ECDH and HKDF."""
        shared_secret = private_key.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=config.AES_KEY_SIZE,
            salt=None,
            info=config.HKDF_INFO,
            backend=default_backend()
        ).derive(shared_secret)
        return derived_key
    
    @staticmethod
    def encrypt_data(data: str, public_key: ec.EllipticCurvePublicKey) -> EncryptionResult:
        """Encrypt data using AES-GCM with ephemeral ECDH key exchange."""
        # Generate ephemeral key pair
        ephemeral_private, ephemeral_public = CryptoOperations.generate_ephemeral_key_pair()
        
        # Derive encryption key
        derived_key = CryptoOperations.derive_shared_key(ephemeral_private, public_key)
        
        # Encrypt data
        iv = os.urandom(config.GCM_IV_SIZE)
        encryptor = Cipher(
            algorithms.AES(derived_key), 
            modes.GCM(iv), 
            backend=default_backend()
        ).encryptor()
        
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        tag = encryptor.tag
        
        return EncryptionResult(ciphertext, iv, tag, ephemeral_public)
    
    @staticmethod
    def decrypt_data(ciphertext: bytes, iv: bytes, tag: bytes,
                    ephemeral_public_key: ec.EllipticCurvePublicKey,
                    private_key: ec.EllipticCurvePrivateKey) -> str:
        """Decrypt data using AES-GCM with ECDH key exchange."""
        # Derive decryption key
        derived_key = CryptoOperations.derive_shared_key(private_key, ephemeral_public_key)
        
        # Decrypt data
        decryptor = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    
    @staticmethod
    def sign_message(message: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """Sign a message using ECDSA with SHA256."""
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature
    
    @staticmethod
    def verify_signature(message: bytes, signature: bytes, 
                        public_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify a signature using ECDSA with SHA256."""
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
    
    @staticmethod
    def create_signed_message(serial: str, encryption_result: EncryptionResult) -> bytes:
        """Create a message for signing (ciphertext)"""
        message = (
                  encryption_result.ciphertext 
                  )
        return message
    
    @staticmethod
    def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
        """Serialize public key to X962 uncompressed point format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    @staticmethod
    def deserialize_public_key(key_bytes: bytes) -> ec.EllipticCurvePublicKey:
        """Deserialize public key from X962 uncompressed point format."""
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            key_bytes
        )