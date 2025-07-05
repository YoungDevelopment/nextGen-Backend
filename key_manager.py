"""
ECC Key management module for generating, saving, and loading cryptographic keys from Supabase.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Tuple, Optional
from supabase_utils import Client
from supabase_utils import (
    save_keys_to_supabase,
    load_keys_from_supabase,
    keys_exist_in_supabase,
    delete_keys_from_supabase,
    get_public_key_from_supabase,
)


class KeyManager:
    """Handles ECC key generation, saving, and loading operations with Supabase."""

    def __init__(self, supabase_client: Client, uid: str):
        self.supabase = supabase_client
        self.uid = uid
        self.table_name = 'Keys'

    def generate_key_pair(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def _serialize_private_key(self, private_key: ec.EllipticCurvePrivateKey) -> str:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

    def _serialize_public_key(self, public_key: ec.EllipticCurvePublicKey) -> str:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def _deserialize_private_key(self, pem_data: str) -> ec.EllipticCurvePrivateKey:
        return serialization.load_pem_private_key(
            pem_data.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

    def _deserialize_public_key(self, pem_data: str) -> ec.EllipticCurvePublicKey:
        return serialization.load_pem_public_key(
            pem_data.encode('utf-8'),
            backend=default_backend()
        )

    def save_keys(self, private_key: ec.EllipticCurvePrivateKey, public_key: ec.EllipticCurvePublicKey) -> bool:
        private_pem = self._serialize_private_key(private_key)
        public_pem = self._serialize_public_key(public_key)
        return save_keys_to_supabase(self.supabase, self.uid, private_pem, public_pem)

    def load_keys(self) -> Optional[Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]]:
        key_data = load_keys_from_supabase(self.supabase, self.uid)
        if not key_data:
            return None
        private_key = self._deserialize_private_key(key_data['Private_Key'])
        public_key = self._deserialize_public_key(key_data['Public_Key'])
        return private_key, public_key

    def keys_exist(self) -> bool:
        return keys_exist_in_supabase(self.supabase, self.uid)

    def generate_and_save_keys(self) -> Optional[Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]]:
        private_key, public_key = self.generate_key_pair()
        if self.save_keys(private_key, public_key):
            return private_key, public_key
        return None

    def get_or_create_keys(self) -> Optional[Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]]:
        keys = self.load_keys()
        if keys:
            return keys
        return self.generate_and_save_keys()

    def delete_keys(self) -> bool:
        return delete_keys_from_supabase(self.supabase, self.uid)

    def get_public_key_only(self) -> Optional[ec.EllipticCurvePublicKey]:
        public_pem = get_public_key_from_supabase(self.supabase, self.uid)
        if public_pem:
            return self._deserialize_public_key(public_pem)
        return None

    def update_keys(self, private_key: ec.EllipticCurvePrivateKey, public_key: ec.EllipticCurvePublicKey) -> bool:
        return self.save_keys(private_key, public_key)
