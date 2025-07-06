import base64
from plistlib import UID
from key_manager import KeyManager
from crypto_operations import CryptoOperations, EncryptionResult
from otp_generator import OTPGenerator, SerialNumberGenerator
from qr_generator import QRCodeGenerator
from supabase_utils import create_client, Client
from supabase_utils import log_otp_to_supabase, mark_otp_unusable_by_uid
from dotenv import load_dotenv
import os
import json

load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)



def generate_otp_qr_code(Machine_IP: str, Uid: str) -> dict:
    mark_otp_unusable_by_uid(Uid)

    print("Generating OTP QR code...")
    key_manager = KeyManager(supabase, Uid)
    otp_generator = OTPGenerator()
    qr_generator = QRCodeGenerator()
    crypto_ops = CryptoOperations()

    private_key, public_key = key_manager.get_or_create_keys()
    if private_key is None or public_key is None:
        print("Failed to obtain keys.")
        return None

    # 1. Generate OTP
    data_to_encrypt = otp_generator.generate_numeric_otp()

    # 2. Encrypt the OTP
    encryption_result = crypto_ops.encrypt_data(data_to_encrypt, public_key)

    # 3. Encode IV and Tag for storage/transmission
    iv_b64 = base64.b64encode(encryption_result.iv).decode()
    tag_b64 = base64.b64encode(encryption_result.tag).decode()

    # 4. Create signed message using ciphertext (as bytes) from EncryptionResult
    # Wrap encryption_result in namedtuple for compatibility with create_signed_message
    enc_result_namedtuple = EncryptionResult(
        ciphertext=encryption_result.ciphertext,
        iv=encryption_result.iv,
        tag=encryption_result.tag,
        ephemeral_public_key=encryption_result.ephemeral_public_key
    )
    message = crypto_ops.create_signed_message(data_to_encrypt, enc_result_namedtuple)

    # 5. Sign the message
    signature = crypto_ops.sign_message(message, private_key)

    # 6. Create QR code with encrypted OTP and signature
    cipher_text = qr_generator.create_secure_qr_code(data_to_encrypt, encryption_result, signature)
    print(f"Generated OTP QR code: {cipher_text}")

    # 7. Log to Supabase with all needed fields
    log_otp_to_supabase(
        uid=Uid,
        machine_ip=Machine_IP,
        cellular_ip="NULL",
        cipher_text=cipher_text,
        otp=data_to_encrypt,
        iv=iv_b64,
        tag=tag_b64
    )

    # 8. Return full info for caller
    return {
        "otp": data_to_encrypt,
        "signature": signature,
        "cipher_text": cipher_text,
        "private_key": private_key,
        "public_key": public_key,
        "iv": iv_b64,
        "tag": tag_b64
    }

def verify_otp_qr_code(message, signature, public_key, encryption_result, private_key):
    """
    Verify signature and decrypt OTP.
    Returns a dictionary with verification results.
    """
    crypto_ops = CryptoOperations()
    is_valid = crypto_ops.verify_signature(message, signature, public_key)
    decrypted_data = crypto_ops.decrypt_data(
        encryption_result.ciphertext,
        encryption_result.iv,
        encryption_result.tag,
        encryption_result.ephemeral_public_key,
        private_key
    )
    return {
        "signature_valid": is_valid,
        "decrypted_data": decrypted_data,
    }

def demo_full_cycle(UID: str) -> dict:
    """
    Demonstrate the complete encryption/decryption cycle.
    Returns a dictionary with all relevant data.
    """
    key_manager = KeyManager(supabase, UID)
    otp_generator = OTPGenerator()
    qr_generator = QRCodeGenerator()
    crypto_ops = CryptoOperations()

    private_key, public_key = key_manager.get_or_create_keys()
    serial = "TEST123"
    otp = otp_generator.generate_numeric_otp()
    uniqueKey = f"{serial}:{otp}"
    encryption_result = crypto_ops.encrypt_data(uniqueKey, public_key)
    message = crypto_ops.create_signed_message(uniqueKey, encryption_result)
    signature = crypto_ops.sign_message(message, private_key)
    output_path = qr_generator.create_secure_qr_code(serial, encryption_result, signature)
    is_valid = crypto_ops.verify_signature(message, signature, public_key)
    decrypted_otp = crypto_ops.decrypt_data(
        encryption_result.ciphertext,
        encryption_result.iv,
        encryption_result.tag,
        encryption_result.ephemeral_public_key,
        private_key
    )
    return {
        "serial": serial,
        "otp": otp,
        "encryption_result": encryption_result,
        "signature": signature,
        "qr_code_path": output_path,
        "message": message,
        "signature_valid": is_valid,
        "decrypted_otp": decrypted_otp,
        "private_key": private_key,
        "public_key": public_key,
    }


def decrypt_otp_from_cipher_text(cipher_text_b64: str, uid: str, supabase_client) -> str:
    """
    Decrypt OTP from base64 QR payload string (cipher_text).
    
    Params:
    - cipher_text_b64: The base64-encoded JSON QR payload (from Supabase or QR scan)
    - uid: User ID to load private key
    - supabase_client: Supabase client object
    
    Returns:
    - Decrypted OTP string
    """
    # 1. Decode base64 QR payload to JSON string

    json_str = base64.b64decode(cipher_text_b64).decode()
    payload = json.loads(json_str)


    # 2. Extract and base64-decode encryption params
    ciphertext = base64.b64decode(payload["encrypted_otp"])
    iv = base64.b64decode(payload["iv"])
    tag = base64.b64decode(payload["tag"])
    ephemeral_pub_key_bytes = base64.b64decode(payload["ephemeral_pub_key"])
    
    # 3. Load private key from Supabase via KeyManager
    key_manager = KeyManager(supabase_client, uid)
    private_key, _ = key_manager.get_or_create_keys()
    if private_key is None:
        raise ValueError("Private key not found for user.")
    
    # 4. Deserialize ephemeral public key
    ephemeral_public_key = CryptoOperations.deserialize_public_key(ephemeral_pub_key_bytes)
    
    # 5. Decrypt using CryptoOperations
    decrypted_otp = CryptoOperations.decrypt_data(
        ciphertext=ciphertext,
        iv=iv,
        tag=tag,
        ephemeral_public_key=ephemeral_public_key,
        private_key=private_key
    )
    
    return decrypted_otp