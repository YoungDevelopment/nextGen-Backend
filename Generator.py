from plistlib import UID
from key_manager import KeyManager
from crypto_operations import CryptoOperations
from otp_generator import OTPGenerator, SerialNumberGenerator
from qr_generator import QRCodeGenerator
from supabase_utils import create_client, Client
from supabase_utils import log_otp_to_supabase, mark_otp_unusable_by_uid
from dotenv import load_dotenv
import os

load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)





def generate_otp_qr_code(Machine_IP: str, Uid: str,) -> dict:
    """
    Generate OTP, encrypt it, sign, and create QR code.
    Returns a dictionary with all relevant data.
    """
    mark_otp_unusable_by_uid(Uid)

    print("Generating OTP QR code...")
    key_manager = KeyManager(supabase, Uid)
    otp_generator = OTPGenerator()
    serial_generator = SerialNumberGenerator()
    qr_generator = QRCodeGenerator()
    crypto_ops = CryptoOperations()

    private_key, public_key = key_manager.get_or_create_keys()
    if private_key is None or public_key is None:
        print("Failed to obtain keys.")
        return None


    data_to_encrypt = otp_generator.generate_numeric_otp()
   
    encryption_result = crypto_ops.encrypt_data(data_to_encrypt, public_key)
    message = crypto_ops.create_signed_message(data_to_encrypt, encryption_result)
    signature = crypto_ops.sign_message(message, private_key)
    cipher_text = qr_generator.create_secure_qr_code(data_to_encrypt, encryption_result, signature)
    print(f"Generated OTP QR code: {cipher_text}")
    log_otp_to_supabase( Uid, Machine_IP, "NULL", cipher_text, data_to_encrypt)
    return {
        "otp": data_to_encrypt,
        "signature": signature,
        "cipher_text": cipher_text,
        "private_key": private_key,
        "public_key": public_key,
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
