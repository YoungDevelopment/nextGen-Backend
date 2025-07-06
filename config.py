"""
Configuration constants for the OTP QR code system.
"""

import os
from pathlib import Path

# Cryptographic constants
ECC_CURVE = "SECP256R1"
OTP_LENGTH = 4
AES_KEY_SIZE = 32  # 256 bits
GCM_IV_SIZE = 12   # 96 bits
HKDF_INFO = b'handshake data'

# File paths
BASE_DIR = Path(__file__).parent
KEYS_DIR = BASE_DIR / "keys"
OUTPUT_DIR = Path(r"/tmp/QR")

# Key file names
PRIVATE_KEY_FILE = "ecc_private_key.pem"
PUBLIC_KEY_FILE = "ecc_public_key.pem"

# QR code settings
QR_CODE_FILENAME = "otp_qr_code.png"


KEYS_DIR = Path("/tmp/keys")
KEYS_DIR.mkdir(parents=True, exist_ok=True)
