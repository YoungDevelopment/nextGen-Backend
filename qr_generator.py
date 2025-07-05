"""
QR code generation module for secure OTP payloads.
"""

import base64
import json
import qrcode
from pathlib import Path
from typing import Dict, Any, Optional
from PIL import Image
import config
from crypto_operations import EncryptionResult


class QRCodeGenerator:
    """Handles QR code generation for encrypted OTP payloads."""
    
    def __init__(self, output_dir: Path = config.OUTPUT_DIR):
        """Initialize with output directory."""
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)
    
    def create_payload(self, serial: str, encryption_result: EncryptionResult, 
                      signature: bytes) -> Dict[str, Any]:
        """Create the JSON payload for QR code."""
        from crypto_operations import CryptoOperations
        
        payload = {
            "serial": serial,
            "encrypted_otp": base64.b64encode(encryption_result.ciphertext).decode(),
            "iv": base64.b64encode(encryption_result.iv).decode(),
            "tag": base64.b64encode(encryption_result.tag).decode(),
            "ephemeral_pub_key": base64.b64encode(
                CryptoOperations.serialize_public_key(encryption_result.ephemeral_public_key)
            ).decode(),
            "signature": base64.b64encode(signature).decode()
        }
        return payload
    
    def encode_payload(self, payload: Dict[str, Any]) -> str:
        """Encode payload as base64 JSON string."""
        json_str = json.dumps(payload, separators=(',', ':'))  # Compact JSON
        return base64.b64encode(json_str.encode()).decode()
    
    def decode_payload(self, encoded_data: str) -> Dict[str, Any]:
        """Decode base64 JSON string back to payload."""
        json_str = base64.b64decode(encoded_data).decode()
        return json.loads(json_str)
    
    def generate_qr_code(self, data: str, filename: str = config.QR_CODE_FILENAME,
                        error_correction: int = qrcode.constants.ERROR_CORRECT_L) -> str:
        """Generate QR code from data string."""
        qr = qrcode.QRCode(
            version=1,
            error_correction=error_correction,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        # Create QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to file
        output_path = self.output_dir / filename
        img.save(output_path)
        
        return str(output_path)
    
    def create_secure_qr_code(self, serial: str, encryption_result: EncryptionResult,
                             signature: bytes, filename: Optional[str] = None) -> str:
        """Create a complete secure QR code with encrypted OTP."""
        if filename is None:
            filename = f"otp_qr_{serial}.png"
        
        # Create payload
        payload = self.create_payload(serial, encryption_result, signature)
        
        # Encode payload
        encoded_data = self.encode_payload(payload)
        
        # Generate QR code
        output_path = self.generate_qr_code(encoded_data, filename)
        
        return encoded_data
    
    def get_qr_data_size(self, data: str) -> int:
        """Get the size of data in bytes."""
        return len(data.encode())
    
    def validate_qr_size(self, data: str, max_size: int = 2900) -> bool:
        """Validate if data fits in QR code capacity."""
        return self.get_qr_data_size(data) <= max_size


class QRCodeReader:
    """Handles QR code reading and payload extraction."""
    
    def __init__(self):
        """Initialize QR code reader."""
        pass
    
    def extract_payload_from_qr(self, qr_data: str) -> Dict[str, Any]:
        """Extract and decode payload from QR code data."""
        generator = QRCodeGenerator()
        return generator.decode_payload(qr_data)
    
    def parse_encryption_data(self, payload: Dict[str, Any]) -> tuple:
        """Parse encryption data from payload."""
        serial = payload["serial"]
        encrypted_otp = base64.b64decode(payload["encrypted_otp"])
        iv = base64.b64decode(payload["iv"])
        tag = base64.b64decode(payload["tag"])
        ephemeral_pub_key_bytes = base64.b64decode(payload["ephemeral_pub_key"])
        signature = base64.b64decode(payload["signature"])
        
        # Deserialize ephemeral public key
        from crypto_operations import CryptoOperations
        ephemeral_pub_key = CryptoOperations.deserialize_public_key(ephemeral_pub_key_bytes)
        
        return serial, encrypted_otp, iv, tag, ephemeral_pub_key, signature