"""
OTP (One-Time Password) generation module.
"""

import secrets
import string
from typing import Optional
import config


class OTPGenerator:
    """Handles OTP generation and validation."""
    
    def __init__(self, length: int = config.OTP_LENGTH):
        """Initialize with OTP length."""
        self.length = length
    
    def generate_numeric_otp(self) -> str:
        """Generate a numeric OTP of specified length."""
        return ''.join(secrets.choice(string.digits) for _ in range(self.length))
    
    def generate_alphanumeric_otp(self) -> str:
        """Generate an alphanumeric OTP of specified length."""
        characters = string.ascii_uppercase + string.digits
        return ''.join(secrets.choice(characters) for _ in range(self.length))
    
    def generate_alpha_otp(self) -> str:
        """Generate an alphabetic OTP of specified length."""
        return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(self.length))
    
    def is_valid_otp(self, otp: str, otp_type: str = "numeric") -> bool:
        """Validate OTP format and length."""
        if len(otp) != self.length:
            return False
        
        if otp_type == "numeric":
            return otp.isdigit()
        elif otp_type == "alphanumeric":
            return otp.isalnum() and otp.isupper()
        elif otp_type == "alpha":
            return otp.isalpha() and otp.isupper()
        else:
            return False


class SerialNumberGenerator:
    """Handles serial number generation."""
    
    @staticmethod
    def generate_serial(prefix: str = "ABC", length: int = 8) -> str:
        """Generate a serial number with given prefix and total length."""
        if len(prefix) >= length:
            raise ValueError("Prefix length must be less than total length")
        
        remaining_length = length - len(prefix)
        numbers = ''.join(secrets.choice(string.digits) for _ in range(remaining_length))
        return prefix + numbers
    
    @staticmethod
    def is_valid_serial(serial: str, expected_prefix: Optional[str] = None) -> bool:
        """Validate serial number format."""
        if not serial:
            return False
        
        if expected_prefix and not serial.startswith(expected_prefix):
            return False
        
        return True


# Convenience functions for backward compatibility
def generate_otp(length: int = config.OTP_LENGTH) -> str:
    """Generate a numeric OTP (convenience function)."""
    generator = OTPGenerator(length)
    return generator.generate_numeric_otp()


def generate_serial_number(prefix: str = "ABC", length: int = 8) -> str:
    """Generate a serial number (convenience function)."""
    return SerialNumberGenerator.generate_serial(prefix, length)