# Secure OTP QR Code Generator

A modular Python application for generating secure OTP (One-Time Password) QR codes using elliptic curve cryptography, AES-GCM encryption, and digital signatures.

## Features

- **ECC Key Management**: Generate and manage SECP256R1 elliptic curve key pairs
- **Secure Encryption**: AES-GCM encryption with ephemeral ECDH key exchange
- **Digital Signatures**: ECDSA signatures for message authentication
- **QR Code Generation**: Secure QR codes containing encrypted OTP data
- **Modular Design**: Clean, maintainable code structure

## Architecture

The application is divided into several modules:

### Core Modules

1. **`config.py`** - Configuration constants and settings
2. **`key_manager.py`** - ECC key generation, saving, and loading
3. **`crypto_operations.py`** - Encryption, decryption, and signature operations
4. **`otp_generator.py`** - OTP and serial number generation
5. **`qr_generator.py`** - QR code generation and payload handling
6. **`main.py`** - Main application orchestrating all components

### Security Features

- **Elliptic Curve Cryptography**: Uses SECP256R1 curve for key generation
- **Ephemeral Key Exchange**: ECDH with ephemeral keys for forward secrecy
- **AES-GCM Encryption**: Authenticated encryption with 256-bit keys
- **Digital Signatures**: ECDSA with SHA-256 for message integrity
- **Secure Random Generation**: Cryptographically secure random number generation

## Installation

1. Clone or download the project files
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Run the main application:

```bash
python main.py
```

This will:

1. Generate or load ECC key pairs
2. Generate a 4-digit OTP
3. Encrypt the OTP using AES-GCM
4. Create a digital signature
5. Generate a QR code with the encrypted data
6. Verify the entire process

### Advanced Usage

#### Custom OTP Generation

```python
from otp_generator import OTPGenerator

# Numeric OTP (default)
otp_gen = OTPGenerator(length=6)
numeric_otp = otp_gen.generate_numeric_otp()

# Alphanumeric OTP
alpha_otp = otp_gen.generate_alphanumeric_otp()

# Custom serial number
from otp_generator import SerialNumberGenerator
serial = SerialNumberGenerator.generate_serial("DEV", 10)
```

#### Key Management

```python
from key_manager import KeyManager

key_mgr = KeyManager()

# Generate new keys
private_key, public_key = key_mgr.generate_and_save_keys()

# Load existing keys
private_key = key_mgr.load_private_key()
public_key = key_mgr.load_public_key()

# Get or create keys
private_key, public_key = key_mgr.get_or_create_keys()
```

#### Encryption and Decryption

```python
from crypto_operations import CryptoOperations

crypto = CryptoOperations()

# Encrypt data
encryption_result = crypto.encrypt_data("1234", public_key)

# Decrypt data
decrypted = crypto.decrypt_data(
    encryption_result.ciphertext,
    encryption_result.iv,
    encryption_result.tag,
    encryption_result.ephemeral_public_key,
    private_key
)
```

#### QR Code Operations

```python
from qr_generator import QRCodeGenerator

qr_gen = QRCodeGenerator()

# Create secure QR code
output_path = qr_gen.create_secure_qr_code(
    serial_number, encryption_result, signature
)

# Read QR code payload
from qr_generator import QRCodeReader
reader = QRCodeReader()
payload = reader.extract_payload_from_qr(qr_data)
```

## File Structure

```
├── config.py              # Configuration constants
├── key_manager.py          # ECC key management
├── crypto_operations.py    # Cryptographic operations
├── otp_generator.py        # OTP and serial generation
├── qr_generator.py         # QR code generation
├── main.py                 # Main application
├── requirements.txt        # Dependencies
├── README.md              # This file
├── keys/                  # Generated key files
│   ├── ecc_private_key.pem
│   └── ecc_public_key.pem
└── output/                # Generated QR codes
    └── otp_qr_code.png
```

## Security Considerations

1. **Key Storage**: Private keys are stored unencrypted in PEM format. For production use, consider encrypting private keys with a password.

2. **Key Rotation**: Implement regular key rotation for enhanced security.

3. **Secure Channels**: Ensure QR codes are transmitted over secure channels.

4. **Access Control**: Implement proper access controls for key files and generated QR codes.

5. **Audit Logging**: Consider adding audit logging for key generation and usage.

## QR Code Payload Structure

The QR code contains a Base64-encoded JSON payload with the following structure:

```json
{
  "serial": "ABC12345",
  "encrypted_otp": "base64_encrypted_data",
  "iv": "base64_initialization_vector",
  "tag": "base64_authentication_tag",
  "ephemeral_pub_key": "base64_ephemeral_public_key",
  "signature": "base64_digital_signature"
}
```

## Error Handling

The application includes comprehensive error handling:

- **Key Management Errors**: Missing key files, invalid key formats
- **Encryption Errors**: Invalid keys, encryption failures
- **QR Code Errors**: Data too large, invalid formats
- **Signature Errors**: Invalid signatures, verification failures

## Testing

Run the demonstration cycle:

```python
# In main.py, uncomment the demo function call
demo_full_cycle()
```

This will demonstrate the complete encryption/decryption cycle with verification.

## Dependencies

- **cryptography**: For ECC, AES-GCM, and ECDSA operations
- **qrcode[pil]**: For QR code generation with PIL support
- **Pillow**: For image processing (included with qrcode[pil])

## License

This project is provided as-is for educational and development purposes. Please ensure compliance with your organization's security policies before using in production.

## Contributing

1. Follow the existing code structure and naming conventions
2. Add appropriate error handling and logging
3. Include docstrings for all public methods
4. Test thoroughly before submitting changes

## Support

For issues or questions, please review the code documentation and error messages. The modular design makes it easy to debug and extend individual components.
