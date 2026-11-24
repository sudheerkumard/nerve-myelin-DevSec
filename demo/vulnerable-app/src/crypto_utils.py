"""Card-token helpers (demo: deliberately mixes current, legacy and quantum-vulnerable cryptography)."""
import hashlib

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def device_key():
    return ec.generate_private_key(ec.SECP256R1())


def encrypt_pan(key: bytes, pan: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(pan.ljust(32, b"\0"))


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


JWT_ALGORITHM = "RS256"
