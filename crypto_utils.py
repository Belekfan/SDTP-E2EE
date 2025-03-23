# crypto_utils.py

import hashlib
import os
import secrets

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import key_derivation
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def sha256(data: bytes) -> bytes:
    """Basit SHA-256 özeti."""
    return hashlib.sha256(data).digest()


def generate_ec_keypair():
    """ECC P-256 anahtar çifti oluşturur (private_key, public_key)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_bytes(pub_key) -> bytes:
    """Public key'i 'uncompressed point' formatında bayta dönüştürür."""
    return pub_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )


def bytes_to_public_key(data: bytes):
    """Bayt verisinden ECC public key objesi oluşturur (uncompressed)."""
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def sign_data(private_key, data: bytes) -> bytes:
    """ECC private key (ECDSA) ile 'data' imzalar."""
    signature = private_key.sign(
        data,
        ECDSA(hashes.SHA256())
    )
    return signature


def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    """ECDSA imzasını doğrular. Hata/veremede False döndürür."""
    try:
        public_key.verify(signature, data, ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def derive_shared_key(private_key, peer_public_key) -> bytes:
    """
    ECDH ile ortak gizli (shared_secret) hesaplar,
    ardından HKDF(SHA-256) ile 32 byte'lık session key türetir.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bit
        salt=None,
        info=b"E2EE-SessionKey"
    )
    return hkdf.derive(shared_secret)


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> (bytes, bytes):
    """
    AES-GCM ile şifreleme.
    Dönüş: (nonce, ciphertext_with_tag)
    """
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext + encryptor.tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    """
    AES-GCM ile çözme.
    ciphertext_with_tag sonunda 16 byte'lık GCM tag içerir.
    """
    tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

