# cipher.py - Drop-in replacement for your existing Cipher class
# Keeps EXACT SAME method names: aes_encrypt, aes_decrypt, get_dh_public_key, get_dh_shared_key
# Uses AES-GCM (more reliable than EAX), HKDF for key derivation, fixes MAC issues

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from diffiehellman import DiffieHellman


class Cipher:
    def __init__(self, key: bytes):
        # Derive clean AES-256 key from raw DH shared secret using HKDF
        self.key = HKDF(
            master=key,
            key_len=32,  # AES-256
            salt=None,
            hashmod=SHA256
        )

    def aes_encrypt(self, data: bytes) -> bytes:
        """Your exact method name - returns nonce(12) + tag(16) + ciphertext"""
        nonce = get_random_bytes(12)  # GCM standard nonce size
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ciphertext  # 12+16+variable = same format as before

    def aes_decrypt(self, data: bytes) -> bytes:
        """Your exact method name - raises ValueError on MAC failure (wrong key/corruption)"""
        if len(data) < 28:  # 12 nonce + 16 tag minimum
            raise ValueError("Encrypted data too short")

        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)  # Replaces EAX, same behavior

    @staticmethod
    def get_dh_public_key():  # ← EXACT SAME NAME & SIGNATURE
        """Returns (dh_object, public_key_bytes) - same as your original"""
        dh = DiffieHellman(group=14)
        return dh, dh.get_public_key()

    @staticmethod
    def get_dh_shared_key(dh, other_public_key, length=32):  # ← EXACT SAME NAME & SIGNATURE
        """Same signature - now uses HKDF internally for better key material"""
        raw_shared = dh.generate_shared_key(other_public_key)
        return HKDF(
            master=raw_shared,
            key_len=length,
            salt=None,
            hashmod=SHA256
        )