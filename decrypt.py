import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

password = ""

private_key = """

"""

message_encrypted =""


def extract_key_from_armor(armored: str) -> bytes:
    lines = armored.strip().splitlines()
    key_base64 = "".join(line.strip() for line in lines if not line.startswith("-----") and not line.startswith("Version:"))
    return base64.b64decode(key_base64)


def decrypt_private_key(encrypted: bytes, password: str) -> bytes:
    if len(encrypted) < 16 + 12 + 16:
        raise ValueError("Encrypted key too short — not valid GCM format.")

    salt = encrypted[:16]
    iv = encrypted[16:28]
    cipher_data = encrypted[28:-16]
    tag = encrypted[-16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    aes_key = kdf.derive(password.encode())

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(cipher_data) + decryptor.finalize()



def load_private_key_from_armor(armored: str, password: str = "") -> ec.EllipticCurvePrivateKey:
    raw = extract_key_from_armor(armored)

    try:
        return serialization.load_der_private_key(raw, password=None, backend=default_backend())
    except ValueError:
        pass

    if not password:
        raise ValueError("Encrypted private key detected, but no password provided.")

    # Second try: decrypt and parse
    decrypted_bytes = decrypt_private_key(raw, password)

    return serialization.load_der_private_key(decrypted_bytes, password=None, backend=default_backend())

def decrypt_with_ephemeral_ecdh(encrypted_text_b64: str, armored_private_key: str, password: str = "") -> str:
    encrypted_bytes = base64.b64decode(encrypted_text_b64)
    offset = 0

    # Read ephemeral public key
    ephemeral_len = encrypted_bytes[offset]
    offset += 1

    ephemeral_pub_key_bytes = encrypted_bytes[offset:offset + ephemeral_len]
    offset += ephemeral_len

    # Read IV
    iv = encrypted_bytes[offset:offset + 12]
    offset += 12

    # Ciphertext + GCM tag
    ciphertext_with_tag = encrypted_bytes[offset:]
    if len(ciphertext_with_tag) < 16:
        raise ValueError("Ciphertext too short to contain a valid GCM tag.")

    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    # Load private key
    private_key = load_private_key_from_armor(armored_private_key, password)

    # Load ephemeral public key
    ephemeral_public_key = serialization.load_der_public_key(ephemeral_pub_key_bytes, backend=default_backend())

    # Derive shared secret
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive AES-128 key from shared secret and ephemeral public key
    digest = hashlib.sha256()
    digest.update(shared_secret)
    digest.update(ephemeral_pub_key_bytes)
    aes_key = digest.digest()[:16]  # AES-128

    # Decrypt with AES-GCM
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")


decrypted = decrypt_with_ephemeral_ecdh(message_encrypted, private_key, password)
print("Decrypted:", decrypted)

