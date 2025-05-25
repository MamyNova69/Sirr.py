import base64
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



def generate_ec_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_private_key(private_key_bytes: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(12)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    aes_key = kdf.derive(password.encode())

    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(private_key_bytes) + encryptor.finalize()
    tag = encryptor.tag

    return salt + iv + ciphertext + tag  # same format as Kotlin


def armor(title: str, data: bytes) -> str:
    b64 = base64.b64encode(data).decode("utf-8")
    formatted = "\n".join([b64[i:i+64] for i in range(0, len(b64), 64)])
    return f"-----BEGIN {title}-----\n{formatted}\n-----END {title}-----"


def generate_and_export_keys(assword: str = ""):

    # Generate EC key pair
    private_key, public_key = generate_ec_key_pair()

    # Serialize public key (X.509 format)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Serialize private key (PKCS8 DER format)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # we encrypt manually below
    )

    # Encrypt private key if password is provided
    protected_private_key = encrypt_private_key(private_key_bytes, password) if password else private_key_bytes

    # Armor both
    armored_pub = armor("PUBLIC KEY", public_key_bytes)
    armored_priv = armor("PRIVATE KEY", protected_private_key)

    return armored_priv, armored_pub



password = "StrongPass123"

armored_priv, armored_pub = generate_and_export_keys(password)
print(armored_priv)
print(armored_pub)