import base64
import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def extract_key_from_armor(armored: str) -> bytes:
    lines = armored.strip().splitlines()
    b64 = "".join(line for line in lines if not line.startswith("-----") and not line.startswith("Version:"))
    return base64.b64decode(b64)


def encrypt_with_ecdh(message: str, armored_pub_key: str) -> str:
    peer_key_bytes = extract_key_from_armor(armored_pub_key)

    # Load recipient's public key
    peer_public_key = serialization.load_der_public_key(peer_key_bytes, backend=default_backend())

    # Generate ephemeral EC key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Compute shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), peer_public_key)

    # Serialize ephemeral public key (X.509 format)
    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Derive AES-128 key using SHA-256(shared_secret + pub)
    digest = hashlib.sha256()
    digest.update(shared_secret)
    digest.update(ephemeral_pub_bytes)
    aes_key = digest.digest()[:16]

    # Encrypt message using AES-GCM
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(message.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag

    # Build payload: 1-byte length + ephemeral pubkey + iv + ciphertext + tag
    payload = (
        bytes([len(ephemeral_pub_bytes)]) +
        ephemeral_pub_bytes +
        iv +
        ciphertext +
        tag
    )

    return base64.b64encode(payload).decode("utf-8")


# Use the same format as your Kotlin app
public_key_armored = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk5Dxrk/jaXQkqvBsV2/PpzL8za9H
5gUFmICZtJeR5gIKx1A5RUF6AhO7h9SXiGGgrUc+aU8Ktz6CfDY3LLFnxA==
-----END PUBLIC KEY-----
"""

message = "Hello, Rémi, I'm writting you from python script can you decode that ? "
encrypted = encrypt_with_ecdh(message, public_key_armored)
print("Encrypted Base64:", encrypted)


