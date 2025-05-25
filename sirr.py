import base64
import os
import getpass
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

Title = r"""
 _____   _                         
/  ___| (_)                        
\ `--.   _ _ __ _ __   _ __  _   _ 
 `--. \ | | '__| '__| | '_ \| | | |
/\__/ / | | |  | |    | |_) | |_| |
\____/  |_|_|  |_|    | .__/ \__, |
                      | |     __/ |
                      |_|    |___/ 
"""
subtitle = "a python implementation of Sirr.app"

public_path = "./Public_keys"
private_path = "./Private_keys"

print("\nWelcome to :")
print(Title)
print(subtitle + "\n")


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


def generate_and_export_keys(password: str = ""):

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

def encrypt_with_ecdh(message: str, armored_pub_key: str) -> str:
    peer_key_bytes = extract_key_from_armor(armored_pub_key)
    peer_public_key = serialization.load_der_public_key(peer_key_bytes, backend=default_backend())

    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), peer_public_key)

    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    digest = hashlib.sha256()
    digest.update(shared_secret)
    digest.update(ephemeral_pub_bytes)
    aes_key = digest.digest()[:16]

    # Encrypt
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(message.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag

    payload = (
        bytes([len(ephemeral_pub_bytes)]) +
        ephemeral_pub_bytes +
        iv +
        ciphertext +
        tag
    )
    return base64.b64encode(payload).decode("utf-8")

def extract_key_from_armor(armored: str) -> bytes:
    lines = armored.strip().splitlines()
    b64 = "".join(line for line in lines if not line.startswith("-----") and not line.startswith("Version:"))
    return base64.b64decode(b64)


def ask_password():
    while True:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm your password: ")
        
        if password == confirm:
            print("Password confirmed.\n")
            return password  # You can return or use it as needed
        else:
            print("Passwords do not match. Please try again.\n")

def select_file_from_folder(folder_path):
    files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
    
    if not files:
        print("No files found in the folder.")
        return None

    print("Select a file:")
    for i, filename in enumerate(files):
        print(f"{i + 1}. {filename}")
    
    while True:
        try:
            choice = int(input("Enter the number of the file: "))
            if 1 <= choice <= len(files):
                selected_file = files[choice - 1]
                print(f"You selected: {selected_file}")
                return os.path.join(folder_path, selected_file)
            else:
                print("Invalid number. Try again.")
        except ValueError:
            print("Please enter a valid number.")

def save_key_to_file(key_data: str, folder_path: str, filename: str):
    os.makedirs(folder_path, exist_ok=True)
    full_path = os.path.join(folder_path, filename)
    with open(full_path, "w") as f:
        f.write(key_data)
    print(f"Key saved to: {full_path}")

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


def main():
    print("Please choose an option:")
    print("1. Generate Keys")
    print("2. Encrypt Message")
    print("3. Decrypt Message")
    
    choice = input("Enter the number of your choice: ")

    if choice == "1":
        print("\n")
        # call your generate_keys() function here

        print("Please enter a password, leave blank to use your private key without password,\n for security reason your password won't be displayed here.\n")

        password = ask_password()

        armored_priv, armored_pub = generate_and_export_keys(password)

        print("Your public key is : \n")
        print(armored_pub + "\n")
        print("Your private key is : \n")
        print(armored_priv + "\n")
        print("DO NOT SHARE YOUR PRIVATE KEY \n")

            # Ask user if they want to save
        save = input("Would you like to save your keys to disk? (y/n): ").strip().lower()
        if save == 'y':
            pub_filename = input("Enter a filename for your public key (e.g. my_key.pub.asc): ").strip()
            priv_filename = input("Enter a filename for your private key (e.g. my_key.priv.asc): ").strip()


            save_key_to_file(armored_pub, public_path, pub_filename)
            save_key_to_file(armored_priv, private_path, priv_filename)
        else:
            print("Keys were not saved.")


    elif choice == "2":
        print("\n")
        selected = select_file_from_folder(public_path)

        if not selected:
            print("No public key selected. Aborting.")
        else:
        # Read public key from file
            with open(selected, "r") as f:
                public_key_data = f.read()

        clear_message = input(f"Enter your message for :  {selected}\n\n")

        message_encrypted = encrypt_with_ecdh(clear_message, public_key_data)
        print("\n Your encrypted message is :\n\n")
        print(message_encrypted + "\n")
        print("Select and use right clic to copy\n")


    elif choice == "3":
        print("\n")
        print("Select your private key to decrypt")
        selected = select_file_from_folder(private_path)

        if not selected:
            print("No private key selected. Aborting.")
        else:
            with open(selected, "r") as f:
                pivate_key_data = f.read()


        print("Password, leave blank if no password")
        password = ask_password()
        encrypted_message = input("\nEnter the encrypted massage :\n\n")
        decrypted_message = decrypt_with_ephemeral_ecdh(encrypted_message, pivate_key_data, password)
        print(f"\nMessage : \n\n{decrypted_message}\n\n")

    else:
        print("Invalid choice. Please try again.\n")

if __name__ == "__main__":
    while True:
        main()