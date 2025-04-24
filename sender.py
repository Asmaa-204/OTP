from keyExchange import KeyExchange
from comm import Communicator
from HMAC import HMAC
from streamCipher import StreamCipher
from seedEncryption import SeedEncryptor
from cryptography.hazmat.primitives import serialization

import os


def sender_process():
    # 1. Read plaintext from file
    with open("plaintext.txt", "rb") as f:
        plaintext = f.read()
        print(f"msg to send: {plaintext}\n")

    # 2. Generate random seed
    seed = int.from_bytes(os.urandom(16), "big")

    # 3. Perform key exchange (Diffie-Hellman)
    key_exchange = KeyExchange()
    private_key, public_key = key_exchange.generate_key_pair()
    print(f"sender public key = {public_key}\n")

    # 4. Send public key to receiver
    communicator = Communicator("localhost", 12346)
    communicator.connect()
    
    communicator.send(
        {
            "public_key": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        }
    )

    # 5. Receive receiver's public key
    receiver_public_key = serialization.load_pem_public_key(
        communicator.receive()["public_key"].encode()
    )
    print(f"receiver public key = {receiver_public_key}")

    # 6. Derive shared secret
    shared_key = key_exchange.derive_shared_key(private_key, receiver_public_key)
    print(f"shared key: {shared_key}\n")

    # 7. Encrypt seed
    seed_encryptor = SeedEncryptor(shared_key[:32])  # Use first 32 bytes for AES-256
    encrypted_seed = seed_encryptor.encrypt(seed)

    # 8. Generate HMAC
    authenticator = HMAC(shared_key[32:])  # Use remaining bytes for HMAC
    hmac_value = authenticator.generate_hmac(encrypted_seed)

    # 9. Send encrypted seed and HMAC
    communicator.send(
        {"encrypted_seed": encrypted_seed.hex(), "hmac": hmac_value.hex()}
    )

    # 10. Encrypt plaintext
    cipher = StreamCipher(seed)
    ciphertext = cipher.encrypt(plaintext)
    print(f"cipher text: {ciphertext}\n")

    # 11. Send ciphertext in chunks of 10 characters
    for i in range(0, len(ciphertext), 10):
        print(f"sending message...\n")
        chunk = ciphertext[i : i + 10]
        communicator.send({"ciphertext_chunk": chunk.hex()})
