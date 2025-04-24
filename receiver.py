from keyExchange import KeyExchange
from comm import Communicator
from HMAC import HMAC
from streamCipher import StreamCipher
from seedEncryption import SeedEncryptor
from cryptography.hazmat.primitives import serialization

import os

def receiver_process():
    # 1. Perform key exchange (Diffie-Hellman)
    key_exchange = KeyExchange()
    private_key, public_key = key_exchange.generate_key_pair()
    print(f"receiver public key = {public_key}\n")

    # 2. Wait for sender's public key
    communicator = Communicator("localhost", 12346)
    communicator.listen()
    
    sender_public_key = serialization.load_pem_public_key(
        communicator.receive()["public_key"].encode()
    )
    print(f"sender public key = {sender_public_key}\n")

    # 3. Send our public key to sender
    communicator.send(
        {
            "public_key": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        }
    )

    # 4. Derive shared secret
    shared_key = key_exchange.derive_shared_key(private_key, sender_public_key)
    print(f"shared key: {shared_key}\n")

    # 5. Receive encrypted seed and HMAC
    seed_data = communicator.receive()
    encrypted_seed = bytes.fromhex(seed_data["encrypted_seed"])
    received_hmac = bytes.fromhex(seed_data["hmac"])

    # 6. Verify HMAC
    authenticator = HMAC(shared_key[32:])
    if not authenticator.verify_hmac(encrypted_seed, received_hmac):
        raise ValueError("HMAC verification failed!")

    # 7. Decrypt seed
    seed_encryptor = SeedEncryptor(shared_key[:32])
    seed = seed_encryptor.decrypt(encrypted_seed)

    # 8. Initialize stream cipher
    cipher = StreamCipher(seed)

    # 9. Receive and decrypt ciphertext chunks
    decrypted_text = bytearray()
    while True:
        print(f"decrypting message....\n")
        chunk_data = communicator.receive()
        if "ciphertext_chunk" not in chunk_data:
            break
        ciphertext_chunk = bytes.fromhex(chunk_data["ciphertext_chunk"])
        decrypted_chunk = cipher.decrypt(ciphertext_chunk)
        decrypted_text.extend(decrypted_chunk)

    # 10. Write decrypted text to file
    with open("decrypted.txt", "wb") as f:
        f.write(decrypted_text)
