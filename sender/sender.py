from modules.keyExchange import KeyExchange
from modules.HMAC import HMAC
from modules.streamCipher import StreamCipher
from modules.seedEncryption import SeedEncryptor

from cryptography.hazmat.primitives import serialization
import socket
import json
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
plaintext_path = os.path.join(project_root, "plaintext.txt")

def sender_process():
    # 1. Read plaintext from file
    with open(plaintext_path, "rb") as f:
        plaintext = f.read()
        print(f"Message to send: {plaintext}\n")

    # 2. Generate random seed
    seed = int.from_bytes(os.urandom(16), "big")

    # 3. Perform key exchange (Diffie-Hellman)
    key_exchange = KeyExchange()
    private_key, public_key = key_exchange.generate_key_pair()
    public_numbers = public_key.public_numbers()
    print("Sender Public Key Components:")
    print(f"Prime modulus (p): {hex(public_numbers.parameter_numbers.p)}")
    print(f"Generator (g): {hex(public_numbers.parameter_numbers.g)}")
    print(f"Public value (y): {hex(public_numbers.y)}\n")

    # 4. Connect to receiver
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", 12346))
        print("Connected to receiver")

        try:
            # 5. Send our public key
            s.sendall(
                (
                    json.dumps(
                        {
                            "public_key": public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                            ).decode()
                        }
                    )
                    + "\n"
                ).encode()
            )

            # 6. Receive receiver's public key
            conn_file = s.makefile()
            data = json.loads(conn_file.readline())
            receiver_public_key = serialization.load_pem_public_key(
                data["public_key"].encode()
            )
            print(f"Receiver public key = {receiver_public_key}")

            # 7. Derive shared secret
            shared_key = key_exchange.get_secret_key(private_key, receiver_public_key)
            print(f"Shared key: {shared_key}\n")

            # 8. Encrypt seed
            seed_encryptor = SeedEncryptor(shared_key[:32])
            encrypted_seed = seed_encryptor.encrypt(seed)

            # 9. Generate HMAC
            authenticator = HMAC(shared_key[32:])
            hmac_value = authenticator.generate_hmac(encrypted_seed)

            # 10. Send encrypted seed and HMAC
            s.sendall(
                (
                    json.dumps(
                        {
                            "encrypted_seed": encrypted_seed.hex(),
                            "hmac": hmac_value.hex(),
                        }
                    )
                    + "\n"
                ).encode()
            )

            # 11. Encrypt plaintext
            cipher = StreamCipher(seed)
            ciphertext = cipher.encrypt(plaintext)
            print(f"Cipher text length: {len(ciphertext)} bytes\n")

            # 12. Send ciphertext in chunks of 10 bytes
            chunk_size = 10
            for i in range(0, len(ciphertext), chunk_size):
                chunk = ciphertext[i : i + chunk_size]
                s.sendall(
                    (json.dumps({"ciphertext_chunk": chunk.hex()}) + "\n").encode()
                )
                print(
                    f"Sent chunk {i//chunk_size + 1}/{(len(ciphertext)-1)//chunk_size + 1}"
                )

            # 13. Send end-of-transmission marker
            s.sendall((json.dumps({"status": "EOT"}) + "\n").encode())
            print("All chunks sent")

        except Exception as e:
            print(f"Error during communication: {e}")
            raise
