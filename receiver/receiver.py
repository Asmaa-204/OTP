from modules.keyExchange import KeyExchange
from modules.HMAC import HMAC
from modules.streamCipher import StreamCipher
from modules.seedEncryption import SeedEncryptor

from cryptography.hazmat.primitives import serialization
import socket
import json

import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ciphertext_path = os.path.join(project_root, "ciphertext.txt")

def receiver_process():
    key_exchange = KeyExchange()
    private_key, public_key = key_exchange.generate_key_pair()
    public_numbers = public_key.public_numbers()
    print("Receiver Public Key Components:")
    print(f"Prime modulus (p): {hex(public_numbers.parameter_numbers.p)}")
    print(f"Generator (g): {hex(public_numbers.parameter_numbers.g)}")
    print(f"Public value (y): {hex(public_numbers.y)}\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("localhost", 12346))
        s.listen()
        print("Waiting for connection...")
        conn, addr = s.accept()
        print(f"Connected by {addr}")

        try:
            with conn:
                conn_file = conn.makefile()

                # 3. Receive sender's public key
                sender_data = json.loads(conn_file.readline())
                sender_public_key = serialization.load_pem_public_key(
                    sender_data["public_key"].encode()
                )
                print(f"Sender public key = {sender_public_key}")

                # 4. Send our public key
                conn.sendall(
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

                # 5. Derive shared secret
                shared_key = key_exchange.get_secret_key(private_key, sender_public_key)
                print(f"Shared key: {shared_key}\n")

                # 6. Receive encrypted seed and HMAC
                seed_data = json.loads(conn_file.readline())
                encrypted_seed = bytes.fromhex(seed_data["encrypted_seed"])
                received_hmac = bytes.fromhex(seed_data["hmac"])

                # 7. Verify HMAC
                authenticator = HMAC(shared_key[32:])
                if not authenticator.verify_hmac(encrypted_seed, received_hmac):
                    raise ValueError("HMAC verification failed!")

                # 8. Decrypt seed
                seed_encryptor = SeedEncryptor(shared_key[:32])
                seed = seed_encryptor.decrypt(encrypted_seed)

                # 9. Initialize stream cipher
                cipher = StreamCipher(seed)

                # 10. Receive and decrypt ciphertext chunks
                decrypted_text = bytearray()
                while True:
                    line = conn_file.readline()
                    if not line:
                        break

                    chunk_data = json.loads(line)
                    if "status" in chunk_data and chunk_data["status"] == "EOT":
                        break

                    ciphertext_chunk = bytes.fromhex(chunk_data["ciphertext_chunk"])
                    decrypted_chunk = cipher.decrypt(ciphertext_chunk)
                    decrypted_text.extend(decrypted_chunk)
                    print(f"Received chunk, decrypted {len(decrypted_chunk)} bytes")

                # 11. Save to file
                with open(ciphertext_path, "wb") as f:
                    f.write(decrypted_text)
                print("Decryption complete. Saved to decrypted.txt")

        except Exception as e:
            print(f"Error during communication: {e}")
            raise
