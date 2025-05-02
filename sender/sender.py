from modules.keyExchange import KeyExchange
from modules.HMAC import HMAC
from modules.streamCipher import StreamCipher
from modules.seedEncryption import SeedEncryptor
from modules.socketSender import SocketSender
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
    print(f"Random seed: {seed}\n")

    # 3. Perform key exchange (Diffie-Hellman)
    key_exchange = KeyExchange()
    private_key, public_key = key_exchange.generate_key_pair()
    public_numbers = public_key.public_numbers()

    print("Sender Public Key Components:")
    print(f"Prime modulus (p): {hex(public_numbers.parameter_numbers.p)}\n")
    print(f"Generator (g): {hex(public_numbers.parameter_numbers.g)}\n")
    print(f"Sender public key: {hex(public_numbers.y)}\n")

    try:
        with SocketSender() as secure_socket:
            # 5. Send our public key
            secure_socket.send_public_key(public_key)

            # 6. Receive receiver's public key
            receiver_public_key = secure_socket.receive_public_key()
            receiver_numbers = receiver_public_key.public_numbers()

            # 7. Derive shared secret
            shared_key = key_exchange.get_secret_key(private_key, receiver_public_key)

            # 8. Encrypt seed
            seed_encryptor = SeedEncryptor(shared_key[:32])
            encrypted_seed = seed_encryptor.encrypt(seed)
            print(f"Encrypted seed: {encrypted_seed}\n")
            print(f"Encrypted seed length: {len(encrypted_seed)} bytes\n")

            # 9. Generate HMAC
            authenticator = HMAC(shared_key[32:])
            hmac_value = authenticator.generate_hmac(encrypted_seed)

            # 10. Send encrypted seed and HMAC
            secure_socket.send_seed_data(encrypted_seed, hmac_value)

            # 11. Encrypt plaintext
            cipher = StreamCipher(seed)
            ciphertext = cipher.encrypt(plaintext)
            print(f"Cipher text: {ciphertext} of length {len(ciphertext)} bytes\n")

            # 12. Send ciphertext in chunks of 10 bytes
            chunk_size = 10
            for i in range(0, len(ciphertext), chunk_size):
                chunk = ciphertext[i : i + chunk_size]
                secure_socket.send_ciphertext_chunk(chunk)
                print(
                    f"Sent chunk {i//chunk_size + 1}/{(len(ciphertext)-1)//chunk_size + 1}"
                )

            # 13. Send end-of-transmission marker
            secure_socket.send_eot()
            print("All chunks sent")

    except Exception as e:
        print(f"Error during communication: {e}")
        raise