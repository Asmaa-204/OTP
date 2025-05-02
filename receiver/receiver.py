from modules.keyExchange import KeyExchange
from modules.HMAC import HMAC
from modules.streamCipher import StreamCipher
from modules.seedEncryption import SeedEncryptor
from modules.socketReceiver import SocketReceiver

import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
decrypted_path = os.path.join(project_root, "decrypted.txt")

def receiver_process():
    # 1. Generate keys
    key_exchange = KeyExchange()
    private_key, public_key = key_exchange.generate_key_pair()
    public_numbers = public_key.public_numbers()

    print("Receiver Public Key Components:")
    # 2. Convert the prime p to bytes and get its length
    p_bytes = public_numbers.parameter_numbers.p.to_bytes((public_numbers.parameter_numbers.p.bit_length() + 7) // 8, 'big')
    print(f"Prime modulus (p): {hex(public_numbers.parameter_numbers.p)}\n")
    print(f"Length of prime modulus (p): {len(p_bytes)} bytes\n")
    print(f"Generator (g): {hex(public_numbers.parameter_numbers.g)}\n")
    print(f"Receiver public key: {hex(public_numbers.y)}\n")

    try:
        with SocketReceiver() as secure_socket:
            secure_socket.start_server()

            # 3. Exchange public keys
            sender_public_key = secure_socket.receive_public_key()
            secure_socket.send_public_key(public_key)

            # 4. Derive shared secret
            shared_key = key_exchange.get_secret_key(private_key, sender_public_key)

            # 5. Receive and verify seed
            encrypted_seed, received_hmac = secure_socket.receive_seed_data()
            authenticator = HMAC(shared_key[32:])
            if not authenticator.verify_hmac(encrypted_seed, received_hmac):
                raise ValueError("HMAC verification failed!")

            # 6. Decrypt seed and initialize cipher
            seed_encryptor = SeedEncryptor(shared_key[:32])
            seed = seed_encryptor.decrypt(encrypted_seed)
            print(f"Decrypted seed: {seed}\n")
            cipher = StreamCipher(seed)

            # 7. Receive and decrypt chunks
            decrypted_text = bytearray()
            for ciphertext_chunk in secure_socket.receive_chunks():
                decrypted_chunk = cipher.decrypt(ciphertext_chunk)
                decrypted_text.extend(decrypted_chunk)
                print(f"Received chunk, decrypted {len(decrypted_chunk)} bytes")

            # 8. Save to file
            with open(decrypted_path, "wb") as f:
                f.write(decrypted_text)
            print("Decryption complete. Saved to decrypted.txt")

    except Exception as e:
        print(f"Error during communication: {e}")
        raise