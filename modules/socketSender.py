import socket
import json
from cryptography.hazmat.primitives import serialization

class SocketSender:
    def __init__(self, host="localhost", port=12346):
        self.host = host
        self.port = port
        self.socket = None
        self.conn_file = None

    def connect(self):
        """Establish connection to the receiver"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.conn_file = self.socket.makefile()
        print("Connected to receiver")

    def send_public_key(self, public_key):
        """Send sender's public key"""
        self.socket.sendall(
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

    def receive_public_key(self):
        """Receive receiver's public key"""
        data = json.loads(self.conn_file.readline())
        return serialization.load_pem_public_key(
            data["public_key"].encode()
        )

    def send_seed_data(self, encrypted_seed, hmac_value):
        """Send encrypted seed and HMAC"""
        self.socket.sendall(
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

    def send_ciphertext_chunk(self, chunk):
        """Send a chunk of ciphertext"""
        self.socket.sendall(
            (json.dumps({"ciphertext_chunk": chunk.hex()}) + "\n").encode()
        )

    def send_eot(self):
        """Send end-of-transmission marker"""
        self.socket.sendall((json.dumps({"status": "EOT"}) + "\n").encode())

    def close(self):
        """Close all connections"""
        if self.conn_file:
            self.conn_file.close()
        if self.socket:
            self.socket.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()