import socket
import json
from cryptography.hazmat.primitives import serialization

class SocketReceiver:
    def __init__(self, host="localhost", port=12346):
        self.host = host
        self.port = port
        self.socket = None
        self.connection = None
        self.conn_file = None

    def start_server(self):
        """Initialize and start the socket server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        print("Waiting for connection...")
        self.connection, addr = self.socket.accept()
        print(f"Connected by {addr}")
        self.conn_file = self.connection.makefile()
        return self.connection

    def receive_public_key(self):
        """Receive sender's public key"""
        sender_data = json.loads(self.conn_file.readline())
        return serialization.load_pem_public_key(
            sender_data["public_key"].encode()
        )

    def send_public_key(self, public_key):
        """Send receiver's public key"""
        self.connection.sendall(
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

    def receive_seed_data(self):
        """Receive encrypted seed and HMAC"""
        seed_data = json.loads(self.conn_file.readline())
        return (
            bytes.fromhex(seed_data["encrypted_seed"]),
            bytes.fromhex(seed_data["hmac"])
        )

    def receive_chunks(self):
        """Generator to receive ciphertext chunks"""
        while True:
            line = self.conn_file.readline()
            if not line:
                break

            chunk_data = json.loads(line)
            if "status" in chunk_data and chunk_data["status"] == "EOT":
                break

            if "ciphertext_chunk" in chunk_data:
                yield bytes.fromhex(chunk_data["ciphertext_chunk"])

    def close(self):
        """Close all connections"""
        if self.conn_file:
            self.conn_file.close()
        if self.connection:
            self.connection.close()
        if self.socket:
            self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()