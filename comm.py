import socket
import json


class Communicator:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.connection = None

    def connect(self):
        """Connect as client"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.connect((self.host, self.port))
        except ConnectionRefusedError:
            print(
                f"Connection refused - is the server running on {self.host}:{self.port}?"
            )
            raise

    def listen(self):
        """Listen as server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        print(f"Listening on {self.host}:{self.port}...")
        self.connection, addr = self.socket.accept()
        print("Got connection from", addr)

    def send(self, data):
        """Send data as JSON"""
        if self.socket is None:
            raise RuntimeError("Not connected - call connect() or listen() first")

        target = self.connection if self.connection else self.socket
        target.sendall(json.dumps(data).encode())

    def receive(self):
        """Receive JSON data"""
        if self.socket is None:
            raise RuntimeError("Not connected - call connect() or listen() first")

        target = self.connection if self.connection else self.socket
        data = target.recv(1024)
        return json.loads(data.decode())

    def close(self):
        """Close the connection"""
        if self.connection:
            self.connection.close()
        if self.socket:
            self.socket.close()
        self.connection = None
        self.socket = None
