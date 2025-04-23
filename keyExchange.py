from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class KeyExchange:
    def __init__(self, key_size = 2048):
        self.params = dh.generate_parameters(generator=2, key_size=key_size)

    def generate_key_pair(self):
        """
        generate public/private key pair
        """
        private_key = self.params.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def get_secret_key(self, private_key, peer_public_key):
        """
        return shared secret key
        """
        return private_key.exchange(peer_public_key)