from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from config.constants import DH_PRIME, DH_GENERATOR, KDF_LENGTH, KDF_SALT, KDF_INFO


class KeyExchange:
    def __init__(self):
        p = int(DH_PRIME, 16)
        g = DH_GENERATOR

        params_numbers = dh.DHParameterNumbers(p, g)
        self.params = params_numbers.parameters()

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
        public_numbers = peer_public_key.public_numbers()
        print(f"INSIDE KEY EXCHANGE (peer public key): {hex(public_numbers.y)}\n")
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=KDF_LENGTH, salt=KDF_SALT, info=KDF_INFO
        ).derive(shared_key)

        print(f"Shared key length: {len(shared_key)} bytes\n")
        print(f"Shared key: {shared_key}\n")
        return derived_key
