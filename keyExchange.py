from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyExchange:
    def __init__(self):
        p = int(
            "FCA682CE8E12CABA26EFCCF7110E526DB078B05EDEED3AD6"
            "218DA3CBAA72C0F8E2D0D29010C191F2579847DE51F6B6F7"
            "C6C7E15D69820B5C82E116E3D3B6F5D30A74E83F7DDF6E56"
            "2E0C2A973DF7C6B403642A9495C917DF090EB8228D64AB96"
            "EA8F1A0F4A68E3C7B7A0C7C3F83BA3E725A92F9F5DC52C52"
            "A9B06D96EA0D03C17A8EAF0AA32D23D8B",
            16,
        )
        g = 2

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
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"secure-session"
        ).derive(shared_key)
        return derived_key
