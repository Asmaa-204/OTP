from cryptography.hazmat.primitives import hashes, hmac

class HMAC:
    def __init__(self, key):
        self.key = key
        print(f"INSIDE HMAC: {key} of length {len(key)} bytes\n") 

    def generate_hmac(self, message):
        """
        generate the HMAC for a given message
        """
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(message)
        return h.finalize()
    
    def verify_hmac(self, message, received_hmac):
        """
        verify the HMAC of a received message
        """
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(message)
        try:
            h.verify(received_hmac)
            return True
        except:
            return False