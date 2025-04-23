import LCG

class StreamCipher:
    def __init__(self, seed):
        self.lcg = LCG(seed)
    
    def encrypt(self, plaintext):
        """
        encrypt the plain text with OTP generated from LCG
        """
        keystream = self.lcg.generate(len(plaintext))
        ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
        return ciphertext
    
    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)