from modules.LCG import LCG

class StreamCipher:
    def __init__(self, seed):
        self.lcg = LCG(seed)
    
    def encrypt(self, plaintext):
        """
        encrypt the plain text with OTP generated from LCG
        """
        print(f"INSIDE STREAM CIPHER: {plaintext}\n")
        keystream = self.lcg.generate(len(plaintext))
        ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
        print(f"INSIDE STREAM CIPHER: {(ciphertext)}\n")
        return ciphertext
    
    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)
