from config.constants import LCG_A, LCG_C, LCG_M

class LCG:
    def __init__(self, seed, a = LCG_A, c = LCG_C, m = LCG_M):
        self.seed = seed
        self.a = a
        self.c = c
        self.m = m
    
    def generate(self, length):
        """
        generate keystream with specific length
        """
        keystream = []
        for _ in range(length):
            self.seed = (self.a * self.seed + self.c) % self.m
            keystream.append(self.seed % 256)
        return bytes(keystream)
