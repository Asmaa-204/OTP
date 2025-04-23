class LCG:
    def __init__(self, seed, a = 16807, c = 1013904223, m = 2**31 - 1):
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
