from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class SomeClass:
    string = None
    num = 98254673
    
    def __init__(self, string):
        self.string = string
        
    def __repr__(self):
        return self.string + '-' + str(self.num)

class CBlock:
    data = None
    previousHash = None
    previousBlock = None
    
    def __init__(self, data, previousBlock):
        self.data = data
        self.previousBlock = previousBlock
        if previousBlock != None:
            self.previousHash = previousBlock.computeHash()
    
    def computeHash(self):
        data_to_hash = bytes(str(self.data), 'utf-8')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data_to_hash)
        if self.previousBlock != None:
            digest.update(self.previousHash)
        return digest.finalize()

if __name__ == '__main__':
    root = CBlock('I am root', None)
    B1 = CBlock('I am a child', root)
    B2 = CBlock('I am B1s brother', root)
    B3 = CBlock(12345, B1)
    B4 = CBlock(SomeClass('Hi there!'), B3)
    B5 = CBlock('Top block', B4)
    
    for b in [B1, B2, B3, B4, B5]:
        if b.previousBlock.computeHash() == b.previousHash:
            print('Success! Hash is good.')
        else:
            print('Fail! Hash is not good.')
    
    # Testing tampering
    B3.data = 19287359
    if B4.previousBlock.computeHash() == B4.previousHash:
        print('Couldnt detect tampering!.')
    else:
        print('Tampering detected!.')
        
    # Testing tampering for data in class
    print(B4.data)
    B4.data.num = 1
    print(B4.data)
    if B5.previousBlock.computeHash() == B5.previousHash:
        print('Couldnt detect tampering!.')
    else:
        print('Tampering detected!.')
    