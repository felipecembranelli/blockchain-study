from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class someClass:
    string = None

    def __init__(self, mystring):
        self.string = mystring
    def __repr__(self):
        return self.string

class CBlock:
    data = None
    previousHash = None
    previousBlock = None
    test = "xxxx"

    def __init__(self, data, previousBlock):
        self.previousBlock = previousBlock

        if previousBlock != None:
            self.previousHash = previousBlock.computeHash()

        self.data = bytes(str(data),'utf-8')

    def computeHash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.data)
        digest.update(bytes(str(self.previousHash),'utf-8'))
        hash = digest.finalize()

        print(hash)

        return hash


if __name__ == '__main__':

    root = CBlock('I am root', None)
    B1 = CBlock('I am a child', root)
    B2 = CBlock('I am a child too', root)
    B3 = CBlock(12312, B1)
    B4 = CBlock(someClass('Hi there'), B2)
    B5 = CBlock('I am the top', B4)

    for b in [B1,B2,B3,B4,B5]:
        if b.previousBlock.computeHash() == b.previousHash:
            print ("Success! hash is good.")
        else:
            print ("Error! Hash is not good.")




