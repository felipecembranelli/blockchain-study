from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from cryptography.exceptions import InvalidSignature

# references
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

def generate_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    
    printPrivateKey(private_key)

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    print(pem)

    return private_key, public_key

def sign(message, private_key):

    signature = private_key.sign(
        message,
        padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),hashes.SHA256())

    return signature

def verify(message, signature, public_key):

    try:
        verification = public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True
    except InvalidSignature:
        return False    


def printPrivateKey(private_key):
    private_key_str = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()).decode()

    print(private_key_str)

if __name__ == '__main__':
    pr,pu = generate_keys()
    pr1,pu1 = generate_keys()

    message = b"this is a secrete message"
    sig = sign(message, pr)
    correct = verify(message, sig, pu)
    
    if correct:
        print("Success! good sig")
    else:
        print("ERROR! sig is bad")

    correct = verify(message, sig, pu1)

    if correct:
        print("Success! good sig")
    else:
        print("ERROR! sig is bad")
    