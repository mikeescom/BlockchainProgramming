from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def generate_keys():
    private = rsa.generate_private_key(
                                         public_exponent=65537,
                                         key_size=2048,
                                         backend=default_backend()
                                      )
    public = private.public_key()
    return private, public

def sign(message, private):
    sig = private.sign(message,
                       padding.PSS(
                                   mgf=padding.MGF1(hashes.SHA256()),
                                   salt_length=padding.PSS.MAX_LENGTH
                                   ),
                       hashes.SHA256())
    return sig

def verify(message, sig, public):
    try:
        public.verify(
                      sig,
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
    except:
        print("Error executing verification!")
        return False
    
if __name__ == '__main__':
    pr, pu = generate_keys()
    print('Private key: {}'.format(pr))
    print('Public key: {}'.format(pu))
    message = b"This is a secret message"
    sig = sign(message, pr)
    print('Signature: {}'.format(sig))
    correct = verify(message, sig, pu)
    print('CORRECT: '.format(correct))
    
    if correct:
        print('Success! Good signature')
    else:
        print('Fail! Bad signature')