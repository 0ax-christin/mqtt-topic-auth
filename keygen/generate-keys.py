from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os

def generate_ED25519_keypair():
    if os.path.exists('private_key.txt'):
        with open('private_key.txt', 'rb') as reader:
            private_bytes = reader.read()
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    else:    
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open('private_key.txt', 'wb') as writer:
            writer.write(private_bytes)
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        with open('public_key.txt', 'wb') as writer:
            writer.write(public_bytes)
    return (private_key, private_key.public_key())

def main():
    private_key, public_key = generate_ED25519_keypair()

if __name__ == "__main__":
    main()
