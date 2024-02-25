from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os

from pathlib import Path

# Base path of the project directory
base_path = Path(__file__).parent

def generate_ED25519_keypair(isBytes: bool = False):
    if os.path.exists((base_path / '../keys/client/private_key.txt').resolve()):
        with open((base_path / '../keys/client/private_key.txt').resolve(), 'rb') as reader:
            private_bytes = reader.read()
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:    
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open((base_path /'../keys/client/private_key.txt').resolve(), 'wb') as writer:
            writer.write(private_bytes)
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        with open((base_path / '../keys/client/public_key.txt').resolve(), 'wb') as writer:
            writer.write(public_bytes)
    if isBytes:
        return (private_bytes, public_bytes)
    else:
        return (private_key, private_key.public_key())

def main():
    private_key, public_key = generate_ED25519_keypair()

if __name__ == "__main__":
    main()
