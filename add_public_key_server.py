import socket
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import os

HOST = "127.0.0.1"
PORT = 63010

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))        
        s.listen()
        conn, addr = s.accept()
        with conn:
            public_bytes = conn.recv(1024)
            print(len(public_bytes))
            if os.path.exists("authorized_keys"):
                with open("authorized_keys", 'rb') as reader:
                    while (current_public_bytes := reader.read(32)):
                        if current_public_bytes == public_bytes:
                            conn.sendall(b"Public key already exists in authorized_keys")
                            conn.close()
                            exit()
            with open("authorized_keys", "ab") as writer:
                writer.write(public_bytes)
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
            conn.sendall(b'Success')
if __name__ == "__main__":
    main()