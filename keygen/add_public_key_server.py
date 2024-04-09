from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from os.path import exists
from pathlib import Path

HOST = "127.0.0.1"
PORT = 63010

base_path = Path(__file__).parent


def main():
    with socket(AF_INET, SOCK_STREAM) as s:
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            public_bytes = conn.recv(1024)
            print(len(public_bytes))
            if exists((base_path / "../authorized_keys").resolve()):
                with open((base_path / "../authorized_keys").resolve(), "rb") as reader:
                    while current_public_bytes := reader.read(32):
                        if current_public_bytes == public_bytes:
                            conn.sendall(
                                b"Public key already exists in authorized_keys"
                            )
                            conn.close()
                            exit()
            with open((base_path / "../authorized_keys").resolve(), "ab") as writer:
                writer.write(public_bytes)
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
            conn.sendall(b"Success")


if __name__ == "__main__":
    main()
