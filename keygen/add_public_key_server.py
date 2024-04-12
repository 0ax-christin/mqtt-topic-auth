from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from os.path import exists
from pathlib import Path

HOST = "127.0.0.1"
PORT = 63010

base_path = Path(__file__).parent


def main():
    """
    This is the server part of a program for testing purposes which listens on port 63010 for a client to send a ED25519 public
    key in bytes. The server takes the public bytes and first checks if it already exists in the file 'authorized_keys'
    by reading 32 bytes and comparing to the received bytes. If it does, the server sends to the client a message
    that the public key already exists and exits. If it doesnt exist, the bytes are written onto the 'authorized_keys' file.

    This 'authorized_keys' file serves as a store of all the valid and authorized public keys of clients which are able
    to register with the server. This program is meant for testing purposes to easily add a clients public key to the servers
    authorized list. It is not secure as it does not have any integrity checking mechanisms that prevent an attacker from
    manipulating the payload.

    """
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
