from socket import socket, AF_INET, SOCK_STREAM
from pathlib import Path

HOST = "127.0.0.1"
PORT = 63010

base_path = Path(__file__).parent


def main():
    with socket(AF_INET, SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        with open(
            (base_path / "../keys/client/public_key.txt").resolve(), "rb"
        ) as reader:
            public_bytes = reader.read()
        s.sendall(public_bytes)
        final_message = s.recv(1024)
        print(final_message)


if __name__ == "__main__":
    main()
