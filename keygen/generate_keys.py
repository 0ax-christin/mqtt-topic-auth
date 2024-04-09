from os.path import exists
from os import getenv
from hvac import Client
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


# Base path of the project directory
base_path = Path(__file__).parent


def generate_ED25519_keypair_server_bytes(pickled_server_static):
    client = Client(url=getenv("VAULT_HOST"), token=getenv("VAULT_TOKEN"))
    response = client.secrets.kv.read_secret_version("server")
    server_identity = response["data"]["data"]["identity_keypair"]
    if server_identity == "":
        print("Server identity keypair not present, generating...")
        private_key = Ed25519PrivateKey.generate()
        server_identity_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print("Pickled Server static: ", pickled_server_static)
        print("Identity keypair hex:", server_identity_bytes.hex())
        client.secrets.kv.v2.create_or_update_secret(
            path="server",
            secret=dict(
                noise_static_keypair=pickled_server_static,
                identity_keypair=server_identity_bytes.hex(),
            ),
        )
    else:
        print("Server identity has a value in the Vault, loading this..")
        hexed_server_identity = client.secrets.kv.read_secret_version(path="server")[
            "data"
        ]["data"]["identity_keypair"]
        print("Hexed server identity", hexed_server_identity)
        private_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(hexed_server_identity)
        )

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return (private_bytes, public_bytes)


def generate_ED25519_keypair_client_bytes():
    if exists((base_path / "../keys/client/private_key.txt").resolve()):
        with open(
            (base_path / "../keys/client/private_key.txt").resolve(), "rb"
        ) as reader:
            private_bytes = reader.read()
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    else:
        private_key = Ed25519PrivateKey.generate()
        with open(
            (base_path / "../keys/client/private_key.txt").resolve(), "wb"
        ) as writer:
            writer.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(
            (base_path / "../keys/client/public_key.txt").resolve(), "wb"
        ) as writer:
            writer.write(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return (private_bytes, public_bytes)


def main():
    private_key, public_key = generate_ED25519_keypair()


if __name__ == "__main__":
    main()
