"""Module containing the code to generate ED25519 identity keypairs on server and client and store in respective backends

The server uses Hashicorp vault as its backend for storing its identity keypair and Noise static keypair.
The client uses a simple file for storing both keypairs in a directory.
These are utility functions used to generate keypairs if they dont exist, or else read the existing long term values
and return them in the form of bytes.
This identity keypair is a ED25519 keypair that is used by the client and server to verify each other outside the Noise protocol
"""

from os import getenv
from os.path import exists
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dotenv import load_dotenv
from hvac import Client

load_dotenv()


# Base path of the project directory
base_path = Path(__file__).parent


def generate_ED25519_keypair_server_bytes(
    pickled_server_static: str,
) -> tuple[bytes, bytes]:
    """Generate ED25519 keypair and store to Hashicorp Vault if it does not exist, else read from Vault

    The function will use the loaded environment variables VAULT_HOST and VAULT_TOKEN for authorization to access and write to
    Hashicorp Vault. Vault's key value store is being used as a database by the server for storing established symmetric keys
    and public keys relating to clients. Along with their own identity keypair and noise static keypair.

    First, a check is done to see if the server has an existing long term identity keypair. If it does not, the server
    generates it, converts to bytes and then to a hexstring, which is then finally stored in the server path of Vault.
    If a identity keypair exists, the server reads it from the Vault and returns the public and private key values in bytes
    Parameters
    ----------
    pickled_server_static:str
      This is the noise static keypair that has been serialized for storage in the Vault. It is passed so that it can be
      written into the new version of the server paths secret key along with the identity keypair.
      Due to the versioned nature of the key value store in Vault, if only the identity keypair is passed to server path,
      and server static keypair value already exists, it does not update, instead it overwrites this value as the new version.
    Returns
    -------
    public_bytes:bytes
      Returns the public key in bytes form of the identity keypair.
    private_bytes:bytes
      Returns the private key in bytes form of the identity keypair.
    """
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


def generate_ED25519_keypair_client_bytes() -> tuple[bytes, bytes]:
    """Generate ED25519 keypair and store in a file if it does not exist, else read from existing file

    Based on whether a file exists, primarily, the private key file, the function will decide whether to read from existing
    file the private key value, or generate a new keypair to write. At the end, both the public and private key in bytes is
    returned.
    Returns
    -------
    public_bytes:bytes
      Returns the public key in bytes form of the identity keypair.
    private_bytes:bytes
      Returns the private key in bytes form of the identity keypair.
    """
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
