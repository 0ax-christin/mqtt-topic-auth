import hvac
import capnp
from socketserver import StreamRequestHandler, ForkingMixIn, TCPServer
from dissononce import logger
from logging import DEBUG
from os import getenv
from os.path import exists
from uuid import uuid4
from time import time
from pickle import dumps, loads
from secrets import token_bytes
from socket import SHUT_RDWR
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash

from keygen.generate_keys import generate_ED25519_keypair_server_bytes

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from schema_factory import (
    generate_request_bytes,
    generate_signed_ticket,
    generate_mqtt_topic,
    generate_mqtt_password,
    generate_mqtt_username,
    generate_signed_token,
    generate_status_reply_bytes,
)

from hvac.exceptions import InvalidPath
import mqtt.dynsec_mqtt as dyns

from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

capnp.remove_import_hook()
request_capnp = capnp.load("capnp_schemas/request.capnp")
ticket_capnp = capnp.load("capnp_schemas/ticket.capnp")

HOST = "127.0.0.1"
PORT = 63000


def public_key_exists(public_bytes):
    """
    Check that a given public key in byte string exists in authorized_keys
    """
    if exists("authorized_keys"):
        with open("authorized_keys", "rb") as reader:
            while current_public_bytes := reader.read(32):
                if current_public_bytes == public_bytes:
                    return True
                else:
                    return False


def setup_static_keypair():
    client = hvac.Client(url=getenv("VAULT_HOST"), token=getenv("VAULT_TOKEN"))
    try:
        response = client.secrets.kv.read_secret_version("server")
        server_static = response["data"]["data"]["noise_static_keypair"]
        if server_static == "":
            print(
                "Server static key was empty, generating keypair and adding to vault.."
            )
            server_static = X25519DH().generate_keypair()
            pickled_server_static = dumps(server_static).hex()
            client.secrets.kv.v2.create_or_update_secret(
                path="server",
                secret=dict(
                    noise_static_keypair=pickled_server_static, identity_keypair=""
                ),
            )
        else:
            print("Reading existing server static value from vault")
            pickled_server_static = client.secrets.kv.read_secret_version(
                path="server"
            )["data"]["data"]["noise_static_keypair"]
            server_static = loads(bytes.fromhex(pickled_server_static))
        return server_static
    except InvalidPath:
        # Creates the servers path with empty fields which will be updated
        client.secrets.kv.v2.create_or_update_secret(
            path="server", secret=dict(noise_static_keypair="", identity_keypair="")
        )


# Base path of the project directory
base_path = Path(__file__).parent

request = request_capnp.Request
ticket = ticket_capnp.Ticket
client = hvac.Client(url=getenv("VAULT_HOST"), token=getenv("VAULT_TOKEN"))

try:
    response = client.secrets.kv.read_secret_version("server")
except InvalidPath:
    # Creates the servers path with empty fields which will be updated
    client.secrets.kv.v2.create_or_update_secret(
        path="server", secret=dict(noise_static_keypair="", identity_keypair="")
    )

server_static = setup_static_keypair()
# Generate identity keypair outside noise handshake, which is stored in a file
private_bytes, public_bytes = generate_ED25519_keypair_server_bytes(
    pickled_server_static=dumps(server_static).hex()
)
# Temporary solution: Write update server public and private key file
# As whenever Vault restarts in dev mode, the database is fresh, so it generates a new keypair
# Must make sure client has the correct key pair in memory
print(public_bytes)
with open((base_path / "./keys/server/public_key.txt").resolve(), "wb") as writer:
    writer.write(public_bytes)

private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)


# Test out StreamRequestHandler, see if it works with CapnProto
class ForkedTCPRequestHandler(StreamRequestHandler):
    def handle(self):
        # 1. Server expects from the client a register request, with a challenge
        # This challenge is for the server to sign and authenticate itself
        # Rationale for readline()[:-1], to make it easy for readline to process sent bytes automatically,
        # All requests have '\n' appended at the end, this must be removed before processing
        client_challenge_req = request.from_bytes_packed(self.rfile.readline()[:-1])
        client_challenge = client_challenge_req.nonceChallenge
        signed_client_response = private_key.sign(client_challenge)
        # 2. Server sends challenge response
        signed_challenge_response = generate_request_bytes(
            requestType="response", nonce=signed_client_response, solution=True
        )
        self.wfile.write(signed_challenge_response)
        # if the server has been verified, the flow continues, else client shutdowns the socket
        # Check the result reply of the client to see whether statusCode is 200, for success, else shutdown this connection
        result_reply = request.from_bytes_packed(self.rfile.readline()[:-1])

        if result_reply.statusCode != 200:
            print("Exit time!")
            self.rfile.close()
            self.request.shutdown(SHUT_RDWR)
            self.request.close()
            exit()

        # First, a public key is expected from client
        client_public_bytes = self.rfile.readline()[:-1]
        print(client_public_bytes)
        if public_key_exists(public_bytes=client_public_bytes):
            print("Public key exists")
            client_public_key = Ed25519PublicKey.from_public_bytes(client_public_bytes)
            # If public key exists in authorized_keys, send random 32 bytes back as a challenge to sign
            random_bits = token_bytes(32)
            server_challenge = generate_request_bytes(
                requestType="challenge", nonce=random_bits
            )
            self.wfile.write(server_challenge)

            # Getting the signed response from the client
            signed_client_response = request.from_bytes_packed(
                self.rfile.readline()[:-1]
            )
            signed_random_bits = signed_client_response.nonceSolution

            try:
                verify_result = client_public_key.verify(
                    signed_random_bits, random_bits
                )
                # If no exception has been raised, means that signature was correctly verified
                if verify_result is None:
                    print("Success")
                    success_reply = generate_status_reply_bytes(statusCode=200)
                    self.wfile.write(success_reply)
            except InvalidSignature:
                print("Invalid sign")
                # 401 for unauthorized, authentication failed
                error_reply = generate_status_reply_bytes(statusCode=401)
                self.wfile.write(error_reply)
                self.wfile.close()
                exit()
        else:
            print("Sent public key not in authorized_keys!")
            unauthorized_key_reply = generate_status_reply_bytes(statusCode=403)
            self.wfile.write(unauthorized_key_reply)
            self.wfile.close()
            exit()

        server_handshakestate = HandshakeState(
            SymmetricState(CipherState(ChaChaPolyCipher()), Blake2sHash()), X25519DH()
        )

        server_handshakestate.initialize(
            XXHandshakePattern(), False, b"", s=server_static
        )

        # Receiving ephemeral public key from client
        message_buffer = self.rfile.readline()
        server_handshakestate.read_message(bytes(message_buffer[:-1]), bytearray())

        # For the server side message pattern
        # <- e, ee, s, es
        message_buffer = bytearray()
        server_handshakestate.write_message(b"", message_buffer)
        # Sending message buffer to client, this will have ephemeral public key of server
        # Server then performs DH to get shared secret, uses this to send static public key under encryption
        self.wfile.write(message_buffer)

        # -> s, se
        message_buffer = self.rfile.readline()[:-1]
        shared_cipherstates = server_handshakestate.read_message(
            bytes(message_buffer), bytearray()
        )
        client_cipherstate = shared_cipherstates[0]
        server_cipherstate = shared_cipherstates[1]

        # Every request after this is under encryption of the noise handshake

        # Load shared HMAC Keys if present, else send a newly generated 128 bit key to be used as HMAC
        # Initialize a secret path with the identifier of the clients public key, where the
        # pickled established cipherstates from a noise handshake and the generated HMAC key are stored
        # The assumption is that a registering client device has not registered previously and thus would
        # not have a path. This part of the code creates the path
        client.secrets.kv.v2.create_or_update_secret(
            path=client_public_bytes.hex(),
            secret=dict(established_cipherstates="", hmac_key=""),
        )
        pickled_shared_cipherstates = dumps(shared_cipherstates).hex()

        key = token_bytes(128)
        hmac_key_hexed = key.hex()

        # Populate the values of the secret path with the cipher states and hmac_key
        client.secrets.kv.v2.create_or_update_secret(
            path=client_public_bytes.hex(),
            secret=dict(
                established_cipherstates=pickled_shared_cipherstates,
                hmac_key=hmac_key_hexed,
            ),
        )
        # Send only thing after noise handshake, an encrypted, signed token to the client
        # Generate the values for the fields of the Token and Ticket
        ticket_id = uuid4().hex
        ## Generate mqtt topic by taking clients public key and shared nonce solving key as inputs
        mqtt_topic = "auth/" + generate_mqtt_topic(
            public_bytes=client_public_bytes, key=key
        )
        mqtt_username = generate_mqtt_username(public_bytes=client_public_bytes)
        mqtt_password = generate_mqtt_password(key=key)
        seed = token_bytes(128)
        device_id = uuid4().hex

        # Generate a signed token, encrypt and send
        signed_token = generate_signed_token(
            private_key=private_key,
            ticket_id=ticket_id,
            mqtt_topic=mqtt_topic,
            mqtt_username=mqtt_username,
            hmac_key=key,
            seed=seed,
        )
        # Set default expiry time of the ticket at the beginning to an hour
        # Stored as int in UNIX time
        # Expiry is set as an hour (3600 seconds) from the time the timestamp was generated
        expiry = int(time()) + 3600
        signed_ticket = generate_signed_ticket(
            private_key=private_key,
            ticket_id=ticket_id,
            device_id=device_id,
            public_key=client_public_bytes,
            expiry=expiry,
            seed=seed,
            hmac_key=key,
        )

        enc_signed_token_bytes = server_cipherstate.encrypt_with_ad(
            b"", signed_token.to_bytes_packed()
        )
        # Send generated signed token
        self.wfile.write(enc_signed_token_bytes)
        # Do blockchain committing of created ticket

        ## Setting up Dynamic Security
        # REQUIREMENT: Must have Mosquitto broker correctly set up
        # After registration and nonce authentication, create on the broker an account with the generated
        # mqtt username and password
        # dyns.create_client(mqtt_username)
        # dyns.set_client_password(mqtt_username, mqtt_password)
        # dyns.set_dynsec_topic(mqtt_username, mqtt_topic)


class ForkedTCPServer(ForkingMixIn, TCPServer):
    pass


def main():
    logger.setLevel(DEBUG)
    # Load Noise server static key pair to memory

    server = ForkedTCPServer((HOST, PORT), ForkedTCPRequestHandler)
    with server:
        try:
            # server_thread = threading.Thread(target=server.serve_forever)
            print("Serving forever...")
            server.serve_forever()
            # server_thread.daemon = True
            # server_thread.start()
            # print("Server loop running in thread:", server_thread.name)
        except KeyboardInterrupt:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
