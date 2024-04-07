import socket, capnp, logging, dissononce, os, pickle, secrets, hashlib
from schema_factory import generate_request_bytes, generate_status_reply_bytes

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash, hashes

from keygen.generate_keys import generate_ED25519_keypair_client_bytes
from pathlib import Path

HOST, PORT = "localhost", 63000 

capnp.remove_import_hook()
request_capnp = capnp.load('capnp_schemas/request.capnp')
token_capnp = capnp.load('capnp_schemas/token.capnp')

# Base path of the project directory
base_path = Path(__file__).parent

def main():
    request = request_capnp.Request
    signed_token = token_capnp.SignedToken
    token = token_capnp.Token
    dissononce.logger.setLevel(logging.DEBUG)
    client_static=''
    server_public_bytes=b''
    # All clients have the server public key stored in them
    print((base_path / f'./keys/server/public_key.txt').resolve())
    if os.path.exists((base_path / f'./keys/server/public_key.txt').resolve()):
        with open((base_path / f'./keys/server/public_key.txt').resolve(), 'rb') as reader:
            server_public_bytes = reader.read()
            print(server_public_bytes)
    server_public_key = Ed25519PublicKey.from_public_bytes(server_public_bytes)

    print((base_path / f'keys/client/client_static_keypair.pickle').resolve())
    if os.path.exists((base_path / f'keys/client/client_static_keypair.pickle').resolve()):
        with open((base_path / f'keys/client/client_static_keypair.pickle').resolve(), 'rb') as keypair_file:
            client_static = pickle.load(keypair_file)
    else:
        # Generate the long term static DH keypair
        client_static = X25519DH().generate_keypair()
    
        # Serializing longterm static keypair
        with open((base_path / f'keys/client/client_static_keypair.pickle').resolve(), 'wb') as keypair_file:
            pickle.dump(client_static, keypair_file)

    client_handshakestate = HandshakeState(
            SymmetricState(
                CipherState(
                    ChaChaPolyCipher()
                ),
                Blake2sHash()
            ),
            X25519DH()
            )
    client_handshakestate.initialize(XXHandshakePattern(), True, b'', s=client_static)

        # Clients long term keypair for public key authentication
    private_bytes, public_bytes = generate_ED25519_keypair_client_bytes()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
            
        ## Authenticate server to the client
        # 1. Send challenge to the server
        random_bits = secrets.token_bytes(32)
        client_challenge = generate_request_bytes(requestType="register", nonce=random_bits)
        s.sendall(client_challenge + b'\n')

        # 2. receive the solution, verify with public key
        signed_challenge_response = request.from_bytes_packed(s.recv(80))
        signed_random_bits = signed_challenge_response.nonceSolution

        try:
            verify_result = server_public_key.verify(signed_random_bits, random_bits)
            # if no exception has been raised, means that signature was correctly verified
            if verify_result is None:
                success_reply_bytes = generate_status_reply_bytes(statusCode=200)
                s.sendall(success_reply_bytes + b'\n')
        except InvalidSignature:
            ## stop connection if the signature doesnt match
            error_reply_bytes = generate_status_reply_bytes(statusCode=401)
            s.sendall(error_reply_bytes + b'\n')
            print("error: invalid signature")
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            exit()

        # send the clients public key
        s.sendall(public_bytes + b'\n') 

        server_response = request.from_bytes_packed(s.recv(45))
        print(server_response.requestType)
        if server_response.requestType == "challenge":
            print("Creating clients response")
            server_challenge = server_response.nonceChallenge
            signed_client_response = private_key.sign(server_challenge)
            signed_client_response = generate_request_bytes(requestType="response", nonce=signed_client_response, solution=True)
            s.sendall(signed_client_response + b'\n')
        else:
            print("Shutdown cause of error code of status Code: ", server_response.statusCode)
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            exit()
        # receive back the result, which indicates whether authentication passed or failed
        result_reply = s.recv(45)
        result_reply = request.from_bytes_packed(result_reply)
        print(result_reply.statusCode)

        if result_reply.statusCode == 200:
            # -> e
            message_buffer = bytearray()
            client_handshakestate.write_message(b'', message_buffer)
            # sends ephemeral public key
            s.sendall(message_buffer + b'\n')

            message_buffer = s.recv(1024)
            # performs dh between ephemeral keys
            # performs dh between ephemeral key of client and static key of server, authenticating server
            client_handshakestate.read_message(bytes(message_buffer), bytearray())

            # -> s,se 
            message_buffer = bytearray()

            # Yields two cipherState, one for client, one for server as a tuple
            # Accessible using [0,1]
            shared_cipherstates = client_handshakestate.write_message(b'', message_buffer)
            client_cipherstate = shared_cipherstates[0]
            server_cipherstate = shared_cipherstates[1]

            # Sends public static key of client to server, does the final DH on both sides
            s.sendall(message_buffer + b'\n')

            # Save derived cipherstate so it can be used later
            with open('keys/shared/client_cipherstates.pickle', 'wb') as f:
                pickle.dump(shared_cipherstates, f)

            enc_signed_token_bytes = s.recv(1500)
            signed_token_bytes = server_cipherstate.decrypt_with_ad(b'', enc_signed_token_bytes)
            token_signed = signed_token.from_bytes_packed(signed_token_bytes)
            original_token = token.new_message(ticketId=token_signed.token.ticketId, mqttTopic=token_signed.token.mqttTopic,
                                      mqttUsername=token_signed.token.mqttUsername, hmacKey=token_signed.token.hmacKey,
                                 seed=token_signed.token.seed)
 
            # Client verifies signed ticket with the servers public key
            try:
                verify_result = server_public_key.verify(token_signed.signature, hashlib.sha3_256(original_token.to_bytes_packed()).digest())
                print("Signature valid! using the values from the token")
            except InvalidSignature:
                ## Program and socket closes and the values of the ticket are not used
                print("Invalid Signature: Shutting Down connection..")
                s.shutdown(socket.SHUT_RDWR)
                s.close()
                exit()
            key = token_signed.token.hmacKey
            print(key
            with open('keys/shared/hmac_key.txt', 'wb') as writer:
                    writer.write(key)
        else:
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            exit()
if __name__ == "__main__":
    main()
