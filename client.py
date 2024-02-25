import dissononce, logging, socket, pickle, capnp, os

capnp.remove_import_hook()
request_capnp = capnp.load('capnp_schemas/request.capnp')
ticket_capnp = capnp.load('capnp_schemas/ticket.capnp')

from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash
from dissononce.extras.processing.handshakestate_guarded import GuardedHandshakeState

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keygen.generate_keys import generate_ED25519_keypair


HOST = "127.0.0.1"
PORT = 63000 

def main():
    request = request_capnp.Request
    dissononce.logger.setLevel(logging.DEBUG)

    if os.path.exists('keys/client/client_static_keypair.pickle'):
        with open('keys/client/client_static_keypair.pickle', 'rb') as keypair_file:
            client_static = pickle.load(keypair_file)
    else:
        # Generate the long term static DH keypair
        client_static = X25519DH().generate_keypair()
    
        # Serializing longterm static keypair
        with open('keys/client/client_static_keypair.pickle', 'wb') as keypair_file:
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

    private_bytes, public_bytes = generate_ED25519_keypair(isBytes=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        # Send the public key to the server
        s.sendall(public_bytes)
        # Receive random challenge bytes to sign
        random_bits = s.recv(32)

        # Sign and send back signed challenge bytes
        signed_random_bits = private_key.sign(random_bits)
        s.sendall(signed_random_bits)

        # Receive back the result, which indicates whether authentication passed or failed
        result_reply = request.from_bytes_packed(s.recv(1024))
        if result_reply.statusCode == 200:
            # -> e
            message_buffer = bytearray()
            client_handshakestate.write_message(b'', message_buffer)
            # Sends ephemeral public key
            s.sendall(message_buffer)

            message_buffer = s.recv(1024)
            # Performs DH between ephemeral keys
            # Performs DH between ephemeral key of client and static key of server, authenticating server
            client_handshakestate.read_message(bytes(message_buffer), bytearray())

            # -> s,se 
            message_buffer = bytearray()

            # Yields two cipherState, one for client, one for server as a tuple
            # Accessible using [0,1]
            client_cipherstates = client_handshakestate.write_message(b'', message_buffer)
            
            # Sends public static key of client to server, does the final DH on both sides
            s.sendall(message_buffer)
            
            # Save derived cipherstate so it can be used later
            with open('keys/shared/client_cipherstates.pickle', 'wb') as f:
                pickle.dump(client_cipherstates, f)
            
            #Access one of the cipher states containing the key and encrypt
            ciphertext = client_cipherstates[0].encrypt_with_ad(b'', b'Hello')
            s.sendall(ciphertext) 
        else:
            conn.shutown()
            conn.close()

if __name__ == "__main__":
    main()
