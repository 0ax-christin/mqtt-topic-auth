import dissononce, logging, socket, pickle, capnp

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

HOST = "127.0.0.1"
PORT = 63000 

def main():
    

    dissononce.logger.setLevel(logging.DEBUG)

    # Generate the long term static DH keypair
    client_static = X25519DH().generate_keypair()
    
    # Serializing longterm static keypair
    with open('client_static_keypair.pickle', 'wb') as f:
        pickle.dump(client_static, f)

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

    with open('public_key.txt', 'rb') as reader:
        public_bytes = reader.read()
    with open('private_key.txt', 'rb') as reader:
        private_bytes = reader.read()

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
        result = s.recv(1024)
        print(result)

        if result == b'SUCCESS':
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
            with open('client_cipherstates.pickle', 'wb') as f:
                pickle.dump(client_cipherstates, f)
            
            ## REGISTRATION PHASE ##
            request = request_capnp.Request
            ticket = ticket_capnp.Ticket

            # Sending first register request
            register_request = request.new_message(noNonce=None, requestType='register').to_bytes()
            s.sendall(register_request)
            
            #Access one of the cipher states containing the key and encrypt
            ciphertext = client_cipherstates[0].encrypt_with_ad(b'', b'Hello')
            s.sendall(ciphertext) 
        else:
            conn.close()

if __name__ == "__main__":
    main()
