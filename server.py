import dissononce, logging, socket, os, secrets

from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash
from dissononce.extras.processing.handshakestate_guarded import GuardedHandshakeState

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

HOST = "127.0.0.1"
PORT = 63000
'''
Check that a given public key in byte string exists in authorized_keys
'''
def public_key_exists(public_bytes):
    if os.path.exists("authorized_keys"):
        with open("authorized_keys", 'rb') as reader:
            while (current_public_bytes := reader.read(32)):
                if current_public_bytes == public_bytes:
                    return True
                else:
                    return False
def main():
    dissononce.logger.setLevel(logging.DEBUG)

    # Generate the long term static DH keypair
    server_static = X25519DH().generate_keypair()

    server_handshakestate = HandshakeState(
            SymmetricState(
                CipherState(
                    ChaChaPolyCipher()
                ),
                Blake2sHash()
            ),
            X25519DH()
        )

    server_handshakestate.initialize(XXHandshakePattern(), False, b'', s=server_static)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            # First, a public key is expected from client
            public_bytes = conn.recv(32)
        
            if public_key_exists(public_bytes=public_bytes):
                public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
                # If public key exists in authorized_keys, send random 32 bytes back as a challenge to sign
                random_bits = secrets.token_bytes(32)
                conn.sendall(random_bits)
                signed_random_bits = conn.recv(64)
                try:
                    verify_result = public_key.verify(signed_random_bits, random_bits)
                except InvalidSignature:
                    conn.sendall(b'INVALID SIGNATURE, AUTH FAILED')
                    conn.close()
                    exit()
                # If no exception has been raised, means that signature was correctly verified
                if verify_result == None:
                    conn.sendall(b'SUCCESS')
            
            # Receiving ephemeral public key from client
            message_buffer = conn.recv(1024)
            
            server_handshakestate.read_message(bytes(message_buffer), bytearray())

            # For the server side message pattern
            # <- e, ee, s, es
            message_buffer = bytearray() 
            server_handshakestate.write_message(b'', message_buffer) 
            # Sending message buffer to client, this will have ephemeral public key of server
            # Server then performs DH to get shared secret, uses this to send static public key under encryption
            conn.sendall(message_buffer)

            # -> s, se
            message_buffer = conn.recv(1024)
            server_cipherstates = server_handshakestate.read_message(bytes(message_buffer), bytearray())
            
            print(server_cipherstates, len(server_cipherstates))
            print(type(server_cipherstates))
            
            ciphertext = conn.recv(1024)
            plaintext = server_cipherstates[0].decrypt_with_ad(b'', ciphertext)
            print(plaintext)
            assert plaintext == b'Hello'

            #conn.sendall(data)

            

if __name__ == "__main__":
    main()
