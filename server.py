import dissononce, logging, socket

from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash
from dissononce.extras.processing.handshakestate_guarded import GuardedHandshakeState

HOST = "127.0.0.1"
PORT = 63000

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

            # Receiving ephemeral public key from client
            message_buffer = conn.recv(1024)
            
            server_handshakestate.read_message(bytes(message_buffer), bytearray())

            # For the server side message pattern
            # <- e, ee, s, es
            message_buffer = bytearray() 
            server_handshakestate.write_message(b'', message_buffer) 
            # Sending message buffer to client
            conn.sendall(message_buffer)

            # -> s, se
            message_buffer = conn.recv(1024)
            print(message_buffer, len(message_buffer))
            server_cipherstates = server_handshakestate.read_message(bytes(message_buffer), bytearray())
            
            ciphertext = conn.recv(1024)
            plaintext = server_cipherstates[0].decrypt_with_ad(b'', ciphertext)
            print(plaintext)
            assert plaintext == b'Hello'

            #conn.sendall(data)

            

if __name__ == "__main__":
    main()
