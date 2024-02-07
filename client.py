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
    client_static = X25519DH().generate_keypair()


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

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # -> e
        message_buffer = bytearray()
        client_handshakestate.write_message(b'', message_buffer)
        s.sendall(message_buffer)

        message_buffer = s.recv(1024)
        client_handshakestate.read_message(bytes(message_buffer), bytearray())

        # -> s,se 
        message_buffer = bytearray()
        client_cipherstates = client_handshakestate.write_message(b'', message_buffer)
        s.sendall(message_buffer)

        ciphertext = client_cipherstates[0].encrypt_with_ad(b'', b'Hello')
        print(ciphertext, type(ciphertext), len(ciphertext))
        s.sendall(ciphertext) 


if __name__ == "__main__":
    main()
