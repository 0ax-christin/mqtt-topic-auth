import dissononce, logging, secrets, socket, pickle, capnp, os

from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash
from dissononce.extras.processing.handshakestate_guarded import GuardedHandshakeState

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from keygen.generate_keys import generate_ED25519_keypair
from capnp_processing.request import generate_request_bytes

from cryptography.hazmat.primitives import hashes, hmac

from capnp_processing.ticket import generate_ticket_id, generate_mqtt_password, generate_mqtt_topic, generate_mqtt_username, generate_signed_ticket

from authentication.challenges import verify_challenge_response, generate_challenge_response

from pathlib import Path

capnp.remove_import_hook()
request_capnp = capnp.load('capnp_schemas/request.capnp')
ticket_capnp = capnp.load('capnp_schemas/ticket.capnp')


HOST = "127.0.0.1"
PORT = 63000 


# Base path of the project directory
base_path = Path(__file__).parent

def main():
    request = request_capnp.Request
    signed_ticket = ticket_capnp.SignedTicket

    dissononce.logger.setLevel(logging.DEBUG)

    # All clients have the server public key stored in them
    if os.path.exists((base_path / f'../keys/server/public_key.txt').resolve()):
        with open((base_path / f'../keys/server/public_key.txt').resolve(), 'rb') as reader:
            server_public_bytes = reader.read()

    server_public_key = Ed25519PublicKey.from_public_bytes(server_public_bytes)

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

    # Clients long term keypair for public key authentication
    private_bytes, public_bytes = generate_ED25519_keypair(isBytes=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        
        ## Authenticate server to the client
        # 1. Send challenge to the server
        random_bits = secrets.token_bytes(32)
        client_challenge = generate_request_bytes(requestType="register", nonce=random_bits)
        s.sendall(client_challenge)

        # 2. Receive the solution, verify with public key
        signed_challenge_response = request.from_bytes_packed(s.recv(80))
        signed_random_bits = signed_challenge_response.nonceSolution

        try:
            verify_result = server_public_key.verify(signed_random_bits, random_bits)
            # If no exception has been raised, means that signature was correctly verified
            if verify_result is None:
                success_reply_bytes = generate_request_bytes(requestType='status', status=True, statusCode=200)
                s.sendall(success_reply_bytes)
        except InvalidSignature:
            ## Stop connection if the signature doesnt match
            error_reply_bytes = generate_request_bytes(requestType='status', status=True, statusCode=401)
            s.sendall(error_reply_bytes)
            print("Error: Invalid Signature")
            s.shutdown()
            s.close()
            
       # Send the clients public key
       s.sendall(public_bytes) 

       server_response = request.from_bytes_packed(s.recv(45))
       if server_response.requestType == "challenge":
           server_challenge = server_response.nonceChallenge
           signed_client_response = private_key.sign(server_challenge)
           signed_client_response = generate_request_bytes(requestType="response", nonce=signed_client_response, solution=True)
           s.sendall(signed_client_response)
       else:
           s.shutdown()
           s.close()
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
            shared_cipherstates = client_handshakestate.write_message(b'', message_buffer)
            client_cipherstate = shared_cipherstates[0]
            server_cipherstate = shared_cipherstates[1]

            # Sends public static key of client to server, does the final DH on both sides
            s.sendall(message_buffer)
            
            # Save derived cipherstate so it can be used later
            with open('keys/shared/client_cipherstates.pickle', 'wb') as f:
                pickle.dump(shared_cipherstates, f)

            # Load the HMAC keys
            if not os.path.exists('keys/shared/hmac_key.txt'):
                enc_key = s.recv(180)
                key = server_cipherstate.decrypt_with_ad(b'', enc_key)
                with open('keys/shared/hmac_key.txt', 'wb') as writer:
                    writer.write(key)
            else:
                with open('keys/shared/hmac_key.txt', 'rb') as reader:
                    key = reader.read()

            ## REGISTRATION PHASE ##
            # Sending first register request
            enc_register_request  = generate_request_bytes(requestType='register', cipherState=client_cipherstate, nonce=None, solution=False)
            s.sendall(enc_register_request)

            # Receive the server challenge
            enc_challenge_req_bytes = s.recv(1028)
            challenge_req_bytes = server_cipherstate.decrypt_with_ad(b'', enc_challenge_req_bytes)
            challenge_request = request.from_bytes_packed(challenge_req_bytes)

            if challenge_request.requestType == 'challenge':
                response = generate_challenge_response(nonce_challenge=challenge_request.nonceChallenge, hmac_key=key)
                ## Send challenge response
                enc_challenge_solution = generate_request_bytes(requestType='response', cipherState=client_cipherstate, nonce=response, solution=True)
                s.sendall(enc_challenge_solution)
            else:
                s.shutdown()
                s.close()
            
            enc_solution_reply_bytes = s.recv(1024)
            solution_reply_bytes = server_cipherstate.decrypt_with_ad(b'', enc_solution_reply_bytes)
            solution_reply = request.from_bytes_packed(solution_reply_bytes)

            if solution_reply.statusCode != 200:
                print("Failure!")
                s.shutdown()
                s.close()
            else:
                print("Success!")
                enc_signed_ticket_bytes = s.recv(1500)
                signed_ticket_bytes = server_cipherstate.decrypt_with_ad(b'', enc_signed_ticket_bytes)
                ticket_signed = signed_ticket.from_bytes_packed(signed_ticket_bytes)
                # Client verifies signed ticket with the servers public key
                try:
                    verify_result = server_public_key.verify(ticket_signed.signature, ticket_signed.ticket)
                    ## Else success reply?
                except InvalidSignature:
                    ## Error Reply for Bad Signature on Signed Ticket
                    ## Program and socket closes and the values of the ticket are not used
                    s.shutdown()
                    s.close()
                    exit()

                # Generate MQTT password from key used for nonce challenge solving
                mqtt_password = generate_mqtt_password(key=key)
                # Client stores in memory the below values to be used in reauthentication via MQTT topics
                mqtt_username = ticket_signed.ticket.mqttUsername
                mqtt_topic = ticket_signed.ticket.mqttTopic
                ticket_id = ticket_signed.ticket.ticket_id

        else:
            s.shutdown()
            s.close()

if __name__ == "__main__":
    main()
