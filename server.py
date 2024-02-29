import dissononce, logging, socket, os, secrets, pickle, capnp

from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash
from dissononce.extras.processing.handshakestate_guarded import GuardedHandshakeState

from keygen.generate_keys import generate_ED25519_keypair

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

from authentication.challenges import verify_challenge_response

from capnp_processing.request import generate_request_bytes

from capnp_processing.ticket import generate_ticket_id, generate_mqtt_password, generate_mqtt_topic, generate_mqtt_username, generate_signed_ticket

import mqtt.dynsec_mqtt as dyns

capnp.remove_import_hook()
request_capnp = capnp.load('capnp_schemas/request.capnp')
ticket_capnp = capnp.load('capnp_schemas/ticket.capnp')

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
    request = request_capnp.Request
    ticket = ticket_capnp.Ticket

    if os.path.exists('keys/server/server_static_keypair.pickle'):
        with open('keys/server/server_static_keypair.pickle', 'rb') as keypair_file:
            server_static = pickle.load(keypair_file)
    else:
        # Generate the long term static DH keypair
        server_static = X25519DH().generate_keypair()
    
        # Serializing longterm static keypair
        with open('keys/server/server_static_keypair.pickle', 'wb') as keypair_file:
            pickle.dump(server_static, keypair_file)

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
    
    # Generate identity keypair outside noise handshake, which is stored in a file
    private_bytes, public_bytes = generate_ED25519_keypair(isBytes=True, server=True)

    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # 1. Client expects the public key of the server
            conn.sendall(public_bytes)

            # 2. Expect to receive random bytes as challenge
            random_bits = conn.recv(32)
            # 3. Sign and send random bits with servers private key
            signed_random_bits = private_key.sign(random_bits)
            conn.sendall(signed_random_bits)
            # if the server has been verified, the flow continues, else client shutdowns the socket
            # Check the result reply of the client to see whether statusCode is 200, for success, else shutdown this connection
            result_reply = request.from_bytes_packed(conn.recv(1024))

            if result_reply.statusCode != 200:
                conn.shutdown()
                conn.close()
                exit()

            # First, a public key is expected from client
            client_public_bytes = conn.recv(32)
        
            if public_key_exists(public_bytes=client_public_bytes):
                client_public_key = Ed25519PublicKey.from_public_bytes(client_public_bytes)
                # If public key exists in authorized_keys, send random 32 bytes back as a challenge to sign
                random_bits = secrets.token_bytes(32)
                conn.sendall(random_bits)
                signed_random_bits = conn.recv(64)
                try:
                    verify_result = client_public_key.verify(signed_random_bits, random_bits)
                except InvalidSignature:
                    # 401 for unauthorized, authentication failed
                    error_reply = generate_request_bytes(requestType='status', status=True, statusCode=401)
                    conn.sendall(error_reply)
                    conn.shutdown()
                    conn.close()
                    exit()
                # If no exception has been raised, means that signature was correctly verified
                if verify_result == None:
                    success_reply = generate_request_bytes(requestType='status', status=True, statusCode=200)
                    conn.sendall(success_reply)
            #TODO: potentially add error requests and types to challenge process? else:
    
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
            shared_cipherstates = server_handshakestate.read_message(bytes(message_buffer), bytearray())
            client_cipherstate = shared_cipherstates[0]
            server_cipherstate = shared_cipherstates[1]

            with open('keys/shared/server_cipherstates.pickle', 'wb') as f:
                pickle.dump(shared_cipherstates, f)
            
            # Every request after this is under encryption of the noise handshake

            # Load shared HMAC Keys if present, else send a newly generated 128 bit key to be used as HMAC
            # Send hmac key after noise established
            if os.path.exists('keys/shared/hmac_key.txt'):
                with open('keys/shared/hmac_key.txt', 'rb') as reader:
                    key = reader.read()
            else:
                key = secrets.randbits(128).to_bytes(128)
                with open('keys/shared/hmac_key.txt', 'wb') as writer:
                    writer.write(key)
                enc_key = server_cipherstate.encrypt_with_ad(b'', key)
                conn.sendall(enc_key)

            enc_register_req_bytes = conn.recv(1028)
            register_req_bytes = client_cipherstate.decrypt_with_ad(b'', enc_register_req_bytes)
            register_request = request.from_bytes_packed(register_req_bytes)
            
            if register_request.requestType == 'register':
                challenge = secrets.token_bytes(64)
                enc_challenge_request = generate_request_bytes(requestType='challenge', cipherState=server_cipherstate, nonce=challenge, solution=False)
                conn.sendall(enc_challenge_request)
            else:
                conn.shutdown()
                conn.close()
            
            # Receive the clients solved response
            enc_response_req_bytes = conn.recv(1028)
            response_req_bytes = client_cipherstate.decrypt_with_ad(b'', enc_response_req_bytes)
            response_request = request.from_bytes_packed(response_req_bytes)

            if response_request.requestType == 'response':
                result = verify_challenge_response(nonce_challenge=challenge, nonce_solution=response_request.nonceSolution, hmac_key=key)
                if result == True:
                    enc_success_reply = generate_request_bytes(requestType='status', cipherState=server_cipherstate, status=True, statusCode=200)
                    conn.sendall(enc_success_reply)
                else:
                    enc_error_reply = generate_request_bytes(requestType='status', cipherState=server_cipherstate, status=True, statusCode=401)
                    conn.sendall(enc_error_reply)
                    conn.shutdown()
                    conn.close()
            else:
                enc_error_reply = generate_request_bytes(requestType='status', cipherState=server_cipherstate, status=True, statusCode=400)
                conn.sendall(enc_error_reply)
                conn.shutdown()
                conn.close()
            
            ## Sending back a successful authentication and registration ticket
            ticket_id = generate_ticket_id()
            ## Generate mqtt topic by taking clients public key and shared nonce solving key as inputs
            mqtt_topic = "auth/" + generate_mqtt_topic(public_bytes=public_bytes, key=key)
            mqtt_username = generate_mqtt_username(public_bytes=public_bytes)
            mqtt_password = generate_mqtt_password(key=key)

            signed_ticket = generate_signed_ticket(private_key=private_key, ticket_id=ticket_id, mqtt_topic=mqtt_topic, mqtt_username=mqtt_username)
            enc_signed_ticket_bytes = server_cipherstate.encrypt_with_ad(b'', signed_ticket.to_bytes_packed())

            conn.sendall(enc_signed_ticket_bytes)

            ## Setting up Dynamic Security 
            # After registration and nonce authentication, create on the broker an account with the generated 
            # mqtt username and password
            dyns.create_client(mqtt_username)
            dyns.set_client_password(mqtt_username, mqtt_password)

            dyns.set_dynsec_topic(mqtt_username, mqtt_topic)

            # Sending


if __name__ == "__main__":
    main()
