import socket, os, secrets, pickle, capnp

from authentication.challenges import generate_challenge
from authentication.challenges import send_challenge

from capnp_processing.request import generate_request
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

capnp.remove_import_hook()
request_capnp = capnp.load('capnp_schemas/request.capnp')
ticket_capnp = capnp.load('capnp_schemas/ticket.capnp')

HOST = "127.0.0.1"
PORT = 63000

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            
            ## assume noise handshake established
            if os.path.exists('keys/shared/hmac_key.txt'):
                with open('keys/shared/hmac_key.txt', 'rb') as reader:
                    key = reader.read()
            else:
                key = secrets.randbits(128).to_bytes(128)
                with open('keys/shared/hmac_key.txt', 'wb') as writer:
                    writer.write(key)
                conn.sendall(key)

            ## REGISTRATION PHASE ##
            request = request_capnp.Request
            ticket = ticket_capnp.Ticket

            register_req_bytes = conn.recv(1028)
            register_request = request.from_bytes_packed(register_req_bytes)

            if register_request.requestType == 'register':
                challenge = generate_challenge()
                send_challenge(socket=conn, challenge=challenge)
            else:
                conn.shutdown()
                conn.close()
            
            # Receive the clients solved response
            response_request = request.from_bytes_packed(conn.recv(64))

            if response_request.requestType == 'response':
                h = hmac.HMAC(key, hashes.BLAKE2s(32))
                h.update(challenge.to_bytes(64))
                try:
                    h.verify(response_request.nonceSolution)
                except InvalidSignature:
                    # Send back error message
                    conn.shutdown()
                    conn.close()
            else:
                # Send back error message
                conn.shutdown()
                conn.close()
            
            # Generate capnproto ticket and send to client
            # Server does other operations: authentication topic gen
            # MQTT username pass gen
            # Gen ticket ID


if __name__ == "__main__":
    main()