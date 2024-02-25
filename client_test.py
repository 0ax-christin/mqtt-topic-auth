import dissononce, logging, socket, pickle, capnp, os

from cryptography.hazmat.primitives import hashes, hmac

from capnp_processing.request import generate_request

capnp.remove_import_hook()
request_capnp = capnp.load('capnp_schemas/request.capnp')
ticket_capnp = capnp.load('capnp_schemas/ticket.capnp')

HOST = "127.0.0.1"
PORT = 63000 

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        ## assume noise handshake established
        if not os.path.exists('keys/shared/hmac_key.txt'):
            key = conn.recv(128)
            with open('keys/shared/hmac_key.txt', 'wb') as writer:
                writer.write(key)
        else:
            with open('keys/shared/hmac_key.txt', 'rb') as reader:
                key = reader.read()

        ## REGISTRATION PHASE ##
        request = request_capnp.Request
        ticket = ticket_capnp.Ticket

        # Sending first register request
        register_request = generate_request(requestType='register', nonce=None, solution=False)
        s.sendall(register_request.to_bytes_packed())

        # Receive the server challenge
        challenge_request = request.from_bytes_packed(s.recv(96))
        
        if challenge_request.requestType == 'challenge':
            challenge = challenge_request.nonceChallenge
            h = hmac.HMAC(key, hashes.BLAKE2s(32))
            h.update(challenge)
            response = h.finalize()

            ## Send challenge response
            challenge_solution = generate_request(requestType='response', nonce=response, solution=True)
            s.sendall(challenge_solution.to_bytes_packed())

        else:
            s.shutdown()
            s.close()



if __name__ == "__main__":
    main()