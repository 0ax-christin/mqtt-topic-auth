import secrets, socket

from capnp_processing.request import generate_request

def generate_challenge() -> int:
    """ Generates a random integer of 64 bits for use as a challenge

    Returns
    -------
    int
        Random integer that will be used as a challenge    
    """
    random_bits = secrets.randbits(64)
    return random_bits


def send_challenge(socket: socket.socket, challenge: int):
    challenge = generate_request(requestType='challenge',  nonce=challenge.to_bytes(64), solution=False)
    # Send challenge in bytes
    socket.sendall(challenge.to_bytes_packed())
