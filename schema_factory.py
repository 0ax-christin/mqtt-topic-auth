import capnp
from hashlib import sha3_256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

capnp.remove_import_hook()
token_capnp = capnp.load("capnp_schemas/token.capnp")
ticket_capnp = capnp.load("capnp_schemas/ticket.capnp")
request_capnp = capnp.load("capnp_schemas/request.capnp")


request = request_capnp.Request
token = token_capnp.Token
ticket = ticket_capnp.Ticket
signed_ticket = ticket_capnp.SignedTicket
signed_token = token_capnp.SignedToken


def is_valid_token_signature(
    public_key: Ed25519PublicKey, signed_token: signed_token
) -> bool:
    try:
        public_key.verify(
            signed_token.signature,
            sha3_256(signed_token.token.to_bytes_packed()).digest(),
        )
        return True
    except InvalidSignature:
        return False


def generate_mqtt_topic(public_bytes: bytes, key: bytes) -> str:
    # Generate the MQTT Topic to be subscribed by the client for reauthentication messages
    return sha3_256(public_bytes + key).hexdigest()


def generate_mqtt_username(public_bytes: bytes) -> str:
    return sha3_256(public_bytes).hexdigest()


def generate_mqtt_password(key: bytes) -> str:
    return sha3_256(key).hexdigest()


def generate_signed_ticket(
    private_key: Ed25519PrivateKey,
    ticket_id: str,
    device_id: str,
    public_key: bytes,
    expiry: int,
    seed: bytes,
    hmac_key: bytes,
) -> signed_ticket:
    new_ticket = ticket.new_message(
        ticketId=ticket_id,
        deviceId=device_id,
        publicKey=public_key,
        expiry=expiry,
        seed=seed,
        hmacKey=hmac_key,
    )
    ticket_bytes = new_ticket.to_bytes_packed()
    signature = private_key.sign(sha3_256(ticket_bytes).digest())
    signed_new_ticket = signed_ticket.new_message(
        ticket=new_ticket, signature=signature
    )
    return signed_new_ticket


def generate_signed_token(
    private_key: Ed25519PrivateKey,
    ticket_id: str,
    mqtt_topic: str,
    mqtt_username: str,
    hmac_key: bytes,
    seed: bytes,
) -> signed_token:
    new_token = token.new_message(
        ticketId=ticket_id,
        mqttTopic=mqtt_topic,
        mqttUsername=mqtt_username,
        hmacKey=hmac_key,
        seed=seed,
    )
    token_bytes = new_token.to_bytes_packed()
    signature = private_key.sign(sha3_256(token_bytes).digest())
    signed_new_token = signed_token.new_message(token=new_token, signature=signature)
    return signed_new_token


def generate_status_reply_bytes(statusCode: int) -> bytes:
    new_request = request.new_message(requestType="status")
    new_request.statusCode = statusCode

    new_request_bytes = new_request.to_bytes_packed()
    return new_request_bytes


# Generate a request object as specified and return as bytes
# For network transmission
# Optionally, if cipherstate is included, the function will encrypt with this cipherstate with no associated data and return the bytes
def generate_request_bytes(
    requestType: str, nonce: bytes = b"", solution: bool = False
) -> bytes:
    allowed_request_types = ["register", "challenge", "response", "reauth"]

    if requestType in allowed_request_types:
        new_request = request.new_message(requestType=requestType)
        if nonce == b"":
            new_request.noNonce = None
        else:
            if solution is True:
                new_request.nonceSolution = nonce
            else:
                new_request.nonceChallenge = nonce

    new_request_bytes = new_request.to_bytes_packed()
    return new_request_bytes
