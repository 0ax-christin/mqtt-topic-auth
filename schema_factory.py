"""
This module is for factory functions which generate CapnProto Schemas or any other functionality related to one of the
schemas (such as a fields, validation). The schemas covered are from the 'capnp_schemas/' folder:
1. Request
2. SignedToken/Token
3. SignedTicket/Token

This was needed for the easy generation of CapnProto Schemas as required by the server and client with the correct parameters
and all functions return in byte form for direct transmission over the wire.
"""
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
    public_key: Ed25519PublicKey, signed_token: token_capnp.SignedToken
) -> bool:
    """Take a signed token and check it using the servers public key with its signature

    Params
    ------
      public_key: Ed25519PublicKey
        Public Key of the server which issued the token, which will be used to verify the signature of the token given to
        the client
      signed_token: token_capnp.SignedToken
        A CapnProto Schema which has a Token schema as its field and a signature. The signature is formed by taking the token,
        turning it to its bytes form, producing a hash and then signing using the servers private key on the hash
    Return
    ------
      True|False: bool
      True means the signature was valid
      False means that the signature was invalid for that public key, indicating a falsely issued token
    """
    try:
        public_key.verify(
            signed_token.signature,
            sha3_256(signed_token.token.to_bytes_packed()).digest(),
        )
        return True
    except InvalidSignature:
        return False


def generate_mqtt_topic(public_bytes: bytes, key: bytes) -> str:
    """ Take a public key and an hmacKey, concatenate and turn it into a hexstring representing the hash, return to be used
    as mqtt authentication topic between client and server
    Params
    ------
    public_bytes: bytes
      Public key in bytestring of the client
    key: bytes
      Key used as the solution for the challenge which is shared between server and client. This allows the topic to be
      unguessable as it requires knowledge of the secret HMAC key, making sure that only client and server know the secret
      topic on which to publish
    Return
    ------
    sha3_256(public_bytes+key).hexdigest(): str
      SHA3 hash turned into a hexstring whose input was a concatenation of public key in bytes and hmac key
    """
    # Generate the MQTT Topic to be subscribed by the client for reauthentication messages
    return sha3_256(public_bytes + key).hexdigest()


def generate_mqtt_username(public_bytes: bytes) -> str:
    """ Take the SHA3 hash of the public key and return the value to be used as mqtt username
    Params
    ------
    public_bytes: bytes
      The public key of the client is used as the identifier for the MQTT account.
    Return
    ------
    sha3_256(public_bytes).hexdigest(): str
      the hexstring of the SHA3 hash of the public key is used as the username for the MQTT account
    """
    return sha3_256(public_bytes).hexdigest()


def generate_mqtt_password(key: bytes) -> str:
    """ Take the SHA3 hash of the hmacKey and return the value to be used as mqtt password
    Params
    ------
    key: bytes
      The password used must be secret, as such, the hmac key is used as the secret value for its generation. If an attacker
      knows how to solve the challenge, which requires knowledge of the key used to generate the HMAC, then it can be assumed
      they can already access the channel
    Return
    ------
    sha3_256(key).hexdigest(): str
      Hexstring which is SHA3 hash of the HMAC key
    """
    return sha3_256(key).hexdigest()


def generate_signed_ticket(
    private_key: Ed25519PrivateKey,
    ticket_id: str,
    device_id: str,
    public_key: bytes,
    expiry: int,
    seed: bytes,
    hmac_key: bytes,
) -> token_capnp.SignedTicket:
    """ Generate a Ticket using the parameters as fields, then generate signature using the private key of server
    after which the Ticket and signature are encapsulated into a SignedTicket which is returned
    Params
    ------
    private_key: Ed25519PrivateKey
      Private key of server which will be used to sign the ticket to allow verification that the ticket was issued by the server
    ticket_id: str
      A Unique identifier for the ticket on the blockchain generated using UUID4 standard
    device_id: str
      A unique identifier for the device of the MQTT account generated using UUID4 standard   
    public_key: bytes
      Public key of client for whom the ticket is committed to the blockchain 
    expiry: int
      Expiry date is an unsigned integer in UNIX time.
    seed: bytes
      The secret seed used in the challenge response requests during reauthentication that allows each challenge to have a unique
      response
    hmac_key: bytes
      The secret key used to generate the solution to the challenge sent by server during reauthentication
    Return
    ------
    signed_new_ticket: token_capnp.SignedTicket
    """
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
) -> token_capnp.SignedToken:
    """Generate a Token using the parameters as fields, then generate signature using the private key of server
    after which the Token and signature are encapsulated into a SignedToken which is returned

    Params
    ------
    private_key: Ed25519PrivateKey
      Private key of server which will be used to sign the ticket to allow verification that the ticket was issued by the server
    ticket_id: str
      A Unique identifier for the ticket on the blockchain generated using UUID4 standard
    mqtt_topic: str
      The secret topic that is used by the client and server to perform continuous reauthentication
    mqtt_username: str
      MQTT username that has been generated by the server for a client
    hmac_key: bytes
      The secret key used to generate the solution to the challenge sent by server during reauthentication
    seed: bytes
      The secret seed used in the challenge response requests during reauthentication that allows each challenge to have a unique
      response
    Return
    ------
    signed_new_token: token_capnp.SignedToken
    """
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
    """ Generate a status reply packet with the given status code
    Params
    ------
    statusCode: int
      The status code to be added in the packet which represents the status of the request, codes similar to HTTP
      Currently there are 4 used in the protocol: 200, 400, 401, 403
    Return
    ------
    new_request_bytes: bytes
      Returns the bytes of the packet to be transferred over the wire
    """
    new_request = request.new_message(requestType="status")
    new_request.statusCode = statusCode

    new_request_bytes = new_request.to_bytes_packed()
    return new_request_bytes


def generate_request_bytes(
    requestType: str, nonce: bytes = b"", solution: bool = False
) -> bytes:
    """ Generate a CapnProto Request object as specified by the parameters and return as bytes for network transmission
    Params
    ------
    requestType: str
      There are four request types allowed for request CapnProto Schema:
      1. register
      2. challenge
      3. response
      4. reauth
      They indicate different kinds of requests that will be done in the protocol
    nonce: bytes, optional
      Relevant to the Reauth request packets used for continous reauthentication. Contains the nonce challenge, which
      is a set of random bits generated by the server (default is b"")
    solution: bool, optional
      Relevant to the reauth request type
      If solution is set to True, it means that the packet is a solution to a reauthentication challenge and
      the nonce parameter is used to set the nonceSolution field of the schema.
      If solution is false, it means the packet is a challenge from the server and the nonce parameter is used
      to set the nonceChallenge field of the schema. (Default is False)
    Return
    ------
    new_request_bytes: bytes
      bytes form of the newly created request to allow for instant transmission over the network socket
    """
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
