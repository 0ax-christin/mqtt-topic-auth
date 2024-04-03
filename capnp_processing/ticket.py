import capnp, uuid, hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

capnp.remove_import_hook()
token_capnp = capnp.load('capnp_schemas/token.capnp')

token = token_capnp.Token
signed_token = token_capnp.SignedToken

def is_valid_token_signature(public_key: Ed25519PublicKey, signed_token: signed_token):
    try:
        result = public_key.verify(signed_token.signature, hashlib.sha3_256(signed_token.token.to_bytes_packed()).digest)
        if result == None:
            return True
    except InvalidSignature:
        return False

def generate_ticket_id() -> str:
    return uuid.uuid4().hex

def generate_mqtt_topic(public_bytes: bytes, key: bytes) -> str:
    # Generate the MQTT Topic to be subscribed by the client for reauthentication messages
    return hashlib.sha3_256(public_bytes+key).hexdigest()

def generate_mqtt_username(public_bytes: bytes) -> str:
    return hashlib.sha3_256(public_bytes).hexdigest()

def generate_mqtt_password(key: bytes) -> str:
    return hashlib.sha3_256(key).hexdigest()

def generate_signed_token(private_key: Ed25519PrivateKey, ticket_id:str, mqtt_topic: str, mqtt_username: str) -> signed_token:
    new_token= token.new_message(ticketId=ticket_id, mqttTopic=mqtt_topic, mqttUsername=mqtt_username)
    signature = private_key.sign(hashlib.sha3_256(new_token.to_bytes_packed()).digest)
    signed_new_token = signed_token.new_message(ticket=new_token, signature=signature)
    return signed_new_token
