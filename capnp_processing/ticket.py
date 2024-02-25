import capnp
import uuid
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

capnp.remove_import_hook()
ticket_capnp = capnp.load('../capnp_schemas/ticket.capnp')


ticket = ticket_capnp.Ticket

def generate_ticket_id() -> str:
    return uuid.uuid4().hex

def generate_mqtt_topic(public_bytes: bytes) -> str:
    # Generate the MQTT Topic to be subscribed by the client for reauthentication messages
    return hashlib.sha3_256(public_bytes).hexdigest()

def generate_mqtt_username(public_bytes: bytes) -> str:
    return hashlib.sha3_256(public_bytes).hexdigest()

def generate_mqtt_password(key: bytes) -> str:
    return hashlib.sha3_256(key).hexdigest()

def generate_ticket(private_key: Ed25519PrivateKey, ticket_id:str, mqtt_topic: str, mqtt_username: str) -> ticket_capnp.Ticket:
    signature = private_key.sign(hashlib.sha3_256((ticket_id + mqtt_topic + mqtt_username).encode()).digest)
    new_ticket = ticket.new_message(ticketId=ticket_id, mqttTopic=mqtt_topic, mqttUsername=mqtt_username, signature=signature)
    return new_ticket