import asyncio, aiomqtt,os
from contextlib import aclosing
# For encryption
from dissononce.processing.impl.cipherstate import CipherState
from dotenv import load_dotenv
# For hostname, port, protocol loaded from .env
load_dotenv()

# MQTT message payloads are always transferred in bytes
async def publish(cipherstate: CipherState, mqtt_username: str, mqtt_password: str, mqtt_topic: str, mqtt_payload: bytes):
    #1.Encrypt whatever payload with noise cipherstate
    enc_payload_bytes = server_cipherstate.encrypt_with_ad(b'', mqtt_payload)
    # 2. Transmit in the payload of a MQTT publish message to auth topic
    async with aiomqtt.Client(hostname=os.getenv("HOSTNAME"), port=os.getenv("PORT"), username=mqtt_username, password=mqtt_password, protocol=os.getenv("PROTOCOL_VER")) as client:
        await client.publish(mqtt_topic, payload=enc_payload_bytes)

async def subscribe(cipherstate: CipherState, mqtt_username: str, mqtt_password: str, mqtt_topic: str) -> bytes:
    async with aiomqtt.Client(hostname=os.getenv("HOSTNAME"), port=os.getenv("PORT"), username=mqtt_username, password=mqtt_password, protocol=os.getenv("PROTOCOL_VER")) as client:
        await client.subscribe(mqtt_topic)
        # We expect only one message from the server, which is returned
        # Decrypt the payload with noise server cipherstate and return the payload
        async for message in aclosing(client.messages):
            enc_payload_bytes = message.payload
            payload_bytes = server_cipherstate.decrypt_with_ad(b'', enc_payload_bytes)
            return payload_bytes
            break