import capnp
import random
import asyncio
import aiomqtt
from os import getenv

from mqtt.dynsec_mqtt import disable_client
from dissononce.processing.impl.cipherstate import CipherState
from collections import namedtuple
from dotenv import load_dotenv
from schema_factory import (
    generate_mqtt_password,
    generate_mqtt_topic,
    generate_mqtt_username,
    generate_signed_ticket,
    generate_request_bytes,
    generate_status_reply_bytes,
)

from authentication.challenges import (
    generate_challenge_response,
    verify_challenge_response,
)

capnp.remove_import_hook()
request_capnp = capnp.load("capnp_schemas/request.capnp")
ticket_capnp = capnp.load("capnp_schemas/ticket.capnp")

request = request_capnp.Request
ticket = ticket_capnp.Ticket


# For hostname, port, protocol loaded from .env
load_dotenv()
# Namedtuple used to easily encapsulate the connectionstate, which is the cipherstate for encryption and
# the values used for authentication
MQTTConnectionState = namedtuple(
    "MQTTConnectionState", ["mqtt_username", "mqtt_password"]
)


async def get_subscribed_topic(
    mqtt_username: str, mqtt_password: str, mqtt_topic: str
) -> bytes:
    """ Given the user account credentials for MQTT and a topic, fetch any new messages published on the channel

    In this case it used by the participants of reauthentication via MQTT topic (the server and the client) for fetching any
    published messages from each other
    Params
    ------
    mqtt_username: str
      MQTT username which is meant to have the correct access rights to subscribe and receive published messages from the topic
    mqtt_password: str
      MQTT password which is used to authenticate the MQTT user
    mqtt_topic: str
      The reauthentication topic from which published messages will be read
    Return
    ------
      payload_bytes: bytes
      The sent message is a CapnProto object made from the Request Schema. The payload of the PUBLISH message, which is the
      CapnProto object is extracted and returned to the caller of the function
    """   
    async with aiomqtt.Client(
        hostname=getenv("HOSTNAME"),
        port=int(getenv("PORT")),
        username=mqtt_username,
        password=mqtt_password,
        protocol=int(getenv("PROTOCOL_VER")),
    ) as client:
        await client.subscribe(mqtt_topic)
        # We expect only one message from the server, which is returned
        async for message in client.messages:
            payload_bytes = message.payload
            return payload_bytes


async def publish_to_topic(
    mqtt_username: str, mqtt_password: str, mqtt_topic: str, mqtt_payload: bytes
):
    """ Publish on an MQTT topic with a given payload using the credentials of the given MQTT account
    Params
    ------
    mqtt_username: str
      MQTT username which is meant to have the correct access rights to subscribe and receive published messages from the topic
    mqtt_password: str
      MQTT password which is used to authenticate the MQTT user
    mqtt_topic: str
      The reauthentication topic on which the payload will be published
    mqtt_payload: bytes
      The actual payload in bytes. In the context of this protocol, usually CapnProto objects
    """
    async with aiomqtt.Client(
        hostname=getenv("HOSTNAME"),
        port=int(getenv("PORT")),
        username=mqtt_username,
        password=mqtt_password,
        protocol=int(getenv("PROTOCOL_VER")),
    ) as client:
        await client.publish(mqtt_topic, payload=mqtt_payload)


def generate_random_seed_bytes(seed: bytes, reauth_number: int) -> bytes:
    """Given the secret seed known only to the server and client, and the reauthentication number, generate 48 random bytes
    Params
    ------
    seed: bytes
      Secret seed shared between client and server used to generate the solution for a given reauthentication
    reauth_number: int
      The reauthentication number indicating the current reauthentication, used to generate the nth in a set of 48 bytes
    Return
    ------
    rand_bytes: bytes
      The random bytes generated for this specific reauthentication (indicated by the reauthentication number) which is required
      as part of the secret solution to the reauthentication challenge
    """
    random.seed(seed)
    rand_bytes = b""
    for i in range(reauth_number):
        rand_bytes = random.randbytes(48)
    return rand_bytes


def mqtt_reauth_flow_client(
    client_cipherstate: CipherState,
    server_cipherstate: CipherState,
    hmac_key: bytes,
    mqtt_username: str,
    mqtt_password: str,
    mqtt_topic: str,
    seed: bytes,
):
    # On ticket expiry, trigger flow
    connection_state = MQTTConnectionState(
        mqtt_username=mqtt_username, mqtt_password=mqtt_password
    )._asdict()
    # Unpack the namedtuple which has been converted to a dictionary
    # as the named arguments of a function
    enc_reauth_req_bytes = asyncio.run(
        get_subscribed_topic(**connection_state, mqtt_topic=mqtt_topic)
    )
    reauth_req_bytes = client_cipherstate.decrypt_with_ad(b"", enc_reauth_req_bytes)
    reauth_request = request.from_bytes_packed(reauth_req_bytes)

    if reauth_request.requestType == "reauth":
        # Need to store the reauthentication number somewhere so that the server knows which iteration of the bytes to generate
        seed_rand_bytes = generate_random_seed_bytes(seed, reauth_number=1)
        response = generate_challenge_response(
            nonce_challenge=reauth_request.nonceChallenge,
            hmac_key=hmac_key,
            rand_bytes=seed_rand_bytes,
        )

        challenge_solution_bytes = generate_request_bytes(
            requestType="response", nonce=response, solution=True
        )

        # Client encrypts with servers key for receiving
        enc_challenge_solution_bytes = server_cipherstate.encrypt_with_ad(
            b"", challenge_solution_bytes
        )

        asyncio.run(
            publish_to_topic(
                **connection_state,
                mqtt_topic=mqtt_topic,
                mqtt_payload=enc_challenge_solution_bytes,
            )
        )

        enc_solution_reply_bytes = asyncio.run(
            get_subscribed_topic(**connection_state, mqtt_topic=mqtt_topic)
        )
        solution_reply_bytes = client_cipherstate.decrypt_with_ad(
            b"", enc_solution_reply_bytes
        )
        solution_reply = request.from_bytes_packed(solution_reply_bytes)

        if solution_reply.statusCode != 200:
            print("Failure, Error Code:", solution_reply.statusCode)
        else:
            print("Success!", solution_reply.statusCode)
    else:
        print("Error: Bad requestType from server")


def mqtt_reauth_flow_server(
    client_cipherstate: CipherState,
    server_cipherstate: CipherState,
    hmac_key: bytes,
    mqtt_username: str,
    mqtt_password: str,
    mqtt_topic: str,
    nonce_challenge: int,
    seed: bytes,
):
    connection_state = MQTTConnectionState(
        mqtt_username=mqtt_username, mqtt_password=mqtt_password
    )._asdict()

    # Generate capnp reauth challenge
    reauth_request_bytes = generate_request_bytes(
        requestType="reauth", nonce=nonce_challenge.to_bytes(64), solution=False
    )  # Send over MQTT pub

    enc_reauth_req_bytes = client_cipherstate.encrypt_with_ad(b"", reauth_request_bytes)

    asyncio.run(
        publish_to_topic(
            **connection_state, mqtt_topic=mqtt_topic, mqtt_payload=enc_reauth_req_bytes
        )
    )

    # Obtain challenge solution from client
    enc_challenge_solution_bytes = asyncio.run(
        get_subscribed_topic(**connection_state, mqtt_topic=mqtt_topic)
    )
    challenge_solution_bytes = server_cipherstate.decrypt_with_ad(
        b"", enc_challenge_solution_bytes
    )
    challenge_solution = request.from_bytes_packed(challenge_solution_bytes)

    if challenge_solution.requestType == "response":
        # Need to store the reauthentication number somewhere so that the server knows which iteration of the bytes to generate
        seed_rand_bytes = generate_random_seed_bytes(seed, reauth_number=1)
        result = verify_challenge_response(
            nonce_challenge=nonce_challenge.to_bytes(64),
            nonce_solution=challenge_solution.nonceSolution,
            hmac_key=hmac_key,
            rand_bytes=seed_rand_bytes,
        )
        if result is True:
            success_reply_bytes = generate_status_reply_bytes(statusCode=200)

            enc_success_reply_bytes = client_cipherstate.encrypt_with_ad(
                b"", success_reply_bytes
            )
            asyncio.run(
                publish_to_topic(
                    **connection_state,
                    mqtt_topic=mqtt_topic,
                    mqtt_payload=enc_success_reply_bytes,
                )
            )
            # Blockchain code which renews the ticket with new expiry time
        else:
            # Error Reply: Unauthorized if the nonce challenge verification via HMAC leads to InvalidSignature
            error_reply_bytes = generate_status_reply_bytes(statusCode=401)
            enc_error_reply_bytes = client_cipherstate.encrypt_with_ad(
                b"", error_reply_bytes
            )
            asyncio.run(
                publish_to_topic(
                    **connection_state,
                    mqtt_topic=mqtt_topic,
                    mqtt_payload=enc_error_reply_bytes,
                )
            )

            disable_client(mqtt_username)
    else:
        # Error reply: Bad Request if the solution request does not have the correct requestType
        error_reply_bytes = generate_status_reply_bytes(statusCode=400)
        enc_error_reply_bytes = client_cipherstate.encrypt_with_ad(
            b"", error_reply_bytes
        )
        asyncio.run(
            publish_to_topic(
                **connection_state,
                mqtt_topic=mqtt_topic,
                mqtt_payload=enc_error_reply_bytes,
            )
        )
