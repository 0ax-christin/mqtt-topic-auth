import socket, secrets, capnp

from mqtt.mqtt_pub_sub import publish, subscribe
from dissononce.processing.impl.cipherstate import CipherState

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

from capnp_processing.ticket import generate_ticket_id, generate_mqtt_password, generate_mqtt_topic, generate_mqtt_username, generate_signed_ticket
from capnp_processing.request import generate_request

from authentication.challenges import generate_challenge_response, verify_challenge_response

capnp.remove_import_hook()
request_capnp = capnp.load('capnp_schemas/request.capnp')
ticket_capnp = capnp.load('capnp_schemas/ticket.capnp')

request = request_capnp.Request
ticket = ticket_capnp.Ticket

from collections import namedtuple

# Namedtuple used to easily encapsulate the connectionstate, which is the cipherstate for encryption and
# the values used for authentication
MQTTConnectionState = namedtuple('MQTTConnectionState', ['cipherstate', 'mqtt_username', 'mqtt_password'])

def mqtt_reauth_flow_client(client_cipherstate: CipherState, hmac_key: bytes, mqtt_username: str, mqtt_password: str, mqtt_topic: str):
    # On ticket expiry, trigger flow
    connection_state = MQTTConnectionState(cipherstate=client_cipherstate, mqtt_username=mqtt_username, mqtt_password=mqtt_password)._asdict()
    # Unpack the namedtuple which has been converted to a dictionary
    # as the named arguments of a function
    reauth_req_bytes = subscribe(**connection_state, mqtt_topic=mqtt_topic)
    reauth_request = request.from_bytes_packed(reauth_req_bytes)

    if reauth_request.requestType == 'reauth':
        response = generate_challenge_response(nonce_challenge=reauth_request.nonceChallenge, hmac_key=hmac_key)

        challenge_solution_bytes = generate_request(requestType='response', nonce=response, solution=True).to_bytes_packed()

        publish(**connection_state, mqtt_topic=mqtt_topic, mqtt_payload=challenge_solution_bytes)

        solution_reply_bytes = subscribe(**connection_state, mqtt_topic=mqtt_topic)
        solution_reply = request.from_bytes_packed(solution_reply_bytes)

        if solution_reply.statusCode != 200:
            print("Failure, Error Code:", solution_reply.statusCode)
        else:
            print("Success!", solution_reply.statusCode)
    else:
        print("Error: Bad requestType from server")
            

def mqtt_reauth_flow_server(server_cipherstate: CipherState, hmac_key: bytes, mqtt_username: str, mqtt_password: str, mqtt_topic: str, nonce_challenge: int):

    connection_state = MQTTConnectionState(cipherstate=server_cipherstate, mqtt_username=mqtt_username, mqtt_password=mqtt_password)._asdict()

    # Generate capnp reauth challenge
    reauth_request_bytes = generate_request(requestType='reauth', nonce=nonce_challenge.to_bytes(64), solution=False).to_bytes_packed()
    # Send over MQTT pub
    publish(**connection_state, mqtt_topic=mqtt_topic, mqtt_payload=reauth_request_bytes)

    # Obtain challenge solution from client
    challenge_solution_bytes = subscribe(**connection_state, mqtt_topic=mqtt_topic)
    challenge_soluton = request.from_bytes_packed(challenge_solution_bytes)

    if challenge_solution.requestType == 'response':
        result = verify_challenge_response(nonce_challenge=nonce_challenge.to_bytes(64), nonce_solution=challenge_solution.nonceSolution, hmac_key=hmac_key)
        if result == True:
            success_reply_bytes = generate_request(requestType='status', status=True, statusCode=200).to_bytes_packed()
            publish(**connection_state, mqtt_topic=mqtt_topic, mqtt_payload=success_reply_bytes)
            # Blockchain code which renews the ticket with new expiry time
        else:
            # Error Reply: Unauthorized if the nonce challenge verification via HMAC leads to InvalidSignature
            error_reply_bytes = generate_request(requestType='status', status=True, statusCode=401).to_bytes_packed()
            publish(**connection_state, mqtt_topic=mqtt_topic, mqtt_payload=error_reply_bytes)

            # Code for blocking access of MQTT account using dynamic ACL?
    else:
        # Error reply: Bad Request if the solution request does not have the correct requestType
        error_reply_bytes = generate_request(requestType='status', status=True, statusCode=400).to_bytes_packed()
        publish(**connection_state, mqtt_topic=mqtt_topic, mqtt_payload=error_reply_bytes)