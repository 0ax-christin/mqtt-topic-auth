import capnp

capnp.remove_import_hook()
request_capnp = capnp.load('capnp_schemas/request.capnp')

from dissononce.processing.impl.cipherstate import CipherState

request = request_capnp.Request

# Generate a request object as specified and return as bytes
# For network transmission
# Optionally, if cipherstate is included, the function will encrypt with this cipherstate with no associated data and return the bytes
def generate_request_bytes(requestType: str, cipherState: CipherState = None, assoc_data: bytes = b'', nonce: bytes = None, solution: bool = False, status: bool = False, statusCode: int = None) -> bytes:
    allowed_request_types = ['register', 'challenge', 'response', 'reauth', 'status']

    if requestType in allowed_request_types:
        new_request = request.new_message(requestType=requestType)
        if status == True:
            new_request.statusCode = statusCode
        elif nonce == None:
            new_request.noNonce = None
        else:
            if solution == True:
                new_request.nonceSolution = nonce
            else:
                new_request.nonceChallenge = nonce

    new_request_bytes = new_request.to_bytes_packed()

    if cipherState != None:
        enc_new_req_bytes = cipherState.encrypt_with_ad(assoc_data, new_request_bytes)
        return enc_new_req_bytes
    # else raise an Exception
    return new_request_bytes