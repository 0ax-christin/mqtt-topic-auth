import capnp

capnp.remove_import_hook()
request_capnp = capnp.load('capnp_schemas/request.capnp')

request = request_capnp.Request

# Generate a request object as specified and return as bytes
# For network transmission
def generate_request(requestType: str, nonce: bytes = None, solution: bool = False, status: bool = False, statusCode: int = None) -> request_capnp.Request:
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
            
    # else raise an Exception
    return new_request