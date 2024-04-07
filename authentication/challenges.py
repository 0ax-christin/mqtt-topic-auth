from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives import hashes, hmac

# Given a challenge of bytes
# and a HMAC key, generate an HMAC(key, challenge) and return
def generate_challenge_response(nonce_challenge: bytes, hmac_key: bytes, rand_bytes: bytes) -> bytes:
    h = hmac.HMAC(hmac_key+rand_bytes, hashes.BLAKE2s(32))
    h.update(nonce_challenge)
    response = h.finalize()
    return response 

# Given the original nonce challenge and hmac key, verify that the supplied nonce solution is valid
# If so, return true, else false
def verify_challenge_response(nonce_challenge: bytes, nonce_solution: bytes, hmac_key: bytes, rand_bytes: bytes) -> bool:
    h = hmac.HMAC(hmac_key+rand_bytes, hashes.BLAKE2s(32))
    h.update(nonce_challenge)
    try:
        h.verify(nonce_solution)
        print("Verified!!!!")
        return True
    except InvalidSignature:
        return False
