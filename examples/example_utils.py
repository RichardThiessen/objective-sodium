from nacl.signing import SigningKey
import hashlib
from objective_sodium import Ed25519 as cv, Scalar

"""
utility functions used by many of the example scripts
"""

def byte_xor(a,b):
    assert len(a)==len(b)
    return bytes(a^b for a,b in zip(*map(bytearray,(a,b))))

def sha512(priv_key):return hashlib.sha512(priv_key).digest()
def H_P2B(P,n=None):
    "maps a curve point to a byte string of length n (n<64)"
    if n>64:raise ValueError("can't supply more than 64 bytes (this uses sha512)")
    return sha512(cv.encode_point(P))[:n]
def hash_to_scalar(B):
    "maps a byte string to a scalar"
    return Scalar.from_long_bytes(sha512(B))

def ed25519_key_scalar(sk):
    assert isinstance(sk, SigningKey)
    "calculates the scalar for a SigningKey object."
    return cv.decode_scalar_25519(sha512(sk.encode())[:32])


    





