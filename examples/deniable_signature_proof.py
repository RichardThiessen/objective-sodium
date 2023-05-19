

from nacl.signing import SigningKey
import json
import io

from objective_sodium import  Scalar,Ed25519 as cv, int_encode, int_decode


import hashlib
from hmac import compare_digest
def sha512(m):return hashlib.sha512(m).digest()
def h_int(m):return Scalar.from_long_bytes(sha512(m))


def verify(sig,pk,m):
    #verify an Ed25519 signature
    assert len(sig)==64
    R = cv.Point(sig[0:32])
    A = cv.Point(pk)
    s = Scalar(sig[32:])
    h = Scalar.from_long_bytes(sha512(bytes(R) + pk + m))
    return cv.generator*s == R+A*h

def ed25519_key_scalar(sk):
    return cv.decode_scalar_25519(sha512(sk.encode())[:32])

def make_proof(sig,challenge_key,m,context=b"",detached=False):
    R=sig[0:32]
    PKc = cv.Point(challenge_key)
    s = Scalar(sig[32:])
    K = s * PKc
    H = sha512(bytes(K)+context)[:32]
    proof = (R+H+
             int_encode(len(context), 4)+context+
             ((int_encode(len(m), 4)+m) if not detached else b""))
    return proof

def check_proof(proof,challenge_sk,pk,m=None):
    stream=io.BytesIO(proof)
    def get(n):
        data=stream.read(n)
        if len(data)<n:raise ValueError("not enough data")
        return data
    R = cv.decode_point(get(32))
    H = get(32)
    context=get(int_decode(get(4)))
    if m is None:
        m = get(int_decode(get(4)))#remainder
    assert not stream.read(-1),"extra data remaining"
    del stream,get
    
    #calculate S from signature equation
    A = cv.decode_point(pk)
    h = h_int(cv.encode_point(R) + pk + m)
    S = R+A*h
    #check the DH shared key sha512 was correctly calculated
    K=cv.encode_point( S * ed25519_key_scalar(challenge_sk))
    H_target=sha512(K+context)[:32]
    if not compare_digest(H_target, H):
        raise ValueError("bad proof")
    return context,m

if __name__=="__main__":
    gov_sk=SigningKey(b"1"*32)
    gov_pk=gov_sk.verify_key.encode()
    
    alice_ID={"info":json.dumps(
        {"name":"Alice Liddell",
         "DOB":"1970-01-01",
         "occupation":"cryptographer"}).encode("utf8")}
    alice_ID["sig"]=gov_sk.sign(alice_ID["info"])[:64]
    
    #check the signature
    assert verify(alice_ID["sig"],gov_pk,alice_ID["info"])
    print("Alice verified she has a valid signature")
    
    #bob has a known key or generates an ephemeral challenge key for the protocol.
    bob_sk=SigningKey((b"bob"*100)[:32])
    bob_pk=bob_sk.verify_key.encode()
    
    print("Bob --> Alice: challenge key:",repr(bob_pk))
    #Alice makes a proof
    proof=make_proof(sig=alice_ID["sig"], challenge_key=bob_pk, m=alice_ID["info"],
                     context=json.dumps({"prover":"Alice","verifier":"Bob","date":"2023-01-01T01:02:59Z"}).encode())
    print("Alice --> Bob: proof:",repr(proof))
    
    
    #bob can verify it
    result=check_proof(proof, bob_sk, gov_pk)
    print("Bob knows the following was signed:",result[1])
    print("with protocol context:",result[0])