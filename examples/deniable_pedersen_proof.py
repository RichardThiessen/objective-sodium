

from nacl.signing import SigningKey
from os import urandom

from objective_sodium import  Scalar,Ed25519 as cv

from example_utils import (
    sha512,
    hash_to_scalar,
    ed25519_key_scalar)

from hmac import compare_digest


def hash_to_curve(seed):
    """maps a seed to a pseudorandomly chosen curve point
    the resulting point has an unknown discrete log
    
    for any H=hash_to_curve(b"some bytes")
    equations of the form (a*G+b*H=0) are not solvable without solving the
    discrete log problem
    """
    for i in range(2**32):
        h=sha512(seed+i.to_bytes(4,"little"))[:32]
        P=cv.decode_point(h)
        if P.is_on_curve():return P

#independent generator for Pedersen commitments
H_generator=hash_to_curve(cv.encode_point(cv.generator))


def commit(x,r=None):
    """create a pedersen commitment to x
    returns commitment C and blinding factor r"""
    if r is None:r=Scalar(urandom(32))
    return cv.generator*x+r*H_generator,r

def Prove_challenge_is_zero_deniable(r,challenge_key,context=b""):
    """proves to the holder of a challenge key:
    that a Pedersen commitment C opens to 0"""
    #derive pseudorandom values
    seed=sha512(bytes(r)+bytes(challenge_key)+context)
    k =hash_to_scalar(seed+b"k")
    s2=hash_to_scalar(seed+b"s2")
    #assemble the ring
    C=r*H_generator
    R1=H_generator*k
    e2=hash_to_scalar(bytes(R1)+bytes(C))
    R2=cv.decode_point(challenge_key)*e2+s2*cv.generator
    e1=hash_to_scalar(bytes(R2))#challenge key can be malleable
    s1=k-e1*r
    #now derive the ECDH key
    K = s2 * cv.Point(challenge_key)
    H= sha512(bytes(K)+context)[:32]
    proof = (bytes(R2)+
             bytes(s1)+
             H+
             context)
    return proof

def check_challenge_is_zero_deniable(proof,challenge_sk,C):
    assert len(proof)>=(32*3)
    R2=cv.decode_point(proof[  :32])
    s1=         Scalar(proof[32:64])
    H =                proof[64:96]
    context=proof[96:]
    #unpack challenge_sk
    challenge_sk=ed25519_key_scalar(challenge_sk)
    #traverse the ring to find S1
    e1=hash_to_scalar(bytes(R2))
    R1=cv.decode_point(C)*e1+s1*H_generator
    e2=hash_to_scalar(bytes(R1)+bytes(C))
    S1=R2-cv.generator*(challenge_sk*e2)
    #derive ECDH key
    K = S1 * challenge_sk
    H_target = sha512(bytes(K)+context)[:32]
    if not compare_digest(H_target, H):
        raise ValueError("bad proof")
    return context

def prove_opening_deniable(x,r,challenge_key,context=b""):
    """proves to the holder of a challenge key:
    that a Pedersen commitment C opens to x"""
    zero_proof=Prove_challenge_is_zero_deniable(r, challenge_key, context)
    return bytes(Scalar(x))+zero_proof

def check_opening_deniable(proof,challenge_sk,C):
    x=Scalar(proof[:32])
    zero_proof=proof[32:]
    C_zero=cv.decode_point(C)-cv.generator*x
    context=check_challenge_is_zero_deniable(zero_proof, challenge_sk, C_zero)
    return context,x


if __name__=="__main__":

    #Bob has a known key or generates an ephemeral challenge key for the protocol.
    bob_sk=SigningKey((b"Bob"*100)[:32])
    bob_pk=bob_sk.verify_key.encode()
    
    #Alice makes a proof
    x=0
    C,r=commit(x)
    proof=Prove_challenge_is_zero_deniable(r,challenge_key=bob_pk)
    
    #Bob checks the proof
    result=check_challenge_is_zero_deniable(proof, bob_sk, C)
    print("Bob knows the following commitment opens to zero:\n",C)
    
    #Alice makes a proof
    x=50
    C,r=commit(x)
    proof=prove_opening_deniable(x, r,challenge_key=bob_pk)
    
    #Bob checks the proof
    result=check_opening_deniable(proof, bob_sk, C)
    print("Bob knows the following commitment opens to %r:\n"%int(result[1]),C)