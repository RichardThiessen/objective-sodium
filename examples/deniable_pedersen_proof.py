

from nacl.signing import SigningKey
from os import urandom

from objective_sodium import  Scalar,Ed25519 as cv

from _example_utils import (
    sha512,
    hash_to_scalar,
    hash_to_curve,
    ed25519_key_scalar)

from hmac import compare_digest

#independent hiding generator for Pedersen commitments
H_generator=hash_to_curve(cv.encode_point(cv.generator))

def commit(x,r=None):
    """create a Pedersen commitment to x
    returns commitment C and blinding factor r"""
    if r is None:r=Scalar(urandom(32))
    return cv.generator*x+r*H_generator,r

def Prove_challenge_is_zero_deniable(r,challenge_key,context=b""):
    """
    proves to the holder of a challenge key:
    - that a Pedersen commitment C opens to 0
    optionally bind context data to the proof
    
    The proof is a ring signature with the keys being:
    1- DLOG(commitment    ,base=H_gen) <-- we know this
    2- DLOG(challenge_key ,base=G    )
    
    for the second ring segment, we don't send the `s2` value
    the point `S2=s2*G` is used as an ephemeral DH key proving knowledge of `s2`
    the other side can recalculate it
    
    Note:the second ring segment uses the challenge key for convenience as a
    point with an unknown discrete log. We could use H_gen or something else
    entirely. The challenge key was used since the second ring segment could use
    a different elliptic curve entirely and that key is a useful point with an
    unknown DLOG.
    """
    #derive pseudorandom values
    seed=sha512(bytes(r)+bytes(challenge_key)+context)
    k =hash_to_scalar(seed+b"k")
    s2=hash_to_scalar(seed+b"s2")
    #unpack/derive variables
    Y=cv.decode_point(challenge_key)
    C=r*H_generator
    #assemble the ring
    R1=H_generator*k 
    # ring equations:
    e2=hash_to_scalar(bytes(R1)+bytes(C)); R2=e2*Y+s2*cv.generator
    e1=hash_to_scalar(bytes(R2)+bytes(Y));#R1=e1*C+s1*H
    s1=k-e1*r #close the ring
    #now derive the ECDH key
    K = s2 * Y
    H= sha512(bytes(K)+context)[:32]
    proof = (bytes(R2)+
             bytes(s1)+
             H+
             context)
    return proof

def check_challenge_is_zero_deniable(proof,challenge_sk,C):
    """verifies a proof that a commitment opens to 0"""
    assert len(proof)>=(32*3)
    R2=cv.decode_point(proof[  :32])
    s1=         Scalar(proof[32:64])
    H =                proof[64:96]
    context=proof[96:]
    #unpack/derive variables
    challenge_sk=ed25519_key_scalar(challenge_sk)
    Y=challenge_sk*cv.generator
    #traverse the ring to find S1
    e1=hash_to_scalar(bytes(R2)+bytes(Y))
    R1=cv.decode_point(C)*e1+s1*H_generator
    e2=hash_to_scalar(bytes(R1)+bytes(C))
    S1=R2-e2*Y
    #derive ECDH key
    K = S1 * challenge_sk
    H_target = sha512(bytes(K)+context)[:32]
    if not compare_digest(H_target, H):
        raise ValueError("bad proof")
    return context

def prove_opening_deniable(x,r,challenge_key,context=b""):
    """proves to the holder of a challenge key:
    that a Pedersen commitment C opens to x
    
    since the commitment is C=x*G+r*H, we send:
    - x
    - a proof C'=r*H opens to zero
    
    the other side:
    - calculates the zero commitment C'=C-x*G
    - checks the proof C' opens to zero 
    """
    zero_proof=Prove_challenge_is_zero_deniable(r, challenge_key, context)
    return bytes(Scalar(x))+zero_proof

def check_opening_deniable(proof,challenge_sk,C):
    """verifies a proof that a commitment opens to x"""
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