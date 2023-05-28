
from os import urandom
from nacl.signing import SigningKey,VerifyKey

from objective_sodium import Ed25519 as cv, Scalar

from _example_utils import (
    byte_xor,
    H_P2B,
    hash_to_scalar,
    ed25519_key_scalar)

"""
This module implements a chameleon hash function, a hash function with a
trapdoor in the form of a public key. Knowledge of the private key allows for
finding preimages.

>>> priv=SigningKey.generate()
>>> pub=priv.verify_key 
>>> Hash,R1=chameleon(pub,m1)
>>> assert verify(Hash,m1,R1)  #verifies correctly
>>> R2=forge(priv,m2,Hash) #calculate preimage using `priv_key` trapdoor
>>> verify(Hash,m2,R2)  #forgery verifies correctly too

note:
default functions bundle public key with the hash for ease of use.
raw functions don't do that
"""

class VerifyError(ValueError):pass

#raw functions

def chameleon_raw(Y,m,r=None):
    """
    This is a schnorr signature with a much more malleable e
    traditional: e=H(R | m)
    This:        e=H(m | (out^H(R)))  since t=H(r)^out
    For a chosen (m,out) this is equivalent to a random oracle
    The standard Schnorr signature security proofs apply
    It can be trivially solved with `out` as a free variable but this gives no
    control over output"""
    #raw chameleon hash, all parameters taken separately (Y,m,[r])
    #returns (H,r)
    if isinstance(Y,VerifyKey):Y=Y.encode()
    assert (r is None) or len(r)==64
    s,t=((Scalar(r[:32]),r[32:]) if r else
         (Scalar.from_long_bytes(urandom(64)),urandom(32)))
    #when generating reduce 64 bytes for uniform s distribution
    r=bytes(s)+t #re-pack everything
    #do the hash
    e=hash_to_scalar(m+t)
    R=e*cv.decode_point(Y)+s*cv.generator
    h=byte_xor(t, H_P2B(R,32))
    return h,r

#the following methods pack h+Y together for convenience.
#unless space is a big concern (64 vs 32 bytes) this makes things a lot easier

def forge(priv_key,m,H,salt=b""):
    #produce r for an (m,h) pair given private key
    #salt randomises process but is not required
    
    #handle packed H
    h=H #default case, if unpacked h supplied
    if len(H)==64:
        h,Y=H[:32],cv.decode_point(H[32:])
        if bytes(Y)!=priv_key.verify_key.encode():
            raise ValueError("wrong private key supplied for packed hash")
    assert len(h)==32

    #ephemeral secret `k` is always derived securely from parameters
    k=hash_to_scalar(priv_key.encode()+m+h+salt+b"chameleon_raw hash forge secret")
    x=ed25519_key_scalar(priv_key)
    R=k*cv.generator
    t=byte_xor(h, H_P2B(R,32))
    e=hash_to_scalar(m+t)
    s=k-e*x
    r=bytes(s)+t
    return r

def chameleon(Y,m):
    if isinstance(Y,VerifyKey):Y=Y.encode()
    h,r=chameleon_raw(Y, m)
    return h+Y,r

def verify(H,m,r):
    assert len(H)==64
    h_target,Y=H[:32],H[32:]
    h=chameleon_raw(Y, m, r)[0]
    return h==h_target

if __name__=="__main__":
    priv_key=SigningKey(b"1"*32) #test key
    Y=priv_key.verify_key #priv key

    priv_key2=SigningKey(b"2"*32) #wrong key
    Y2=priv_key2.verify_key #wrong priv key
    
    r_other=b"\x00"*64 #wrong r
    
    m1=b"hello"
    m2=b"goodbye"
    
    #raw method tests
    h,r1=chameleon_raw(Y,m1)
    assert h==chameleon_raw(Y,m1,r1)[0]
    
    r2=forge(priv_key, m2, h)
    assert h==chameleon_raw(Y,m2, r2)[0]
    
    del h,r1,r2
    #now check wrapped functions
    H,r1=chameleon(Y, m1)
    assert verify(H, m1, r1)
    assert not verify(H, m1, r_other)
    r2=forge(priv_key, m2, H) #forge takes wrapped h as well
    assert verify(H, m2, r2)
    
    try:
        forge(priv_key2, m2, H) #forge with wrapped hash checks against Y in wrapped hash
        raise Exception("wrong privkey should be detected")
    except ValueError:pass