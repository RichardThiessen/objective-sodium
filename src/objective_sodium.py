from __future__ import division
import unittest
from hmac import compare_digest

from nacl.bindings.crypto_core import (
    crypto_core_ed25519_BYTES,
    crypto_core_ed25519_NONREDUCEDSCALARBYTES,
    crypto_core_ed25519_SCALARBYTES,
    crypto_core_ed25519_add,
    crypto_core_ed25519_is_valid_point,
    crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_scalar_complement,
    crypto_core_ed25519_scalar_invert,
    crypto_core_ed25519_scalar_mul,
    crypto_core_ed25519_scalar_negate,
    crypto_core_ed25519_scalar_reduce,
    crypto_core_ed25519_scalar_sub,
    crypto_core_ed25519_sub,
    has_crypto_core_ed25519,
)
from nacl.bindings.crypto_scalarmult import (
    crypto_scalarmult_ed25519_noclamp,
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_scalarmult_base,
    crypto_scalarmult)

import nacl.signing
import nacl.public

if not has_crypto_core_ed25519:raise ImportError

import hashlib
def sha512(priv_key):return hashlib.sha512(priv_key).digest()

def int_decode(s):
    return sum(256**i * b for i,b in enumerate(bytearray(s)))
def int_encode(x,n):
    if not 256**n>x>=0:raise ValueError("not enough bytes to represent x")
    return bytes(bytearray((x>>i*8)&255 for i in range(n)))

class Scalar():
    """represents a curve25519 or ed25519 scalar
    constant time arithmetic operations
    
    Can be constructed from:
    - bytes[32]
    - integer
    - nacl.signing.SigningKey
    - nacl.public.PrivateKey
    """
    SCALARBYTES=crypto_core_ed25519_SCALARBYTES
    NONREDUCEDSCALARBYTES=crypto_core_ed25519_NONREDUCEDSCALARBYTES
    order=int_decode(crypto_core_ed25519_scalar_negate(int_encode(1,SCALARBYTES)))+1
    @classmethod
    def _reduce(cls,B):
        if len(B)==cls.SCALARBYTES:
            B+=b"\0"*(cls.NONREDUCEDSCALARBYTES-cls.SCALARBYTES)
        return crypto_core_ed25519_scalar_reduce(B)
    @classmethod
    def from_long_bytes(cls,B):
        return cls(cls._reduce(B))
    def __init__(self,x,allow_nonreduced=True):
        if isinstance(x,Scalar):
            x=reduced=x.bytes
        elif type(x)==int:
            reduced=x%self.order
            self.bytes=int_encode(reduced,self.SCALARBYTES)
        elif type(x)==bytes:
            assert len(x)==self.SCALARBYTES
            self.bytes=reduced=self._reduce(x)
        elif isinstance(x, nacl.signing.SigningKey):
            #calculate secret scalar from signing key
            x=sha512(x.encode())[:32]
            self.bytes=self.decode_scalar_25519(x).bytes
        elif isinstance(x,nacl.public.PrivateKey):
            #C25519 keys objects just store scalar not the seed
            #scalar bytes aren't clamped though, so use the decode_scalar function to do that.
            self.bytes=self.decode_scalar_25519(x.encode()).bytes
        else:
            raise TypeError("Scalar must be created from bytes or int")
        if not allow_nonreduced and reduced!=x:
            raise ValueError("input scalar was not reduced mod group order") 
    def __repr__(self):
        return "%s(%s)"%(self.__class__.__name__,hex(int_decode(self.bytes)))
    def __bytes__(self):return self.bytes
    def __int__(self):return int_decode(self.bytes)
    #helpers for operations
    @classmethod
    def _tryop(cls,other,f):
        "if other is (Scalar,Int) convert to bytes and eval function else return NotImplemented" 
        if   isinstance(other, cls):return f(other.bytes)
        elif isinstance(other, int):return f(int_encode(other%cls.order,cls.SCALARBYTES))
        return NotImplemented
    #unary ops
    def __pos__(self):return self
    def __neg__(self):return Scalar(crypto_core_ed25519_scalar_negate(self.bytes))
    #binary ops
    def __add__ (self,other):return self._tryop(other,lambda o:Scalar(crypto_core_ed25519_scalar_add(self.bytes,o)))
    def __sub__ (self,other):return self._tryop(other,lambda o:Scalar(crypto_core_ed25519_scalar_sub(self.bytes,o)))
    def __mul__ (self,other):return self._tryop(other,lambda o:Scalar(crypto_core_ed25519_scalar_mul(self.bytes,o)))
    def __rsub__(self,other):return self._tryop(other,lambda o:Scalar(crypto_core_ed25519_scalar_sub(o,self.bytes)))
    #commutative ops
    def __radd__(self,other):return self+other
    def __rmul__(self,other):return self*other
    #division
    def inverse(self):#returns 1/self
        return Scalar(crypto_core_ed25519_scalar_invert(self.bytes))
    def __truediv__(self,other):
        return self._tryop(other,lambda o:
            Scalar(crypto_core_ed25519_scalar_mul(self.bytes,
                      crypto_core_ed25519_scalar_invert(o))))
    def __rtruediv__(self,other):
        return self._tryop(other,lambda o:
            Scalar(crypto_core_ed25519_scalar_mul(o,
                      crypto_core_ed25519_scalar_invert(self.bytes))))
    def __eq__(self,other):
        return self._tryop(other,lambda o:
            compare_digest(self.bytes,o))
        #use compare digest to avoid timing side channel
        #return isinstance(other,Scalar) and compare_digest(self.bytes,other.bytes)
    @classmethod
    def decode_scalar_25519(cls,data):
        """ decode scalar according to RF7748 and draft-irtf-cfrg-eddsa

        Args:
               k (bytes) : scalar to decode

        Returns:
              Scalar: decoded scalar
        """
        assert isinstance(data, bytes)
        k = bytearray(data)
        k[0]  &= 0xF8
        k[31] = (k[31] &0x7F) | 0x40
        k = bytes(k)
        S=Scalar(k)
        S.bytes=k
        return S
        return Scalar(k)
Scalar.zero=Scalar(0)


class Point_c25519():
    "represents a curve25519 point"
    ed25519_BYTES=crypto_core_ed25519_BYTES
    @classmethod
    def decode_point(cls,data):
        #for compatibility with ecpy
        assert isinstance(data,bytes)
        return cls(data)
    @classmethod
    def encode_point(cls,inst):
        #for compatibility with ecpy
        assert isinstance(inst,cls)
        return bytes(inst)
    def __init__(self,x):
        if isinstance(x, nacl.public.PublicKey):
            x=x.encode()
        self.bytes=bytes(x)
        assert len(self.bytes)==self.ed25519_BYTES
    def __repr__(self):
        return "%s(%r)"%(self.__class__.__name__,self.bytes)
    def __bytes__(self):return self.bytes
    #helpers for operations
    #unary ops
    def is_on_curve(self):raise NotImplemented("Not available in libsodium library")
    def __pos__(self):return self
    def __neg__(self):return (-1)*self
    #add/sub not implemented for curve25519 points
    def __mul__(self,other):
        return Scalar._tryop(other,lambda o:
            Point_c25519(crypto_scalarmult(o,self.bytes)))    
    def __rmul__(self,other):return self*other
    def __truediv__(self,other):
        return Scalar._tryop(other, lambda o:
            self*Scalar(o).inverse())
    def __eq__(self,other):
        assert isinstance(other,Point_c25519)
        #use compare digest to avoid timing side channel
        return compare_digest(self.bytes,other.bytes)

class Point_ed25519(Point_c25519):
    "represents an ed25519 curve point"
    def is_on_curve(self):return crypto_core_ed25519_is_valid_point(self.bytes)
    def __init__(self,x):
        if isinstance(x, nacl.signing.VerifyKey):
            x=x.encode()
        self.bytes=bytes(x)
#         if not self.is_on_curve():
#             raise ValueError("point is not on curve")
        assert len(self.bytes)==self.ed25519_BYTES
    #add/sub implemented for ed25519
    def __add__(self,other):
        assert isinstance(other,Point_ed25519)
        return Point_ed25519(crypto_core_ed25519_add(self.bytes,other.bytes))
    def __sub__(self,other):
        assert isinstance(other,Point_ed25519)
        return Point_ed25519(crypto_core_ed25519_sub(self.bytes,other.bytes))
    #no reflected add/sub, other instance must also be point
    def __mul__(self,other):
        return Scalar._tryop(other,lambda o:
            Point_ed25519(crypto_scalarmult_ed25519_noclamp(o,self.bytes)))    
    def __eq__(self,other):
        if not isinstance(other,Point_ed25519):return NotImplemented
        #use compare digest to avoid timing side channel
        return compare_digest(self.bytes,other.bytes)


class Curve25519():
    def __init__(self):
        raise NotImplemented("singleton class, do not create instance")
    class _generator_c25519(Point_c25519):
        def __repr__(self):
            return "%s(%r)"%(Point_c25519.__name__,self.bytes)
        def __mul__(self,other):
            if other == Scalar.zero:raise ValueError("can't handle point at infinity")
            return Scalar._tryop(other,lambda o:
                Point_c25519(crypto_scalarmult_base(o)))
    generator=_generator_c25519(b"\t"+b"\0"*31)
    Point=Point_c25519
    order=Scalar.order
    name='Curve25519'
    type='montgomery'
    size=256
    a=486662
    b=1
    field=57896044618658097711785492504343953926634992332820282019728792003956564819949
    @classmethod
    def encode_point(cls,P):
        assert isinstance(P, cls.Point)
        return bytes(P)
    @classmethod
    def decode_point(cls,data):
        return cls.Point(data)
    @classmethod
    def encode_scalar_25519(cls,s):
        assert isinstance(s, Scalar)
        return bytes(s)
    decode_scalar_25519=Scalar.decode_scalar_25519

class Ed25519(Curve25519):
    zero_point=Point_ed25519(b'\x01'+b'\0'*31)
    class _generator_ed25519(Point_ed25519):
        def __repr__(self):
            return "%s(%r)"%(Point_ed25519.__name__,self.bytes)
        def __mul__(self,other):
            if other == Scalar.zero:return Ed25519.zero_point
            return Scalar._tryop(other,lambda o:
                Point_ed25519(crypto_scalarmult_ed25519_base_noclamp(o)))
    generator=_generator_ed25519(_generator_ed25519.__mul__(None,1))
    Point=Point_ed25519
    name='Ed25519'
    type='twistededward'
    size=256
    a=-1
    d=37095705934669439343138083508754565189542113879843219016388785533085940283555


class TestScalar(unittest.TestCase):
    def test_arithmetic(self):
        N=Scalar.order
        opers=[("a+b",lambda a,b:a+b,0),
               ("a-b",lambda a,b:a-b,0),
               ("a*b",lambda a,b:a*b,0),
               ("a/b",lambda a,b:a/b,0),
               ("+a",lambda a,b:+a,1),
               ("-a",lambda a,b:-a,1),
               ("a==b",lambda a,b:int(a==b),0),]
        nums=[0,1,2,6,7,8,2**100,2**200,]
        nums.extend([(-n)%N for n in nums])
        for fname,f,unary in opers:
            for a in nums:
                for b in [0] if unary else nums:
                    try:correct=f(a,b)
                    except ZeroDivisionError:continue
                    if fname=="a/b" and (int(correct)*b)!=a:
                        continue#this involves modular inverses
                    correct=int(correct)
                    Scorrect,Sa,Sb=map(Scalar,(correct,a,b))
                    self.assertEqual(Scorrect, f(Sa,Sb),(fname,a,b))
                    if not unary:
                        self.assertEqual(Scorrect, f(Sa, b),(fname,a,b))
                        self.assertEqual(Scorrect, f( a,Sb),(fname,a,b))
    def test_init(self):
        #check scalar reduction can be caught but works otherwise
        for v in [Scalar.order,int_encode(Scalar.order, 32),-Scalar.order]: 
            with self.assertRaises(ValueError):
                Scalar(v,allow_nonreduced=False)
            self.assertEqual(Scalar(Scalar.order),0)

class TestC25519(unittest.TestCase):
    pass
    #TODO:add unit tests for curves

if __name__=="__main__":
    from ecpy.curves import Curve
    cv=Curve.get_curve("Curve25519")
    import math
    print(hex(cv.order))
    a=int_decode(bytes(Scalar.decode_scalar_25519(b"\xff"*32)))
    print(hex(int(a/8.0)))
    print(hex(int_decode(bytes(Scalar(1)/2))))
    print(hex(int_decode(bytes(Scalar(1)/4))))
    print(hex(int_decode(bytes(Scalar(1)/8))))
    from nacl import _sodium
    
    
    
    sk=nacl.public.PrivateKey.generate()
    pk=sk.public_key
    
    print(cv.encode_point(cv.generator))
    print(Curve25519.generator)
    
    
    sk_scalar=Scalar(sk)
    pk_point=Curve25519.Point(pk)
    target=Curve25519.generator*sk_scalar
    import nacl.bindings
    print(sk_scalar)
    print(Scalar(sk_scalar.bytes))
    print(pk_point)
    print(Curve25519.Point(nacl.bindings.crypto_scalarmult_base(sk.encode())))
    print(Curve25519.Point(nacl.bindings.crypto_scalarmult_base(sk_scalar.bytes)))
    print(target)
    assert target==pk_point
    
    exit()
    sk=nacl.signing.SigningKey.generate()
    pk=sk.verify_key
    
    sk_scalar=Scalar(sk)
    pk_point=Ed25519.Point(pk)
    target=Ed25519.generator*sk_scalar
    print(sk_scalar)
    print(pk_point)
    print(target)
    assert target==pk_point
    
    unittest.main()
    
    




