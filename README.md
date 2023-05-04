##objective-sodium

Implements a very simple wrapper around the Ed25519 and Curve25519 libsodium bindings in pynacl

This allows for `c=a+b` instead of `c=crypto_core_ed25519_add(a,b)`

This is mostly API compatible with [ecpy](https://ec-python.readthedocs.io/en/latest/).

If you were doing

```
from ecpy.curves     import Curve
cv     = Curve.get_curve('Ed25519')
```

You can instead do `from objective_sodium import Ed25519 as cv` and things should just work.

Note that this library also supplies a `Scalar` class that wraps integers and uses constant time libsodium scalar arithmetic. Using those is reccomended to avoid timing attacks.