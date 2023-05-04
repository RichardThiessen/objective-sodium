##Chameleon hash

Implements a chameleon hash mostly based on Shnorr signatures

Can be used for:

- rewriteable blockchain type datastructures to allow a keyholder to change hash linked content
- trapdoor permutation to break the random oracle assumption for the holder of a particular key
  - EG:create a Fiat-Shamir zero knowledge proof whose random oracle has a trapdoor
