# Hybrid Post Quantum Cryptography
While both Falcon and Dilithium have been standardized, these two Digital Signature Schemes schemes haven’t 
been battle-tested widely. It's possible that newer category of attacks on Lattice based cryptography may come to light.

Because of these reasons, it's preferable to use a hybrid signature scheme that 
uses two crypto schemes behind the scenes: a PQC scheme and a classical scheme (ECDSA). This hybrid 
model is required to provide a hedge against Falcon or Dilithium getting broken 
on classical computers in the interim. 

When quantum computers capable enough to break ECDSA become available, the hybrid model 
will still provide protection against quantum computer attacks, since a post quantum crypto scheme is used in the hybrid model. 


This hybrid model will be abstracted away so that users do not have to worry 
about managing two sets of keys. To users, it will be just one composite key to manage and 
use. Likewise, higher-level developers do not have to worry about the hybrid 
model, since it will be abstracted away.

Some disadvantages of the hybrid model are increased complexity, increased compute time, increased 
storage, and bandwidth requirements. However, the security benefits of the 
hybrid model outweigh these disadvantages.

## Falcon
Falcon is a Post Quantum Digital Signature Scheme that has been standardized by NIST.
This repository is based on the [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions) submission of Falcon. 
New functions have been added to work with the *Doge Protocol Blockchain*.

### Source
[https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Falcon-Round3.zip](https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Falcon-Round3.zip)

```SHA256: fd58f0454f6bfb4713734e60b2d2d75d96fbae62d5180fceeef1039df5362f44```

## Contributing

Thank you for considering to help out with the source code! 

* Please reach out in [our Discord Server](https://discord.gg/bbbMPyzJTM) for any questions. 
* Pull requests need to be based on and opened against the `main` branch.

## License

This Falcon implementation is provided under the MIT license, whose text
is included at the start of every source file.
