[![CMake on multiple platforms](https://github.com/DogeProtocol/hybrid-pqc/actions/workflows/cmake-multi-platform.yml/badge.svg)](https://github.com/DogeProtocol/hybrid-pqc/actions/workflows/cmake-multi-platform.yml)

# Hybrid Post Quantum Cryptography
While lattice based post-quantum cryptography schemes such as SPHINCS+ and Dilithium have been standardized, they haven’t 
been battle-tested widely over the years like RSA and Elliptic Curve vased crypto-schemes. It's possible that newer category of attacks on Lattice based cryptography may come to light.

Because of these reasons, it's preferable to use a hybrid signature scheme that 
uses two crypto schemes behind the scenes: a PQC scheme and a classical scheme (EdDSA). This hybrid 
model is required to provide a hedge against Lattice based cryptography schemes such as Dilithium getting broken 
on classical computers in the interim. In addition, SPHINCS+ which is hash based is also part of the signature scheme, to be used as a breakglass (details below).

When quantum computers capable enough to break EdDSA become available, the hybrid model 
will still provide protection against quantum computer attacks, since a post quantum crypto scheme is used in the hybrid model. 

This hybrid model will be abstracted away so that users do not have to worry 
about managing multiple sets of keys. To users, it will be just one composite key to manage and 
use. Likewise, higher-level developers do not have to worry about the hybrid 
model, since it will be abstracted away.

Some disadvantages of the hybrid model are increased complexity, increased risk of implementation bugs, increased compute time, increased 
storage, and bandwidth requirements. However, the security benefits of the hybrid model outweigh these disadvantages.

## Hybrid Scheme
In this hybrid scheme, Dilithium, SPHINCS+ and ed25519 are used in a combiner mode. More details on the comment at https://github.com/DogeProtocol/hybrid-pqc/blob/main/hybrid-dilithium-sphincs/hybrid.c

Since SPHINCS+ signatures are large, the do not fit requirements of many applications. Because of this reason, this hybrid scheme supports two modes of signing:

1) A compact mode in which a message hashed from the original message, the SPHINCS+ public-key and a 40 byte random nonce is embedded into the signature. If both Dilithium and ed25519 are broken in the future, the SPHINCS+ full signing mode can be required by the verifying applications, like a breakglass.
2) A full mode in which all the three signature schemes are used to create a signature (including the full SPHINCS+ signature). 

## Dilithium and SPHINCS+
Dilihitum and SPHINCS+ are Post Quantum Digital Signature Schemes that have been standardized by NIST.
This repository is based on the PQClean implementations at https://github.com/PQClean/PQClean 

## EdDSA
The classical digital signature algorithm used is EdDSA (ed25519). The implementation used is [TweetNaCl](https://tweetnacl.cr.yp.to/), a self-contained public-domain C library. (https://tweetnacl.cr.yp.to/)

## Randombytes
The random implementation is based on (https://github.com/dsprenkels/randombytes), which itself is based on libsodium randombytes.

## Building

### Linux/macOS

1. Install dependencies:

	On Ubuntu:

		 apt-get update
		 sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml

	On macOS, using a package manager of your choice (we've picked Homebrew):

		brew install cmake ninja openssl@1.1 wget doxygen graphviz astyle
		pip3 install pytest pytest-xdist pyyaml

2. Get the source:

		git clone https://github.com/dogeprotocol/hybrid-pqc.git
		cd hybrid-pqc

	and build:

		mkdir build && cd build
		cmake -G Ninja -DBUILD_SHARED_LIBS=ON ..
		ninja

### Windows

Binaries can be generated using Visual Studio 2019 with the [CMake Tools](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cmake-tools) extension installed. The same options as explained above for Linux/macOS can be used and build artifacts are generated in the specified `build` folders.

If you want to create Visual Studio build files, e.g., if not using `ninja`, be sure to _not_ pass the parameter `-GNinja` to the `cmake` command as exemplified above. You can then build all components using `msbuild`, e.g. as follows: `msbuild ALL_BUILD.vcxproj` and install all artifacts e.g. using this command `msbuild INSTALL.vcxproj`.

### Web Assembly WASM

1. Install emsdk https://www.tutorialspoint.com/webassembly/webassembly_installation.htm
2. Goto directory of emsdk and run: emsdk_env.bat
3. Create build folder. For example: c:\github\hybrid-pqc\wasm\build
4. Run the following command, replacing appropriate paths:


		emcc -s WASM=1 -s EXPORTED_FUNCTIONS="['_free', '_malloc']"  -s "EXPORTED_RUNTIME_METHODS=['getValue']" ${{ github.workspace }}/wasm/hybrid-pqc.c ${{ github.workspace }}/dilithium2/ntt.c ${{ github.workspace }}/dilithium2/packing.c ${{ github.workspace }}/dilithium2/poly.c ${{ github.workspace }}/dilithium2/polyvec.c ${{ github.workspace }}/dilithium2/reduce.c ${{ github.workspace }}/dilithium2/rounding.c ${{ github.workspace }}/dilithium2/sign.c ${{ github.workspace }}/dilithium2/symmetric-shake.c ${{ github.workspace }}/sphincs/address.c ${{ github.workspace }}/sphincs/context_shake.c ${{ github.workspace }}/sphincs/fors.c ${{ github.workspace }}/sphincs/hash_shake.c ${{ github.workspace }}/sphincs/merkle.c ${{ github.workspace }}/sphincs/sign.c ${{ github.workspace }}/sphincs/thash_shake_simple.c ${{ github.workspace }}/sphincs/utils.c ${{ github.workspace }}/sphincs/utilsx1.c ${{ github.workspace }}/sphincs/wots.c ${{ github.workspace }}/sphincs/wotsx1.c  ${{ github.workspace }}/random/randombytes.c ${{ github.workspace }}/common/fips202.c ${{ github.workspace }}/common/hybrid-common.c ${{ github.workspace }}/common/shake_prng.c ${{ github.workspace }}/tweetnacl/tweetnacl.c  ${{ github.workspace }}/hybrid-dilithium-sphincs/hybrid.c -o ${{ github.workspace }}/build/wasm/hybrid-pqc.html

## Contributing

Thank you for considering to help out with the source code! 

* Please reach out in [our Discord Server](https://discord.gg/bbbMPyzJTM) for any questions. 
* Pull requests need to be based on and opened against the `main` branch.

## License
PQClean: https://github.com/PQClean/PQClean

Random bytes and Hybrid also have their own license files (MIT License).
