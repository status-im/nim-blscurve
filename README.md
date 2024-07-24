# BLS Signature Scheme over BLS12-381 pairing-friendly curve

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Github action](https://github.com/status-im/nim-blscurve/workflows/CI/badge.svg)

This library implements:
- The BLS signature scheme (Boneh-Lynn-Shacham)
- over the BLS12-381 (Barreto-Lynn-Scott) pairing-friendly curve

Cipher suite ID: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`

## Installation

You can install the developement version of the library through nimble with the following command
```
nimble install https://github.com/status-im/nim-blscurve
```

## Implementation stability

This repo follows Ethereum 2.0 requirements.

Besides the standardization work described below, no changes are planned upstream
for the foreseeable future.

### Standardization

Currently (Jun 2019) a cross-blockchain working group is working to standardize BLS signatures
for the following blockchains:
- Algorand
- Chia Network
- Dfinity
- Ethereum 2.0
- Filecoin
- Zcash Sapling

#### Signature scheme

- IETF draft submission v2: https://tools.ietf.org/html/draft-boneh-bls-signature-02
- Repo for collaboration on the draft: https://github.com/cfrg/draft-irtf-cfrg-bls-signature

#### Hashing to curve

- https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09
- https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve

Note: the implementation was done following Hash-to-curve v7
v9 and v7 are protocol compatible but have cosmetic changes (naming variables, precomputing constants, ...)

#### Curve implementation

- https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-00

## Backend

This library uses:
- [SupraNational BLST](https://github.com/supranational/blst) on all platforms.

BLST uses SSSE3 by default, if supported on the host. To disable that, when building
binaries destined for older CPUs, pass `-d:BLSTuseSSSE3=0` to the Nim compiler.

### Executing the test suite

We recommend working within the nimbus build environment described here:
https://github.com/status-im/nimbus-eth2

To execute the test suite, just navigate to the root of this repo and execute:

```
nimble test
```

> Please note that within the nimbus build environment, the repository will
  be located in `nimbus-eth2/vendor/nim-blscurve`.

### Executing the fuzzing tests

Before you start, please make sure that the regular test suite executes
successfully (see the instructions above). To start a particular fuzzing
test, navigate to the root of this repo and execute:

```
nim tests/fuzzing/run_fuzzing_test.nims <test-name>
```

You can specify the fuzzing engine being used by passing an additional
`--fuzzer` parameter. The currently supported engines are `libFuzzer`
(used by default) and `afl`.

All fuzzing tests are located in `tests/fuzzing` and use the following
naming convention:

```
fuzz_<test-name>.nim
```

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT
* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. These files may not be copied, modified, or distributed except according to those terms.

### Dependencies

- SupraNational BLST is distributed under the Apache License, Version 2.0
