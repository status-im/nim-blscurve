# Nim BLS12-381 Curve implementation

[![Build Status](https://travis-ci.org/status-im/nim-blscurve.svg?branch=master)](https://travis-ci.org/status-im/nim-blscurve)
[![Build status](https://ci.appveyor.com/api/projects/status/6l1il60ljfbtxw3g/branch/master?svg=true)](https://ci.appveyor.com/project/nimbus/nim-blscurve/branch/master)
[![Build Status: Azure](https://img.shields.io/azure-devops/build/nimbus-dev/0c305144-232d-4f3e-ba77-93e4e81182da/4/master?label=Azure%20%28Linux%2032-bit%2F64-bit%2C%20Windows%2032-bit%2F64-bit%2C%20MacOS%2064-bit%29)](https://dev.azure.com/numforge/Weave/_build?definitionId=2&branchName=master)


This library uses sources from [AMCL](https://github.com/apache/incubator-milagro-crypto-c).

Current curve supported:

  - BLS12-381 (ZK-SNARKS)

For signature and verification purposes, raw messages are first hashed with SHA256 (SHA2)
following Ethereum requirements 2.0

## Installation

You can install the developement version of the library through nimble with the following command
```
nimble install https://github.com/status-im/nim-blscurve
```

## Keeping track of upstream

To keep track of upstream:

- Update the submodule.
- Execute `nim e milagro.nims amcl blscurve/csources`
- Test
- Commit

## Implementation stability

This repo follows Ethereum 2.0 requirements.

Besides the standardization work described below, no changes are planned upstream
for the foreseeable future.

Currently (Jun 2019) a cross-blockchain working group is working to standardize BLS signatures
for the following blockchains:
- Algorand
- Chia Network
- Dfinity
- Ethereum 2.0
- Filecoin
- Zcash Sapling

Standardization work is led by:
- Dan Boneh, Professor at Stanford University and co-author of BLS
- Sergey Gorbunov, Assistant Professor at the University of Waterloo and working at Algorand

IETF draft submission: https://tools.ietf.org/html/draft-boneh-bls-signature-00
Repo for collaboration on the draft: https://github.com/pairingwg/bls_standard

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT
* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
