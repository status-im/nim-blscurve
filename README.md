# Nim Milagro Crypto Library

❗❗❗ - Status unmaintained

As only the BLS12-381 curve is needed for Eth2.0, development has been moved to [Nim BLS Curve](https://github.com/status-im/nim-blscurve)

[![Build Status (Travis)](https://img.shields.io/travis/status-im/nim-milagro-crypto/master.svg?label=Linux%20/%20macOS "Linux/macOS build status (Travis)")](https://travis-ci.org/status-im/nim-milagro-crypto)
[![Windows build status (Appveyor)](https://img.shields.io/appveyor/ci/nimbus/nim-milagro-crypto/master.svg?label=Windows "Windows build status (Appveyor)")](https://ci.appveyor.com/project/nimbus/nim-milagro-crypto)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Status: unmaintained](https://img.shields.io/badge/status-unmaintained-red.svg)

Wrapper for specific curve from [AMCL](https://github.com/milagro-crypto/amcl) and [Milagro-Crypto-C](https://github.com/milagro-crypto/milagro-crypto-c).

Current curve supported:

  - BLS12-381 (ZK-SNARKS)

## Installation

You can install the developement version of the library through nimble with the following command
```
nimble install https://github.com/status-im/nim-milagro-crypto@#master
```

## Keeping track of upstream

To keep track of upstream:

- Update the submodule.
- Execute `nim e milagro.nims amcl/version3/c milagro_crypto/csources`
- Test
- Commit

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
