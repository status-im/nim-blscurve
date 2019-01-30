# Nim BLS12-381 Curve implementation

[![Build Status](https://travis-ci.org/status-im/nim-blscurve.svg?branch=master)](https://travis-ci.org/status-im/nim-blscurve)
[![Build status](https://ci.appveyor.com/api/projects/status/6l1il60ljfbtxw3g/branch/master?svg=true)](https://ci.appveyor.com/project/nimbus/nim-blscurve/branch/master)

This library uses sources from [AMCL](https://github.com/milagro-crypto/amcl) and [Milagro-Crypto-C](https://github.com/milagro-crypto/milagro-crypto-c).

Current curve supported:

  - BLS12-381 (ZK-SNARKS)

## Installation

You can install the developement version of the library through nimble with the following command
```
nimble install https://github.com/status-im/nim-blscurve
```

## Keeping track of upstream

To keep track of upstream:

- Update the submodule.
- Execute `nim e milagro.nims amcl/version3/c blscurve/csources`
- Test
- Commit

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT
* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
