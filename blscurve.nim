# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

const BLS_ETH2_SPEC* = "v1.0.0"
import
  blscurve/bls_public_exports,
  blscurve/keygen_eip2333

export bls_public_exports, keygen_eip2333
