# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import ./blscurve/bls_signature_scheme
export
  SecretKey, PublicKey, Signature, ProofOfPossession,
  `==`,
  aggregate,
  sign, verify, aggregateVerify, fastAggregateVerify,
  keyGen, privToPub,
  fromHex, fromBytes, toHex, serialize, exportRaw

export BLS_ETH2_SPEC
static: doAssert: BLS_ETH2_SPEC=="v0.11.x" or BLS_ETH2_SPEC=="v0.12.x"
# Pass -d:BLS_ETH2_SPEC="v0.11.x"
# For testnets that use the old BLS draft (schlesi, witti)
