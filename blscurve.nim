# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

const BLS_USE_IETF_API* {.booldefine.} = true

when BLS_USE_IETF_API:
  import ./blscurve/bls_signature_scheme
  export
    SecretKey, PublicKey, Signature, ProofOfPossession,
    aggregate,
    sign, verify, aggregateVerify, fastAggregateVerify,
    keyGen,
    fromHex, fromBytes, toHex
else:
  import ./blscurve/bls_old_spec
  export bls_old_spec
