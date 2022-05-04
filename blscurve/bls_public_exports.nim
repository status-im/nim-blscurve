# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  bls_backend

export
  BLS_BACKEND, BlsBackendKind,
  SecretKey, PublicKey, Signature, ProofOfPossession,
  AggregateSignature, AggregatePublicKey,
  `==`,
  init, aggregate, finish, aggregateAll,
  publicFromSecret,
  fromHex, fromBytes, fromBytesKnownOnCurve,
  toHex, serialize, exportRaw

# TODO - MIRACL implementation
when BLS_BACKEND == BLST:
  export
    exportUncompressed,
    ID, recover, genSecretShare, fromUint32, add

import bls_sig_min_pubkey

export
  sign,
  verify,
  aggregateVerify,
  fastAggregateVerify

when BLS_BACKEND == BLST:
  import ./blst/blst_recovery
  export blst_recovery

  import ./blst/sha256_abi
  export sha256_abi

  import ./bls_batch_verifier
  export bls_batch_verifier
