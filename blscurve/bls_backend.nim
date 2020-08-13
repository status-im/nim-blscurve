# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

const BLS_FORCE_BACKEND*{.strdefine.} = "auto"

static: doAssert BLS_FORCE_BACKEND == "auto" or
                 BLS_FORCE_BACKEND == "miracl" or
                 BLS_FORCE_BACKEND == "blst",
                 """Only "auto", "blst" and "miracl" backends are valid."""

type BlsBackendKind* = enum
  BLST
  Miracl

when BLS_BACKEND == "blst" or (
      BLS_BACKEND == "auto" and
        sizeof(int) == 8 and
        (defined(arm64) or defined(amd64))
    ):
  const BLS_BACKEND* = BLST
else:
  const BLS_BACKEND* = Miracl

when BLS_BACKEND == BLST:
  import ./blst/bls_sig_min_pubkey_size_pop
  export bls_sig_min_pubkey_size_pop
else:
  import
    ./miracl/bls_signature_scheme
  export
    SecretKey, PublicKey, Signature, ProofOfPossession,
    AggregateSignature,
    `==`,
    init, aggregate, finish,
    sign, verify, aggregateVerify, fastAggregateVerify,
    privToPub,
    fromHex, fromBytes, toHex, serialize, exportRaw
