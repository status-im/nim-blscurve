# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  # Status libraries
  nimcrypto/sysrand,
  # Internals
  ../blscurve/bls_signature_scheme,
  ../blscurve/milagro

proc newKeyPair*(): tuple[pubkey: ECP_BLS12381, seckey: BIG_384] {.noInit.}=
  ## Generates a new public-private keypair
  ## This requires entropy on the system
  # The input-keying-material requires 32 bytes at least for security
  # The generation is deterministic and the input-keying-material
  # must be protected against side-channel attacks

  var ikm: array[32, byte]
  let written = randomBytes(ikm)
  doAssert written >= 32, "Key generation failure"

  var pk: PublicKey
  var sk: SecretKey

  doAssert keyGen(ikm, pk, sk), "Key generation failure"

  # We cast because the fields are normally private to the signature module
  result.pubkey = cast[ECP_BLS12381](pk)
  result.seckey = cast[BIG_384](sk)
