# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Implementation of Ethereum 2 Key derivation
# https://eips.ethereum.org/EIPS/eip-2333

{.push raises: [Defect].}

import ../bls_backend

when BLS_BACKEND == BLST:
  import ../blst/blst_lowlevel

  template asScalar(sk: SecretKey): blst_scalar =
    ## Access the secret key field without making it public
    cast[ptr blst_scalar](sk.unsafeAddr)[]

  func derive_child_secretKey*(
          childSecretKey: var SecretKey,
          parentSecretKey: SecretKey,
          index: uint32
      ): bool =
    ## Child Key derivation function
    childSecretKey.asScalar().blst_derive_child_eip2333(
      parentSecretKey.asScalar(),
      index
    )
    return true

  func derive_master_secretKey*(
          masterSecretKey: var SecretKey,
          ikm: openArray[byte]
      ): bool =
    ## Master key derivation
    if ikm.len < 32:
      return false

    masterSecretKey.asScalar().blst_derive_master_eip2333(
      ikm
    )
    return true
