# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import ../blst/blst_lowlevel, ../bls_backend

func keyGen*(ikm: openArray[byte], publicKey: var PublicKey, secretKey: var SecretKey): bool =
  ## Generate a (public key, secret key) pair
  ## from the input keying material `ikm`
  ##
  ## For security, `ikm` MUST be infeasible to guess, for example,
  ## generated from a trusted source of randomness.
  ##
  ## `ikm` MUST be at least 32 bytes long but may be longer
  ##
  ## Key generation is deterministic
  ##
  ## Either the keypair (publickey, secretkey) can be stored or
  ## the `ikm` can be stored and keys can be regenerated on demand.
  ##
  ## Inputs:
  ##   - IKM: a secret array or sequence of bytes
  ##
  ## Outputs:
  ##   - publicKey
  ##   - secretKey
  ##
  ## Returns `true` if generation successful
  ## Returns `false` if generation failed
  ## Generation fails if `ikm` length is less than 32 bytes
  ##
  ## `IKM` and  `secretkey` must be protected against side-channel attacks
  ## including timing attaks, memory dumps, attaching processes, ...
  ## and securely erased from memory.
  ##
  ## At the moment, the nim-blscurve library does not guarantee such protections

  #  (PK, SK) = KeyGen(IKM)
  #
  #  Inputs:
  #  - IKM, a secret octet string. See requirements above.
  #
  #  Outputs:
  #  - PK, a public key encoded as an octet string.
  #  - SK, the corresponding secret key, an integer 0 <= SK < r.
  #
  #  Definitions:
  #  - HKDF-Extract is as defined in RFC5869, instantiated with hash H.
  #  - HKDF-Expand is as defined in RFC5869, instantiated with hash H.
  #  - L is the integer given by ceil((1.5 * ceil(log2(r))) / 8).
  #  - "BLS-SIG-KEYGEN-SALT-" is an ASCII string comprising 20 octets.
  #  - "" is the empty string.
  #
  #  Procedure:
  #  1. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM)
  #  2. OKM = HKDF-Expand(PRK, "", L)
  #  3. x = OS2IP(OKM) mod r
  #  4. xP = x * P
  #  5. SK = x
  #  6. PK = point_to_pubkey(xP)
  #  7. return (PK, SK)

  if ikm.len < 32:
    return false

  # The cast is a workaround for private field access
  cast[ptr blst_scalar](secretKey.addr)[].blst_keygen(ikm, info = "")
  publicKey.publicFromSecret(secretKey)