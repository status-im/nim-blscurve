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

when BLS_BACKEND == Miracl:
  import
    # third-party
    nimcrypto/[hmac, sha2], stew/endians2,
    # internal
    ./hkdf, ./bls_spec_keygen_miracl

  func ikm_to_lamport_SK(
        ikm: openArray[byte],
        salt: array[4, byte],
        lamportSecretKey: var array[255, array[32, byte]]) =
    ## Generate a Lamport private key
    # TODO: consider using an HKDF iterator

    var ctx: HMAC[sha256]
    var prk: MDigest[sha256.bits]

    # 0. PRK = HKDF-Extract(salt, IKM)
    ctx.hkdfExtract(prk, salt, ikm, append = default(array[0, byte]))

    # 1. OKM = HKDF-Expand(PRK, "" , L)
    #    with L = K * 255 and K = 32 (sha256 output)
    const L = sizeof(lamportSecretKey)
    let okm = cast[ptr array[L, byte]](lamportSecretKey.addr)
    # TODO: this will likely be changed to match BLS-02 construction
    #       regarding salt and prk
    ctx.hkdfExpand(prk, "", append = default(array[0, byte]), okm[])

  func parent_SK_to_lamport_PK(
        parentSecretKey: SecretKey,
        index: uint32,
        lamportPublicKey: var array[32, byte]) =
    ## Derives the index'th child's lamport PublicKey
    ## from the parent SecretKey

    # 0. salt = I2OSP(index, 4)
    let salt = index.toBytesBE()
    static: doAssert sizeof(salt) == 4

    # 1. IKM = I2OSP(parent_SK, 32)
    var ikm {.noinit.}: array[32, byte]
    when BLS_BACKEND == Miracl:
      # While the BLS prime is 381-bit (48 bytes)
      # the curve order is 255-bit (32 bytes)
      # and a secret key would always fit in 32 bytes
      var tmp {.noinit.}: array[48, byte]
      doAssert tmp.serialize(parentSecretKey)
      ikm[0 .. 31] = tmp.toOpenArray(48-32, 48-1)
    else:
      doAssert ikm.serialize(parentSecretKey)

    # Reorganized the spec to save on stack allocations
    # and limit stackoverflow potential.
    # As an additional optimization we could do the HKDF-Expand
    # in a streaming fashion 32 byte-chunk per 32 byte-chunk
    # via an iterator

    # 5. lamport_PK = ""
    var ctx: sha256
    ctx.init()

    # 2. lamport_0 = IKM_to_lamport_SK(IKM, salt)
    # TODO: this uses 8KB and has a high stack-overflow potential
    var lamport {.noinit.}: array[255, array[32, byte]]
    ikm.ikm_to_lamport_SK(salt, lamport)

    # TODO: unclear inclusive/exclusive ranges in spec
    #       assuming exclusive:
    #       https://github.com/ethereum/EIPs/issues/2337#issuecomment-637521421
    # 6. for i = 0 to 255
    #        lamport_PK = lamport_PK | SHA256(lamport_0[i])
    for i in 0 ..< 255:
      ctx.update(sha256.digest(lamport[i]).data)

    # 3. not_IKM = flip_bits(parent_SK)
    # We can flip the bit of the IKM instead
    # as flipping bits of milagro representation (Montgomery)
    # doesn't make sense
    var not_ikm {.noinit.}: array[32, byte]
    for i in 0 ..< 32:
      not_ikm[i] = not ikm[i]

    # 4. lamport_1 = IKM_to_lamport_SK(not_IKM, salt)
    # We reuse the previous buffer to limit stack usage
    not_ikm.ikm_to_lamport_SK(salt, lamport)

    # TODO: inclusive/exclusive range?
    # 7. for i = 0 to 255
    #        lamport_PK = lamport_PK | SHA256(lamport_1[i])
    for i in 0 ..< 255:
      ctx.update(sha256.digest(lamport[i]).data)

    # 8. compressed_lamport_PK = SHA256(lamport_PK)
    # 9. return compressed_lamport_PK
    discard ctx.finish(lamportPublicKey)

  func derive_child_secretKey*(
          childSecretKey: var SecretKey,
          parentSecretKey: SecretKey,
          index: uint32
      ): bool =
    ## Child Key derivation function
    var compressed_lamport_PK: array[32, byte]
    # 0. compressed_lamport_PK = parent_SK_to_lamport_PK(parent_SK, index)
    parent_SK_to_lamport_PK(
      parentSecretKey,
      index,
      compressed_lamport_PK
    )
    childSecretKey.hkdf_mod_r(compressed_lamport_PK, key_info = "")

  func derive_master_secretKey*(
          masterSecretKey: var SecretKey,
          ikm: openArray[byte]
      ): bool =
    ## Master key derivation
    if ikm.len < 32:
      return false

    masterSecretKey.hkdf_mod_r(ikm, key_info = "")

else:
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