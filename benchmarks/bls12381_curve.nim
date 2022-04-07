# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  std/random,
  ../blscurve,
  ./bench_templates

when BLS_BACKEND == BLST:
  import
    ../blscurve/blst/blst_abi
else:
  import
    ../blscurve/miracl/[common, milagro],
    ../blscurve/miracl/hash_to_curve

# ############################################################
#
#             Benchmark of BLS curve
#              (Barreto-Lynn-Scott)
#
# ############################################################

var benchRNG = initRand(0xFACADE)

proc benchScalarMultG1*(iters: int) =
  when BLS_BACKEND == BLST:
    var x{.noinit.}: blst_p1
    x.blst_p1_from_affine(BLS12_381_G1) # init from generator

    var scal{.noinit.}: array[32, byte]
    for val in scal.mitems:
      val = byte benchRNG.rand(0xFF)

    var scalar{.noinit.}: blst_scalar
    scalar.blst_scalar_from_bendian(scal)

    bench("Scalar multiplication G1 (255-bit, constant-time)", iters):
      x.blst_p1_mult(x, scalar, 255)
  else:
    var x = generator1()
    var scal{.noinit.}: array[32, byte]
    for val in scal.mitems:
      val = byte benchRNG.rand(0xFF)

    var scalar{.noinit.}: BIG_384
    doAssert scalar.fromBytes(scal)
    scalar.BIG_384_mod(CURVE_Order)

    bench("Scalar multiplication G1 (255-bit, constant-time)", iters):
      x.mul(scalar)

proc benchScalarMultG2*(iters: int) =
  when BLS_BACKEND == BLST:
    var x{.noinit.}: blst_p2
    x.blst_p2_from_affine(BLS12_381_G2) # init from generator

    var scal{.noinit.}: array[32, byte]
    for val in scal.mitems:
      val = byte benchRNG.rand(0xFF)

    var scalar{.noinit.}: blst_scalar
    scalar.blst_scalar_from_bendian(scal)

    bench("Scalar multiplication G2 (255-bit, constant-time)", iters):
      x.blst_p2_mult(x, scalar, 255)
  else:
    var x = generator2()
    var scal{.noinit.}: array[32, byte]
    for val in scal.mitems:
      val = byte benchRNG.rand(0xFF)

    var scalar{.noinit.}: BIG_384
    doAssert scalar.fromBytes(scal)
    scalar.BIG_384_mod(CURVE_Order)

    bench("Scalar multiplication G2 (255-bit, constant-time)", iters):
      x.mul(scalar)

proc benchECAddG1*(iters: int) =
  when BLS_BACKEND == BLST:
    var x{.noinit.}, y{.noinit.}: blst_p1
    x.blst_p1_from_affine(BLS12_381_G1) # init from generator
    y = x

    bench("EC add G1 (constant-time)", iters):
      x.blst_p1_add_or_double(x, y)
  else:
    var x = generator1()
    var y = generator1()

    bench("EC add G1 (constant-time)", iters):
      x.add(y)

proc benchECAddG2*(iters: int) =
  when BLS_BACKEND == BLST:
    var x{.noinit.}, y{.noinit.}: blst_p2
    x.blst_p2_from_affine(BLS12_381_G2) # init from generator
    y = x

    bench("EC add G2 (constant-time)", iters):
      x.blst_p2_add_or_double(x, y)
  else:
    var x = generator2()
    var y = generator2()

    bench("EC add G2 (constant-time)", iters):
      x.add(y)

when BLS_BACKEND == BLST:

  proc benchBLSTPairing*(iters: int) =
    let (pubkey, seckey) = block:
      var pk: PublicKey
      var sk: SecretKey
      var ikm: array[32, byte]
      ikm[0] = 0x12
      discard ikm.keygen(pk, sk)
      (cast[blst_p1_affine](pk), cast[blst_scalar](sk))
    let msg = "Mr F was here"
    const domainSepTag = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

    # Signing
    var sig = block:
      var sig {.noinit.}: blst_p2_affine
      var s {.noinit.}: blst_p2
      s.blst_hash_to_g2(
        msg,
        domainSepTag,
        aug = ""
      )
      s.blst_sign_pk_in_g1(s, seckey)
      sig.blst_p2_to_affine(s)
      sig

    # Verification
    let ctx = createU(blst_pairing) # Heap to avoid stack smashing
    ctx[].blst_pairing_init(
      hash_or_encode = kHash,
      domainSepTag
    )
    doAssert BLST_SUCCESS == ctx[].blst_pairing_aggregate_pk_in_g1(
      PK = pubkey.unsafeAddr,
      signature = nil,
      msg,
      aug = ""
    )
    doAssert BLST_SUCCESS == ctx[].blst_pairing_aggregate_pk_in_g1(
      PK = nil,
      signature = sig.unsafeAddr,
      msg = "",
      aug = ""
    )

    # Cache the benchmarking context, there will be a ~8MB copy overhead (context size)
    let ctxSave = createU(blst_pairing)
    ctxSave[] = ctx[]

    ctx[].blst_pairing_commit()                     # Miller loop
    let valid = ctx[].blst_pairing_finalVerify(nil) # Final Exponentiation
    doAssert bool valid

    # Pairing: e(Q, xP) == e(R, P)
    bench("Pairing (Miller loop + Final Exponentiation)", iters):
      ctx[] = ctxSave[]
      ctx[].blst_pairing_commit()                     # Miller loop
      let valid = ctx[].blst_pairing_finalVerify(nil) # Final Exponentiation
      # doAssert bool valid

else:

  proc benchMiraclPairingViaDoublePairing*(iters: int) =
    ## Builtin Miracl Double-Pairing implementation
    # Ideally we don't depend on the bls_signature_scheme but it's much simpler
    let (pubkey, seckey) = block:
      var pk: PublicKey
      var sk: SecretKey
      var ikm: array[32, byte]
      ikm[0] = 0x12
      discard ikm.keygen(pk, sk)
      (cast[ECP_BLS12381](pk), cast[BIG_384](sk))
    let msg = "Mr F was here"
    const domainSepTag = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

    # Signing
    var sig = hashToG2(msg, domainSepTag)
    sig.mul(seckey)

    # Verification
    let generator = generator1()
    let Q = hashToG2(msg, domainSepTag)
    # Pairing: e(Q, xP) == e(R, P)
    bench("Pairing (Milagro builtin double pairing)", iters):
      let valid = doublePairing(
        Q, pubkey,
        sig, generator
      )
      # doAssert valid

  proc benchMiraclPairingViaMultiPairing*(iters: int) =
    ## MultiPairing implementation
    ## Using deferred Miller loop + Final Exponentiation
    # Ideally we don't depend on the bls_signature_scheme but it's much simpler
    let (pubkey, seckey) = block:
      var pk: PublicKey
      var sk: SecretKey
      var ikm: array[32, byte]
      ikm[0] = 0x12
      discard ikm.keygen(pk, sk)
      (cast[ECP_BLS12381](pk), cast[BIG_384](sk))
    let msg = "Mr F was here"
    const domainSepTag = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

    # Signing
    var sig = hashToG2(msg, domainSepTag)
    sig.mul(seckey)

    # Verification
    let generator = generator1()
    let Q = hashToG2(msg, domainSepTag)
    # Pairing: e(Q, xP) == e(R, P)
    bench("Pairing (Multi-Pairing with delayed Miller and Exp)", iters):
      let valid = multiPairing(
        Q, pubkey,
        sig, generator
      )
      # doAssert valid

when isMainModule:
  benchScalarMultG1(1000)
  benchScalarMultG2(1000)
  benchEcAddG1(1000)
  benchEcAddG2(1000)

  when BLS_BACKEND == BLST:
    benchBLSTPairing(5000)
  else:
    benchMiraclPairingViaDoublePairing(1000)
    benchMiraclPairingViaMultiPairing(1000)
