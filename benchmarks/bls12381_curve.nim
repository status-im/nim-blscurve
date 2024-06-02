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
    blst_p1_from_affine(toCV(x, cblst_p1), toCC(BLS12_381_G1, cblst_p1_affine)) # init from generator

    var scal{.noinit.}: array[32, byte]
    for val in scal.mitems:
      val = byte benchRNG.rand(0xFF)

    var scalar{.noinit.}: blst_scalar
    blst_scalar_from_bendian(toCV(scalar, cblst_scalar), scal)

    bench("Scalar multiplication G1 (255-bit, constant-time)", iters):
      blst_p1_mult(toCV(x, cblst_p1), toCC(x, cblst_p1), addr scalar.b[0], 255)

proc benchScalarMultG2*(iters: int) =
  when BLS_BACKEND == BLST:
    var x{.noinit.}: blst_p2
    blst_p2_from_affine(toCV(x, cblst_p2), toCC(BLS12_381_G2, cblst_p2_affine)) # init from generator

    var scal{.noinit.}: array[32, byte]
    for val in scal.mitems:
      val = byte benchRNG.rand(0xFF)

    var scalar{.noinit.}: blst_scalar
    blst_scalar_from_bendian(toCV(scalar, cblst_scalar), scal)

    bench("Scalar multiplication G2 (255-bit, constant-time)", iters):
      blst_p2_mult(toCV(x, cblst_p2), toCC(x, cblst_p2), addr scalar.b[0], 255)

proc benchECAddG1*(iters: int) =
  when BLS_BACKEND == BLST:
    var x{.noinit.}, y{.noinit.}: blst_p1
    blst_p1_from_affine(toCV(x, cblst_p1), toCC(BLS12_381_G1, cblst_p1_affine)) # init from generator
    y = x

    bench("EC add G1 (constant-time)", iters):
      blst_p1_add_or_double(toCV(x, cblst_p1), toCC(x, cblst_p1), toCC(y, cblst_p1))

proc benchECAddG2*(iters: int) =
  when BLS_BACKEND == BLST:
    var x{.noinit.}, y{.noinit.}: blst_p2
    blst_p2_from_affine(toCV(x, cblst_p2), toCC(BLS12_381_G2, cblst_p2_affine)) # init from generator
    y = x

    bench("EC add G2 (constant-time)", iters):
      blst_p2_add_or_double(toCV(x, cblst_p2), toCC(x, cblst_p2), toCC(y, cblst_p2))

when BLS_BACKEND == BLST:

  proc benchBLSTPairing*(iters: int) =
    let (pubkey, seckey) = block:
      var pk: PublicKey
      var sk: SecretKey
      var ikm: array[32, byte]
      ikm[0] = 0x12
      discard ikm.keyGen(pk, sk)
      (cast[blst_p1_affine](pk), cast[blst_scalar](sk))
    let msg = "Mr F was here"
    const domainSepTag = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

    # Signing
    var sig = block:
      var sig {.noinit.}: blst_p2_affine
      var s {.noinit.}: blst_p2
      blst_hash_to_g2(
        toCV(s, cblst_p2),
        msg,
        domainSepTag,
        aug = ""
      )
      blst_sign_pk_in_g1(toCV(s, cblst_p2), toCC(s, cblst_p2), toCC(seckey, cblst_scalar))
      blst_p2_to_affine(toCV(sig, cblst_p2_affine), toCC(s, cblst_p2))
      sig

    # Verification
    let ctx = createU(blst_pairing) # Heap to avoid stack smashing
    blst_pairing_init(
      cast[ptr cblst_pairing](ctx),
      hash_or_encode = kHash,
      domainSepTag
    )
    doAssert BLST_SUCCESS == blst_pairing_aggregate_pk_in_g1(
      cast[ptr cblst_pairing](ctx),
      PK = toCC(pubkey, cblst_p1_affine),
      signature = nil,
      msg,
      aug = ""
    )
    doAssert BLST_SUCCESS == blst_pairing_aggregate_pk_in_g1(
      cast[ptr cblst_pairing](ctx),
      PK = nil,
      signature = toCC(sig, cblst_p2_affine),
      msg = "",
      aug = ""
    )

    # Cache the benchmarking context, there will be a ~8MB copy overhead (context size)
    let ctxSave = createU(blst_pairing)
    ctxSave[] = ctx[]

    blst_pairing_commit(cast[ptr cblst_pairing](ctx))                     # Miller loop
    let valid = blst_pairing_finalverify(cast[ptr cblst_pairing](ctx), nil) # Final Exponentiation
    doAssert bool valid

    # Pairing: e(Q, xP) == e(R, P)
    bench("Pairing (Miller loop + Final Exponentiation)", iters):
      ctx[] = ctxSave[]
      blst_pairing_commit(cast[ptr cblst_pairing](ctx))                     # Miller loop
      let valid = blst_pairing_finalverify(cast[ptr cblst_pairing](ctx), nil) # Final Exponentiation
      # doAssert bool valid

when isMainModule:
  benchScalarMultG1(1000)
  benchScalarMultG2(1000)
  benchEcAddG1(1000)
  benchEcAddG2(1000)

  when BLS_BACKEND == BLST:
    benchBLSTPairing(5000)
