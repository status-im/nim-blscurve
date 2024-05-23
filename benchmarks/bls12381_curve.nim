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
    x.blst_p1_from_affine(BLS12_381_G1) # init from generator

    var scal{.noinit.}: array[32, byte]
    for val in scal.mitems:
      val = byte benchRNG.rand(0xFF)

    var scalar{.noinit.}: blst_scalar
    scalar.blst_scalar_from_bendian(scal)

    bench("Scalar multiplication G1 (255-bit, constant-time)", iters):
      x.blst_p1_mult(x, cast[ptr byte](addr scalar), 255)

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
      x.blst_p2_mult(x, cast[ptr byte](addr scalar), 255)

proc benchECAddG1*(iters: int) =
  when BLS_BACKEND == BLST:
    var x{.noinit.}, y{.noinit.}: blst_p1
    x.blst_p1_from_affine(BLS12_381_G1) # init from generator
    y = x

    bench("EC add G1 (constant-time)", iters):
      x.blst_p1_add_or_double(x, y)

proc benchECAddG2*(iters: int) =
  when BLS_BACKEND == BLST:
    var x{.noinit.}, y{.noinit.}: blst_p2
    x.blst_p2_from_affine(BLS12_381_G2) # init from generator
    y = x

    bench("EC add G2 (constant-time)", iters):
      x.blst_p2_add_or_double(x, y)

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
    blst_pairing_init(
      cast[ptr blst_opaque](ctx),
      hash_or_encode = kHash,
      domainSepTag
    )
    doAssert BLST_SUCCESS == blst_pairing_aggregate_pk_in_g1(
      cast[ptr blst_opaque](ctx),
      PK = pubkey.unsafeAddr,
      signature = nil,
      msg,
      aug = ""
    )
    doAssert BLST_SUCCESS == blst_pairing_aggregate_pk_in_g1(
      cast[ptr blst_opaque](ctx),
      PK = nil,
      signature = sig.unsafeAddr,
      msg = "",
      aug = ""
    )

    # Cache the benchmarking context, there will be a ~8MB copy overhead (context size)
    let ctxSave = createU(blst_pairing)
    ctxSave[] = ctx[]

    blst_pairing_commit(cast[ptr blst_opaque](ctx))                     # Miller loop
    let valid = blst_pairing_finalverify(cast[ptr blst_opaque](ctx), nil) # Final Exponentiation
    doAssert bool valid

    # Pairing: e(Q, xP) == e(R, P)
    bench("Pairing (Miller loop + Final Exponentiation)", iters):
      ctx[] = ctxSave[]
      blst_pairing_commit(cast[ptr blst_opaque](ctx))                     # Miller loop
      let valid = blst_pairing_finalverify(cast[ptr blst_opaque](ctx), nil) # Final Exponentiation
      # doAssert bool valid

when isMainModule:
  benchScalarMultG1(1000)
  benchScalarMultG2(1000)
  benchEcAddG1(1000)
  benchEcAddG2(1000)

  when BLS_BACKEND == BLST:
    benchBLSTPairing(5000)
