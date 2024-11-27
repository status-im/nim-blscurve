# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  system/ansi_c,
  std/random,
  ../blscurve,
  ./bench_templates

when BLS_BACKEND == BLST:
  import
    ../blscurve/blst/blst_abi

var benchRNG = initRand(0xFACADE)

proc benchECmsmG1*(numPoints, iters: int) =
  var ps = newSeq[cblst_p1_affine](numPoints)
  var coefs = newSeq[cblst_scalar](numPoints)
  for i in 0 ..< ps.len:
    # Fill with generator, BLST handles doubling without branching
    var t: cblst_p1
    t.addr.blst_p1_from_affine(toCC(BLS12_381_G1, cblst_p1_affine))

    var scal{.noinit.}: array[32, byte]
    for val in scal.mitems:
      val = byte benchRNG.rand(0xFF)

    # 1. Randomize the input point to avoid triggering the "double" path
    var scalar{.noinit.}: cblst_scalar
    scalar.addr.blst_scalar_from_bendian(scal)
    t.addr.blst_p1_mult(t.addr, toCC(scalar, byte), 96) # go fast, 96 should be enough
    ps[i].addr.blst_p1_to_affine(t.addr)

    # 2. Randomize the coefficients
    for val in scal.mitems:
      val = byte benchRNG.rand(0xFF)

    coefs[i].addr.blst_scalar_from_bendian(scal)

  var r{.noinit.}: cblst_p1

  proc msm(r: var cblst_p1, coefs: seq[cblst_scalar], ps: seq[cblst_p1_affine]) =
    # Ensure no Nim GC interference by using c_malloc
    let scratch = cast[ptr limb_t](c_malloc(csize_t blst_p1s_mult_pippenger_scratch_sizeof(ps.len.uint)))

    let ps0 = ps[0].unsafeAddr
    let ps00 = [ps0, nil] # Weird API with double indirection
    let coefs0 = toCC(coefs[0], byte)
    let coefs00 = [coefs0, nil]

    blst_p1s_mult_pippenger(r.addr, ps00[0].unsafeAddr, ps.len.uint,
                                coefs00[0].unsafeAddr, 255,
                                scratch)


  bench("EC MSM G1 - " & $numPoints, iters):
    r.msm(coefs, ps)

when isMainModule:
  benchECmsmG1(8, 10)
  benchECmsmG1(16, 10)
  benchECmsmG1(32, 10)
  benchECmsmG1(64, 10)
  benchECmsmG1(128, 10)
  benchECmsmG1(256, 10)
  # benchECmsmG1(512, 10)
  # benchECmsmG1(1024, 10)
  # benchECmsmG1(2048, 1)
  # benchECmsmG1(4096, 1)
  # benchECmsmG1(8192, 1)
  # benchECmsmG1(16384, 1)
  # benchECmsmG1(32768, 1)
  benchECmsmG1(65536, 1)
  # benchECmsmG1(131071, 1)
  # benchECmsmG1(262144, 1)