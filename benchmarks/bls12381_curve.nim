# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  # Internals
  ../blscurve/common,
  ../blscurve/milagro,
  ../blscurve/hash_to_curve,
  # Bench
  ./bench_templates,
  ./keygen

# ############################################################
#
#             Benchmark of BLS curve
#              (Barreto-Lynn-Scott)
#
# ############################################################

{.passC: "-DUSE_GLV_BLS12381".}
{.passC: "-DUSE_GS_G2_BLS12381".}

proc benchScalarMultG1*(iters: int) =
  var g1 = generator1()
  var x: ECP_BLS12381
  var scal: BIG_384
  random(scal)

  bench("Scalar multiplication G1 - constant-time fixed window method", iters):
    x = g1
    ECP_BLS12381_mul(addr x, scal)

proc benchScalarMultG2*(iters: int) =
  var g2 = generator2()
  var x: ECP2_BLS12381
  var scal: BIG_384
  random(scal)

  bench("Scalar multiplication G2 - constant-time fixed window method", iters):
    x = g2
    ECP2_BLS12381_mul(addr x, scal)

proc benchScalarMultG1Endo*(iters: int) =
  var g1 = generator1()
  var x: ECP_BLS12381
  var scal: BIG_384
  random(scal)

  bench("Scalar multiplication G1 - Endomorphism acceleration (GLV)", iters):
    x = g1
    PAIR_BLS12381_G1mul(addr x, scal)

proc benchScalarMultG2Endo*(iters: int) =
  var g2 = generator2()
  var x: ECP2_BLS12381
  var scal: BIG_384
  random(scal)

  bench("Scalar multiplication G2 - Endomorphism acceleration (GLS)", iters):
    x = g2
    PAIR_BLS12381_G2mul(addr x, scal)

proc benchECAddG1*(iters: int) =
  var x = generator1()
  var y = generator1()

  bench("EC add G1", iters):
    x.add(y)

proc benchECAddG2*(iters: int) =
  var x = generator2()
  var y = generator2()

  bench("EC add G2", iters):
    x.add(y)

proc benchPairingViaDoublePairing*(iters: int) =
  ## Builtin Milagro Double-Pairing implementation
  # Ideally we don't depend on the bls_signature_scheme but it's much simpler
  let (pubkey, seckey) = newKeyPair()
  let msg = "msg"
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

proc benchPairingViaMultiPairing*(iters: int) =
  ## MultiPairing implementation
  ## Using deferred Miller loop + Final Exponentiation
  # Ideally we don't depend on the bls_signature_scheme but it's much simpler
  let (pubkey, seckey) = newKeyPair()
  let msg = "msg"
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

when isMainModule:
  benchScalarMultG1(1000)
  benchScalarMultG1Endo(1000)
  benchScalarMultG2(1000)
  benchScalarMultG2Endo(1000)
  benchEcAddG1(1000)
  benchEcAddG2(1000)

  benchPairingViaDoublePairing(1000)
  benchPairingViaMultiPairing(1000)
