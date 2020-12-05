import
  ../blscurve,
  ./bls12381_curve,
  ./hash_to_curve,
  ./bls_signature

# Curve operations
benchScalarMultG1(1000)
benchScalarMultG2(1000)
benchEcAddG1(1000)
benchEcAddG2(1000)

# Pairings
when BLS_BACKEND == BLST:
  benchBLSTPairing(1000)
else:
  benchMiraclPairingViaDoublePairing(1000)
  benchMiraclPairingViaMultiPairing(1000)

# Hash-to-curve implementation
benchHashToG2(1000)

# High-level BLS signature scheme
benchSign(1000)
benchVerify(1000)
benchFastAggregateVerify(numKeys = 128, iters = 10)
