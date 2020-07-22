import
  ./bls12381_curve,
  ./hash_to_curve

benchScalarMultG1(1000)
benchScalarMultG1Endo(1000)
benchScalarMultG2(1000)
benchScalarMultG2Endo(1000)
benchEcAddG1(1000)
benchEcAddG2(1000)

benchPairingViaDoublePairing(1000)
benchPairingViaMultiPairing(1000)

benchHashToG2(1000)
