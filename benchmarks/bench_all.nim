import
  ./bls12381_curve,
  ./hash_to_curve

benchScalarMultG1(1000)
benchScalarMultG2(1000)
benchEcAddG1(1000)
benchEcAddG2(1000)

benchPairingViaDoublePairing(1000)
benchPairingViaMultiPairing(1000)

echo "\n⚠️ Warning: using draft v5 of IETF Hash-To-Curve (HKDF-based)."
echo "           This is an outdated draft.\n"
benchHashToG2(1000)
