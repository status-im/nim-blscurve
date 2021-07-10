import
  std/[os, strutils, cpuinfo],
  ../blscurve,
  ./bls12381_curve,
  ./hash_to_curve,
  ./bls_signature,
  ./bench_templates

# Curve operations
benchScalarMultG1(1000)
benchScalarMultG2(1000)
benchEcAddG1(1000)
benchEcAddG2(1000)
separator()

# Pairings
when BLS_BACKEND == BLST:
  benchBLSTPairing(1000)
else:
  benchMiraclPairingViaDoublePairing(1000)
  benchMiraclPairingViaMultiPairing(1000)
separator()

# Hash-to-curve implementation
benchHashToG2(1000)
separator()

# High-level BLS signature scheme
benchSign(1000)
benchVerify(1000)
benchFastAggregateVerify(numKeys = 128, iters = 10)
separator()

when BLS_BACKEND == BLST:
    var nthreads: int
    if existsEnv"TP_NUM_THREADS":
      nthreads = getEnv"TP_NUM_THREADS".parseInt()
    else:
      nthreads = countProcessors()

    # Simulate Block verification (at most 6 signatures per block)
    batchVerifyMulti(numSigs = 6, iters = 10)
    batchVerifyMultiBatchedSerial(numSigs = 6, iters = 10)
    batchVerifyMultiBatchedParallel(numSigs = 6, iters = 10, nthreads)
    separator()

    # Simulate 10 blocks verification
    batchVerifyMulti(numSigs = 60, iters = 10)
    batchVerifyMultiBatchedSerial(numSigs = 60, iters = 10)
    batchVerifyMultiBatchedParallel(numSigs = 60, iters = 10, nthreads)
    separator()

    # Simulate 30 blocks verification
    batchVerifyMulti(numSigs = 180, iters = 10)
    batchVerifyMultiBatchedSerial(numSigs = 180, iters = 10)
    batchVerifyMultiBatchedParallel(numSigs = 180, iters = 10, nthreads)
    separator()

    echo "\nUsing nthreads = ", nthreads, ". The number of threads can be changed with TP_NUM_THREADS environment variable."
