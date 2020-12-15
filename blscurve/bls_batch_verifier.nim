# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  ./bls_backend, ./bls_sig_min_pubkey,
  ./openmp

# BLS Batch Verifier
# ----------------------------------------------------------------------
# We use OpenMP here but might want to use a simple threadpool
# for portability as Mac compiler doesn't ship with OpenMP
# and while MSVC has OpenMP, it's unsure about Mingw
#
# Also as Nim supports for view types and openarray in object fields is experimental
# we collect/copy the inputs in the object for now by copy.
# instead of accumulating them in a pairing context.
# Note that a pairing context is 3+MB
# while we have
# - publickey = 48B
# - signature = 96B
# - message = 32B (assuming sha256 hashed)
# hence 176B only
#
# TODO: Once ContextMultiAggregateVerify is implemented
# for Milagro/Miracl, this wouldn't need to be in the BLST specific file

type
  SignatureSet = object
    ## A (Public Key, Message, Signature) triplet
    ## that will be batch verified.
    ## This should not hold GC-ed memory
    ## as this would complexify multithreading.
    ## Consequently this assumes that message
    ## is the output of a fixed size hash function.
    signature: Signature
    pubkey: PublicKey
    message: array[32, byte]

  BatchedBLSVerifierCache* = object
    ## A type to batch BLS multi signatures (aggregated or individual)
    ## verification using multiple cores if compiled with OpenMP
    sets: seq[SignatureSet]

    # Per-batch contexts for multithreaded batch verification
    batchContexts: seq[ContextMultiAggregateVerify[DST]]
    updateResults: seq[tuple[ok: bool, padCacheLine: array[64, byte]]]

func init*(T: type BatchedBLSVerifierCache): T {.inline.} =
  ## Initialize or reinitialize a batchedBLS Verifier
  discard # default initialization

func clear*(batcher: var BatchedBLSVerifierCache) {.inline.} =
  ## Initialize or reinitialize a batchedBLS Verifier
  batcher.sets.setLen(0)
  batcher.batchContexts.setLen(0)

func add*(
       batcher: var BatchedBLSVerifierCache,
       public_key: PublicKey,
       message: array[32, byte],
       signature: Signature
     ) {.inline.} =
  ## Include a (public key, message, signature) triplet
  ## to the batch for verification.
  ##
  ## Assumes subgroup checks
  ## and infinity checks were done prior.
  ## This is currently guaranteed
  ## on deserialization of public keys and signatures.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## For Eth2, the public key must correspond to a valid deposit.
  batcher.sets.add SignatureSet(
    signature: signature,
    pubkey: public_key,
    message: message
  )

func add*(
       batcher: var BatchedBLSVerifierCache,
       public_keys: openarray[PublicKey],
       message: array[32, byte],
       signature: Signature
     ): bool =
  ## Include a (array of public keys, message, signature) triplet
  ## to the batch for verification.
  ##
  ## All public keys sign the same message
  ## and signature is their aggregated signature
  ##
  ## Returns false if no public keys are passed
  ## Returns true otherwise
  ##
  ## Assumes subgroup checks
  ## and infinity checks were done prior.
  ## This is currently guaranteed
  ## on deserialization of public keys and signatures.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## For Eth2, the public key must correspond to a valid deposit.
  if publicKeys.len == 0:
    return false

  var aggAffine{.noInit.}: PublicKey
  if not aggAffine.aggregateAll(publicKeys):
    return false

  batcher.sets.add SignatureSet(
    signature: signature,
    pubkey: aggAffine,
    message: message
  )

  return true

# Serial Batch Verifier
# ----------------------------------------------------------------------

func batchVerifySerial*(
       batcher: BatchedBLSVerifierCache,
       secureRandomBytes: array[32, byte]
     ): bool =
  ## Single-threaded batch verification
  if batcher.sets.len == 0:
    # Spec precondition
    return false

  batcher.batchContexts.setLen(1)
  template ctx: untyped = batcher.batchContexts[0]
  ctx.init()

  # Accumulate line functions
  for i in 0 ..< batcher.sets.len:
    let ok = ctx.update(
      batcher.sets[i].pubkey,
      batcher.sets[i].message,
      batcher.sets[i].signature
    )
    if not ok:
      return false

  # Miller loop
  ctx.commit()

  # Final exponentiation
  return ctx.finalVerify()

# Parallelized Batch Verifier
# ----------------------------------------------------------------------
# Parallel pairing computation requires the following steps
#
# Assuming we have N (public key, message, signature) triplets to verify
# on P processor/threads.
# We want B batches with B = P
# Each processing W work items with W = N/B or N/B + 1
#
# Step 0: Initialize a context per parallel batch.
# Step 1: Compute partial pairings, W work items per thread.
# Step 2: Merge the B partial pairings
#
# For step 2 we have 2 strategies.
# Strategy A: a simple linear merge
# ```
# for i in 1 ..< N:
#   contexts[0].merge(contexts[i])
# ```
# which requires B operations.
# In that case we can get away with just a simple parallel for loop.
# and a serial linear merge for step 2
#
# Strategy B: A divide-and-conquer algorithm
# We binary split the merge until we hit the base case:
# ```
# contexts[i].merge(contexts[i+1])
# ```
#
# As pairing merge (Fp12 multiplication) is costly
# (~10000 CPU cycles on Skylake-X with ADCX/ADOX instructions)
# and for Ethereum we would at least have 6 sets:
# - block proposals signatures
# - randao reveal signatures
# - proposer slashings signatures
# - attester slashings signatures
# - attestations signatures
# - validator exits signatures
# not counting deposits signatures which may be invalid
# The merging would be 60k cycles if linear
# or 10k * log2(6) = 30k cycles if divide-and-conquer on 6+ cores
# Note that as the tree processing progresses, less threads are required
# for full parallelism so even with less than 6 cores, the speedup should be important.
# But on the other side, it's hard to utilize all cores of a high-core count machine.
#
# Note 1: a pairing is about 3400k cycles so the optimization is only noticeable
# when we do multi-block batches,
# for example batching 20 blocks would require 1200k cycles for a linear merge.
#
# Note 2: Skylake-X is a very recent family, with bigint instructions MULX/ADCX/ADOX,
# multiply everything by 2~3 on a Raspberry Pi
# and scale by core frequency.
#
# Note 3: 3M cycles is 1ms at 3GHz.

template checksAndStackTracesOff(body: untyped): untyped =
  ## No Nim checks in OpenMP multithreading land, failure allocates an exception.
  ## No stacktraces either.
  ## Also use uint instead of int to ensure no range checks.
  ##
  ## For debugging a parallel OpenMP region, put "attachGC"
  ## as the first statement after "omp_parallel"
  ## Then you can echo strings and reenable stacktraces
  {.push stacktrace:off, checks: off.}
  body
  {.pop.}

checksAndStackTracesOff:
  func toPtrUncheckedArray[T](s: seq[T]): ptr UncheckedArray[T] {.inline.} =
    {.pragma: restrict, codegenDecl: "$# __restrict $#".}
    let p{.restrict.} = cast[
      ptr UncheckedArray[T]](
        s[0].unsafeAddr()
    )
    return p

  func accumPairingLines(
        sigsets: ptr UncheckedArray[SignatureSet],
        contexts: ptr UncheckedArray[ContextMultiAggregateVerify[DST]],
        batchID: uint32,
        subsetStart: uint32,
        subsetStopEx: uint32): bool =
    ## Accumulate pairing lines
    ## subsetStopEx is iteration stopping index, non-inclusive
    ## Assumes that contexts[batchID] is valid.
    ## Assumes that sigsets[subsetStart..<subsetStopEx] is valid
    for i in subsetStart ..< subsetStopEx:
      let ok = contexts[batchID].update(
          sigsets[i].pubkey,
          sigsets[i].message,
          sigsets[i].signature
        )
      if not ok:
        return false

    contexts[batchID].commit()
    return true

  func reducePartialPairings(
        contexts: ptr UncheckedArray[ContextMultiAggregateVerify[DST]],
        start, stopEx: uint32): bool =
    ## Parallel logarithmic reduction of partial pairings
    ## start->stopEx describes an exclusive range
    ## of contexts to reduce.
    # Rationale for using a more complex parallel logarithmic reduction
    # rather than a serial for loop
    # is in comments at the start of the Parallelized Batch Verifier Section.
    let mid = (start + stopEx) shr 1
    if stopEx-start == 1:
      # Odd number of batches
      return true
    elif stopEx-start == 2:
      # Leaf node
      let ok = contexts[start].merge(contexts[stopEx-1])
      return ok

    var leftOk{.exportC.}, rightOk{.exportC.} = false
    omp_task"shared(leftOk)": # Subtree puts partial reduction in "first"
      leftOk = reducePartialPairings(contexts, start, mid)
    omp_task"shared(rightOk)": # Subtree puts partial reduction in "mid"
      rightOk = reducePartialPairings(contexts, mid, stopEx)

    # Wait for all subtrees
    omp_taskwait()
    if not leftOk or not rightOk:
      return false
    return contexts[start].merge(contexts[mid])

proc batchVerifyParallel*(
       batcher: var BatchedBLSVerifierCache,
       secureRandomBytes: array[32, byte]
     ): bool {.sideeffect.} =
  ## Multithreaded batch verification
  ## Requires OpenMP 3.0 (GCC 4.4, 2008)
  let numSets = batcher.sets.len.uint32
  if numSets == 0:
    # Spec precondition
    return false

  let numBatches = min(numSets, omp_get_max_threads().uint32)

  # Stage 0: Accumulators - setLen for noinit of seq
  batcher.batchContexts.setLen(numBatches.int)
  batcher.updateResults.setLen(numBatches.int)

  # No stacktrace, exception
  # or anything that require a GC in a parallel section
  # otherwise "attachGC()" is needed in the parallel prologue
  # Hence we use raw ptr UncheckedArray instead of seq
  let contextsPtr = batcher.batchContexts.toPtrUncheckedArray()
  let setsPtr = batcher.sets.toPtrUncheckedArray()
  let updateResultsPtr = batcher.updateResults.toPtrUncheckedArray()

  # Stage 1: Accumulate partial pairings
  checksAndStackTracesOff:
    omp_parallel: # Start the parallel region
      let threadID = omp_get_thread_num()
      omp_chunks(numSets, chunkStart, chunkLen):
        # Partition work into even chunks
        # Each thread receives a different start+len to process
        # chunkStart and chunkLen are set per-thread by the template
        contextsPtr[threadID].init(
          secureRandomBytes,
          threadSepTag = cast[array[sizeof(threadID), byte]](threadID)
        )

        updateResultsPtr[threadID].ok =
          accumPairingLines(
            setsPtr, contextsPtr,
            threadID.uint32,
            chunkStart.uint32, uint32(chunkStart+chunkLen)
          )

  for i in 0 ..< batcher.updateResults.len:
    if not updateResultsPtr[i].ok:
      return false

  # Stage 2: Reduce partial pairings
  if numBatches < 4: # linear merge
    for i in 1 ..< numBatches:
      let ok = contextsPtr[0].merge(contextsPtr[i])
      if not ok:
        return false

  else: # parallel logarithmic merge
    var ok = false
    checksAndStackTracesOff:
      omp_parallel: # Start the parallel region
        omp_single: # A single thread should create the master task
          ok = reducePartialPairings(contextsPtr, start = 0, stopEx = numBatches)

    if not ok:
      return false

  return batcher.batchContexts[0].finalVerify()

# Autoselect Batch Verifier
# ----------------------------------------------------------------------

proc batchVerify*(
       batcher: var BatchedBLSVerifierCache,
       secureRandomBytes: array[32, byte]
     ): bool =
  ## Verify all signatures in batch at once.
  ## Returns true if all signatures are correct
  ## Returns false if there is at least one incorrect signature
  ##
  ## This requires securely generated random bytes
  ## for scalar blinding
  ## to defend against forged signatures that would not
  ## verify individually but would verify while aggregated.
  ##
  ## The blinding scheme also assumes that the attacker cannot
  ## resubmit 2^64 times forged (publickey, message, signature) triplets
  ## against the same `secureRandomBytes`
  if batcher.sets.len >= 3:
    batcher.batchVerifyParallel(secureRandomBytes)
  else:
    batcher.batchVerifySerial(secureRandomBytes)
