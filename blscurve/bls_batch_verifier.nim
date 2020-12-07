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
  SignatureSet[HashLen: static int] = object
    ## A (Public Key, Message, Signature) triplet
    ## that will be batch verified.
    ## This should not hold GC-ed memory
    ## as this would complexify multithreading.
    ## Consequently this assumes that message
    ## is the output of a fixed size hash function.
    signature: Signature
    pubkey: PublicKey
    message: array[HashLen, byte]

  BatchedBLSVerifier*[HashLen: static int] = object
    ## A type to batch BLS multi signatures (aggregated or individual)
    ## verification using multiple cores if compiled with OpenMP
    sets: seq[SignatureSet[HashLen]]

    # Per-batch contexts for multithreaded batch verification
    batchContexts: seq[ContextMultiAggregateVerify[DST]]

func init*(T: type BatchedBLSVerifier): T {.inline.} =
  ## Initialize or reinitialize a batchedBLS Verifier
  # Impl: A BatchedBLSVerifier still MUST be zero-init
  # otherwise the sequences fields
  # like capacity and reserve memory will be wrong.
  result.sets.setLen(0)
  result.batchContexts.setLen(0)

func clear*(batcher: var BatchedBLSVerifier) {.inline.} =
  ## Initialize or reinitialize a batchedBLS Verifier
  batcher.sets.setLen(0)
  batcher.batchContexts.setLen(0)

func incl*[HashLen: static int](
       batcher: var BatchedBLSVerifier[HashLen],
       public_key: PublicKey,
       message: array[HashLen, byte],
       signature: Signature
     ): bool {.inline.} =
  ## Include a (public key, message, signature) triplet
  ## to the batch for verification.
  ##
  ## Always return true
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  batcher.sets.add SignatureSet[HashLen](
    signature: signature,
    pubkey: public_key,
    message: message
  )
  return true

func incl*[HashLen: static int](
       batcher: var BatchedBLSVerifier[HashLen],
       public_keys: openarray[PublicKey],
       message: array[HashLen, byte],
       signature: Signature
     ): bool {.inline.} =
  ## Include a (array of public keys, message, signature) triplet
  ## to the batch for verification.
  ##
  ## All public keys sign the same message
  ## and signature is their aggregated signature
  ##
  ## Returns false if no public keys are passed
  ## Returns true otherwise
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
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
       batcher: BatchedBLSVerifier,
       secureRandomBytes: array[32, byte]
     ): bool =
  ## Single-threaded batch verification
  if batcher.sets.len == 0:
    return false

  var ctx {.noInit.}: ContextMultiAggregateVerify[DST]
  ctx.init(
    secureRandomBytes,
    threadSepTag = ""
  )

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

# No Nim checks in OpenMP multithreading land, failure allocates an exception.
# No stacktraces either.
# Also use uint instead of int to ensure no range checks.
{.push stacktrace:off, checks: off.}

func toPtrUncheckedArray[T](s: seq[T]): ptr UncheckedArray[T] {.inline.} =
  {.pragma: restrict, codegenDecl: "$# __restrict $#".}
  let p{.restrict.} = cast[
    ptr UncheckedArray[T]](
      s[0].unsafeAddr()
  )
  return p

func accumPairingLines[HashLen](
       sigsets: ptr UncheckedArray[SignatureSet[HashLen]],
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

func dacPairing[HashLen](
       sigsets: ptr UncheckedArray[SignatureSet[HashLen]],
       contexts: ptr UncheckedArray[ContextMultiAggregateVerify[DST]],
       numBatches: uint32,
       batchID: uint32,
       subsetStart: uint32,
       subsetStopEx: uint32
     ): bool =
  ## Distribute pairing computation using a recursive divide-and-conquer (DAC) algorithm
  ##
  ## Returns false if at least one partial pairing `update` failed.
  ## ⚠️ : We use 0-based indexing for the tree splitting
  ##                  root at 0    root at 1
  ## Left child        ix*2 + 1     ix*2
  ## Right child       ix*2 + 2     ix*2 + 1
  ## Parent            (ix-1)/2     ix/2
  #
  # Rationale for divide and conquer.
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
  #
  # Hence we prefer strategy B. It would also be easier to port to a simple threadpool
  # which doesn't support parallel for loop but do support plain task spawning.
  #
  # That said a pairing is about 3400k cycles so the optimization is only noticeable
  # when we do multi-block batches,
  # for example batching 20 blocks would require 1200k cycles for a linear merge.
  #
  # Since we use divide-and-conquer for step 2, we might as well use it for step 1 as well
  # which would also allow us to remove synchronization barriers between step 1 and 2.
  # - 1 for the master thread to check ctx.update(...) results and early return
  # - 1 to ensure that the contextPtr array is fully updated before starting merge
  #
  # Note: Skylake-X is a very recent family, with bigint instructions MULX/ADCX/ADOX,
  # multiply everything by 2~3 on a Raspberry Pi
  # and scale by core frequency.
  # 3000 cycles is 1ms at 3GHz.

  # Overflow check: numBatches and so batchID*2+2 are capped by number of threads
  template left(batchID: uint32): uint32 = 2*batchID+1
  template right(batchID: uint32): uint32 = 2*batchID+2

  let mid = (subsetStopEx+subsetStart) shr 1

  if subsetStopEx-subsetStart <= 1 or batchID.left >= numBatches:
    # Can't split or no need to split anymore
    # as there is more work than hardware threads/batches
    # and it's better to accumulate as much as possible in partial pairings
    # as merge cost is non-trivial (10k to 20k cycles).
    # So we want 1 merge per thread and no more.
    let ok = accumPairingLines(sigsets, contexts,
                               batchID, subsetStart, subsetStopEx)
    if not ok:
      return false
    return true
  elif batchID.right >= numBatches:
    # No need to split, there is no right subtree
    # We directly accumulate in the current batch context
    let ok = accumPairingLines(sigsets, contexts,
                               batchID, subsetStart, mid)
    if not ok:
      return false
    return true
  else:
    # Split in half, distribute the right and work on the left
    var leftOk, rightOk = true
    omp_task"":
      rightOk = dacPairing(sigsets, contexts, numBatches,
                           batchID.right(), mid, subsetStopEx)
    leftOk = dacPairing(sigsets, contexts, numBatches,
                        batchID.left(), subsetStart, mid)

    # Wait for all subtrees
    omp_taskwait()
    if not leftOk or not rightOk:
      return false
    # Merge left and right
    let mergeOk = contexts[batchID.left()].merge(contexts[batchID.right()])
    if not mergeOk:
      return false
    # Update our own pairing context - 3+MB copy
    contexts[batchID] = contexts[batchID.left()]
    return true

{.pop.}

proc batchVerifyParallel*(
       batcher: var BatchedBLSVerifier,
       secureRandomBytes: array[32, byte]
     ): bool {.sideeffect.} =
  ## Multithreaded batch verification
  ## Requires OpenMP 3.0 (GCC 4.4, 2008)
  let numSets = batcher.sets.len.uint32
  if numSets == 0:
    return false

  let numBatches = min(numSets, omp_get_max_threads().uint32)

  # Stage 0: Accumulators - setLen for noinit of seq
  batcher.batchContexts.setLen(numBatches.int)

  # No stacktrace, exception
  # or anything that require a GC in a parallel section
  # otherwise "attachGC()" is needed in the parallel prologue
  # Hence we use raw ptr UncheckedArray instead of seq
  let contextsPtr = batcher.batchContexts.toPtrUncheckedArray()
  let setsPtr = batcher.sets.toPtrUncheckedArray()

  var ok: bool
  {.push stacktrace:off, checks:off.}
  omp_parallel:
    let threadID = omp_get_thread_num()

    if threadID.uint32 < numBatches:
      contextsPtr[threadID].init(
        secureRandomBytes,
        threadSepTag = cast[array[sizeof(cint), byte]](threadID)
      )

    omp_single:
      ok = dacPairing(setsPtr, contextsPtr, numBatches,
                      batchID = 0, subsetStart = 0, subsetStopEx = numSets)
  {.pop.}

  if not ok:
    return false

  return batcher.batchContexts[0].finalVerify()

# Autoselect Batch Verifier
# ----------------------------------------------------------------------

proc batchVerify*(
       batcher: var BatchedBLSVerifier,
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
  if min(batcher.sets.len.uint32, omp_get_num_threads().uint32) >= 2:
    batcher.batchVerifyParallel(secureRandomBytes)
  else:
    batcher.batchVerifySerial(secureRandomBytes)
