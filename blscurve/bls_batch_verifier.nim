# Nim-BLSCurve
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import ./bls_backend, ./bls_sig_min_pubkey

when compileOption("threads"):
  import
    stew/ptrops,
    taskpools, ./parallel_chunks

{.push raises: [].}

# BLS Batch Verifier
# ----------------------------------------------------------------------
# Nim supports for view types and openArray in object fields is experimental
# we collect/copy the inputs in the object for now by copy.
# instead of accumulating them in a pairing context.
# Note that a pairing context is 3+MB
# while we have
# - publickey = 48B (or 96B uncompressed)
# - signature = 96B (or 192B uncompressed)
# - message = 32B (assuming sha256 hashed)
# hence 176B only
#
# TODO: This wouldn't need to be in the BLST specific file

type
  SignatureSet* = tuple[pubkey: PublicKey, message: array[32, byte], signature: Signature]
    ## A (Public Key, Message, Signature) triplet
    ## that will be batch verified.
    ##
    ## `pubkey` can be an aggregate publickey (via `aggregateAll`)
    ## if `signature` is the corresponding AggregateSignature
    ## on the same `message`
    ##
    ## This assumes that `message` is the output of a fixed size hash function.
    ##
    ## `pubkey` and `signature` are assumed to be grouped checked
    ## which is guaranteed at deserialization from bytes or hex

  MultiSignatureSet* = object
    ## A set of signatures that all pertain to the same `message`.
    ##
    ## `pubkeys` can contain aggregate publickeys (via `aggregateAll`)
    ## if `signatures` contains the corresponding AggregateSignature
    ## on the same `message`
    ##
    ## This assumes that `message` is the output of a fixed size hash function.
    ##
    ## `pubkeys` and `signatures` are assumed to be grouped checked
    ## which is guaranteed at deserialization from bytes or hex
    pubkeys: seq[PublicKey]
    message: array[32, byte]
    signatures: seq[Signature]

  BatchedBLSVerifierCache* {.requiresInit.} = object
    ## This types hold temporary contexts
    ## to batch BLS multi signatures (aggregated or individual)
    ## verification.
    ## As the contexts are heavy, they can be reused

    # Per-batch contexts for multithreaded batch verification
    batchContexts: seq[ContextMultiAggregateVerify[DST]]

# Serial Batch Verifier
# ----------------------------------------------------------------------

func init*(
       T: type MultiSignatureSet,
       pubkeys: seq[PublicKey],
       message: array[32, byte],
       signatures: seq[Signature]
     ): MultiSignatureSet =
  doAssert pubkeys.len == signatures.len
  doAssert pubkeys.len > 0
  MultiSignatureSet(
    pubkeys: pubkeys,
    message: message,
    signatures: signatures,
  )

func init*(T: type MultiSignatureSet, sigset: SignatureSet): MultiSignatureSet =
  MultiSignatureSet(
    pubkeys: @[sigset.pubkey],
    message: sigset.message,
    signatures: @[sigset.signature],
  )

func add*(multiSet: var MultiSignatureSet, sigset: SignatureSet) =
  doAssert multiSet.message == sigset.message
  multiSet.pubkeys.add sigset.pubkey
  multiSet.signatures.add sigset.signature

func combine*(
          multiSet: MultiSignatureSet,
          secureRandomBytes: array[32, byte]
        ): SignatureSet =
  let (pubkey, signature) = secureRandomBytes
    .combine(multiSet.pubkeys, multiSet.signatures)
  (pubkey, multiSet.message, signature)

func init*(T: type BatchedBLSVerifierCache): T =
  ## Initialise the cache for single-threaded usage
  BatchedBLSVerifierCache(
    batchContexts: newSeq[ContextMultiAggregateVerify[DST]](1),
  )

when compileOption("threads"):
  func init*(T: type BatchedBLSVerifierCache, tp: Taskpool): T =
    ## Initialise the cache for multi-threaded usage
    BatchedBLSVerifierCache(
      batchContexts: newSeq[ContextMultiAggregateVerify[DST]](tp.numThreads),
    )

func batchVerifySerial*(
       cache: var BatchedBLSVerifierCache,
       input: openArray[SignatureSet],
       secureRandomBytes: array[32, byte]
     ): bool =
  ## Single-threaded batch verification
  ## This will verify all the inputs (PublicKey, message, Signature) triplets
  ##  at once and return true if verification is successful.
  ## If unsuccessful:
  ## - The input was empty
  ## - One or more of the inputs was invalid on aggregation
  ## - One or more of the inputs had an invalid signature
  ## If knowing which input was problematic is required, they must be checked one by one.
  ##
  ## The `cache` argument is required to have been initialized via `init`.
  ## This function performs no memory allocations.
  if input.len == 0:
    # Spec precondition
    return false

  doAssert cache.batchContexts.len >= 1

  template ctx: untyped = cache.batchContexts[0]
  ctx.init(secureRandomBytes, "")

  # Accumulate line functions
  for i in 0 ..< input.len:
    let ok = ctx.update(
      input[i].pubkey,
      input[i].message,
      input[i].signature
    )
    if not ok:
      return false

  # Miller loop
  ctx.commit()

  # Final exponentiation
  ctx.finalVerify()

func batchVerifySerial*(
       input: openArray[SignatureSet],
       secureRandomBytes: array[32, byte]
     ): bool =
  ## Single-threaded batch verification
  ## This will verify all the inputs (PublicKey, message, Signature) triplets
  ##  at once and return true if verification is successful.
  ## If unsuccessful:
  ## - The input was empty
  ## - One or more of the inputs was invalid on aggregation
  ## - One or more of the inputs had an invalid signature
  ## If knowing which input was problematic is required, they must be checked one by one.

  # Don't {.noinit.} this or seq capacity will be != 0.
  var batcher = BatchedBLSVerifierCache.init()
  return batcher.batchVerifySerial(input, secureRandomBytes)

when compileOption("threads"):
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

  func toPtrUncheckedArray[T](s: openArray[T]): ptr UncheckedArray[T] {.inline.} =
    {.pragma: restrict, codegenDecl: "$# __restrict $#".}
    let p{.restrict.} = cast[
      ptr UncheckedArray[T]](
        s[0].unsafeAddr()
    )
    return p

  func accumPairingLines(
        sigsets: ptr UncheckedArray[SignatureSet],
        contexts: ptr UncheckedArray[ContextMultiAggregateVerify[DST]],
        batchID: int,
        subsetStart: int,
        subsetStopEx: int): bool =
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

  proc reducePartialPairings(
        tp: Taskpool,
        contexts: ptr UncheckedArray[ContextMultiAggregateVerify[DST]],
        start, stopEx: int): bool {.gcsafe.} =
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

    # Subtree puts partial reduction in "first"
    let leftOkFV = tp.spawn reducePartialPairings(tp, contexts, start, mid)
    # Subtree puts partial reduction in "mid"
    let rightOkFV = reducePartialPairings(tp, contexts, mid, stopEx)

    # Wait for all subtrees, important: don't shortcut booleans as future/flowvar memory is released on sync
    let leftOk = sync(leftOkFV)
    let rightOk = rightOkFV
    if not leftOk or not rightOk:
      return false
    return contexts[start].merge(contexts[mid])

  proc batchVerifyParallel*(
        tp: Taskpool,
        cache: ptr BatchedBLSVerifierCache,
        setsPtr: ptr UncheckedArray[SignatureSet],
        numSets: int,
        secureRandomBytes: ptr array[32, byte]
      ): bool {.sideEffect.} =
    ## Multithreaded batch verification
    ## If multithreaded with -d:openmp requires OpenMP 3.0 (GCC 4.4, 2008)
    ## This will verify all the inputs (PublicKey, message, Signature) triplets
    ##  at once and return true if verification is successful.
    ## If unsuccessful:
    ## - The input was empty
    ## - One or more of the inputs was invalid on aggregation
    ## - One or more of the inputs had an invalid signature
    ## If knowing which input was problematic is required, they must be checked one by one.
    if numSets == 0:
      # Spec precondition
      return false

    let numBatches = min(numSets, tp.numThreads)

    # Stage 0: Accumulators - setLen for noinit of seq
    doAssert cache[].batchContexts.len >= numBatches

    # No GC in a parallel section
    # Hence we use raw ptr UncheckedArray instead of seq
    let contextsPtr = cache[].batchContexts.toPtrUncheckedArray()

    # Stage 1: Accumulate partial pairings
    proc processSingleChunk(
          contextsPtr: ptr UncheckedArray[ContextMultiAggregateVerify[DST]],
          setsPtr: ptr UncheckedArray[SignatureSet],
          secureRandomBytes: ptr array[32, byte],
          chunkID: int,
          chunkStart, chunkLen: int): bool {.gcsafe, nimcall.} =

      contextsPtr[chunkID].init(
        secureRandomBytes[],
        threadSepTag = cast[array[sizeof(chunkID), byte]](chunkID)
      )

      accumPairingLines(
        setsPtr, contextsPtr, chunkID,
        chunkStart, (chunkStart+chunkLen)
      )
    var results: seq[Flowvar[bool]]
    for chunkID in 0 ..< numBatches:
      parallel_chunks(numBatches, numSets, chunkID, chunkStart, chunkLen):
        # Partition work into even chunks
        # Each thread receives a different start+len to process
        # chunkStart and chunkLen are set per-thread by the template

        results.add(tp.spawn processSingleChunk(
          contextsPtr, setsPtr,
          secureRandomBytes,
          chunkID, chunkStart, chunkLen
        ))

    for res in results.mitems:
      if not sync(res):
        return false

    # Stage 2: Reduce partial pairings
    if numBatches < 4: # linear merge
      for i in 1 ..< numBatches:
        let ok = contextsPtr[0].merge(contextsPtr[i])
        if not ok:
          return false
    else: # parallel logarithmic merge
      let ok = reducePartialPairings(tp, contextsPtr, start = 0, stopEx = numBatches)

      if not ok:
        return false

    return cache.batchContexts[0].finalVerify()

  proc batchVerifyParallel*(
        tp: Taskpool,
        cache: var BatchedBLSVerifierCache,
        input: openArray[SignatureSet],
        secureRandomBytes: array[32, byte]
      ): bool {.sideEffect.} =
    ## Multithreaded batch verification
    ## If multithreaded with -d:openmp requires OpenMP 3.0 (GCC 4.4, 2008)
    ## This will verify all the inputs (PublicKey, message, Signature) triplets
    ##  at once and return true if verification is successful.
    ## If unsuccessful:
    ## - The input was empty
    ## - One or more of the inputs was invalid on aggregation
    ## - One or more of the inputs had an invalid signature
    ## If knowing which input was problematic is required, they must be checked one by one.
    ##
    ## If called from multiple threads, each call must have its own
    ## `BatchedBLSVerifierCache` instance initialised with the
    ## threadpool-specific initializer.
    ##
    ## This function does not allocate garbage-collected memory.

    batchVerifyParallel(
      tp, addr cache, makeUncheckedArray(baseAddr input), input.len,
      unsafeAddr secureRandomBytes)

  proc batchVerifyParallel*(
        tp: Taskpool,
        input: openArray[SignatureSet],
        secureRandomBytes: array[32, byte]
      ): bool =
    ## Multithreaded batch verification
    ## If multithreaded (with -d:openmp) requires OpenMP 3.0 (GCC 4.4, 2008)
    ## This will verify all the inputs (PublicKey, message, Signature) triplets
    ##  at once and return true if verification is successful.
    ## If unsuccessful:
    ## - The input was empty
    ## - One or more of the inputs was invalid on aggregation
    ## - One or more of the inputs had an invalid signature
    ## If knowing which input was problematic is required, they must be checked one by one.

    # Don't {.noinit.} this or seq capacity will be != 0.
    var batcher = BatchedBLSVerifierCache.init(tp)
    return tp.batchVerifyParallel(batcher, input, secureRandomBytes)

  # Autoselect Batch Verifier
  # ----------------------------------------------------------------------
  proc batchVerify*(
        tp: Taskpool,
        cache: ptr BatchedBLSVerifierCache,
        setsPtr: ptr UncheckedArray[SignatureSet],
        numSets: int,
        secureRandomBytes: ptr array[32, byte]
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
    when compileOption("threads"):
      if tp.numThreads > 1 and numSets >= 3:
        return tp.batchVerifyParallel(cache, setsPtr, numSets, secureRandomBytes)
      else:
        return cache[].batchVerifySerial(
          setsPtr.toOpenArray(0, numSets - 1), secureRandomBytes[])
    else:
      return cache.batchVerifySerial(
        setsPtr.toOpenArray(0, numSets - 1), secureRandomBytes[])

  proc batchVerify*(
        tp: Taskpool,
        cache: var BatchedBLSVerifierCache,
        input: openArray[SignatureSet],
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
    when compileOption("threads"):
      if tp.numThreads > 1 and input.len >= 3:
        return tp.batchVerifyParallel(cache, input, secureRandomBytes)
      else:
        return cache.batchVerifySerial(input, secureRandomBytes)
    else:
      return cache.batchVerifySerial(input, secureRandomBytes)

  proc batchVerify*(
        tp: Taskpool,
        input: openArray[SignatureSet],
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

    # Don't {.noinit.} this or seq capacity will be != 0.
    var batcher = BatchedBLSVerifierCache.init(tp)
    return tp.batchVerify(batcher, input, secureRandomBytes)
